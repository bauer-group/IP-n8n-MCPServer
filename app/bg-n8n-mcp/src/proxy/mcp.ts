/**
 * The MCP reverse proxy.
 *
 * `/i/<host>/mcp` → n8n-mcp's `/mcp`, with the caller's OAuth token replaced by
 * the upstream shared secret and the caller's own n8n credentials injected as
 * tenant headers.
 *
 * Five things this has to get right:
 *
 *  1. **Never forward the client's token.** The MCP spec forbids token
 *     passthrough outright — it is the confused-deputy vulnerability the spec
 *     names by name. The inbound bearer is resolved to a grant here and
 *     discarded; what goes upstream is `AUTH_TOKEN`, which n8n-mcp shares with
 *     this gateway and nobody else.
 *
 *  2. **Audience binding.** A token issued for tenant A must not work on
 *     tenant B's path. Without this check the per-tenant paths are decoration:
 *     anyone with any valid token could address any allowlisted instance.
 *
 *  3. **Strip inbound tenant headers.** A client that sends its own
 *     `x-n8n-url` must not be able to redirect the upstream call. Traefik
 *     strips them too (see the compose files) — this is the hop that must not
 *     rely on that.
 *
 *  4. **Per-grant `x-instance-id`.** n8n-mcp's default
 *     `MULTI_TENANT_SESSION_STRATEGY=instance` evicts every existing session
 *     sharing an instance id whenever one initialises. Sending the n8n
 *     hostname there would mean any user connecting kicks every other user of
 *     that instance off. A per-grant id gives each user their own session and
 *     makes the eviction do the useful thing instead: cleaning up that user's
 *     own stale session on reconnect.
 *
 *  5. **Stream, do not buffer.** MCP responses can be SSE that stay open for
 *     the length of a tool call, with keep-alive comments every 15s. Anything
 *     that accumulates the body turns a live stream into a timeout.
 */

import { isIP } from 'node:net';
import type { Context } from 'hono';
import type { Config } from '../config.js';
import { hashKey, unseal } from '../lib/crypto.js';
import { clientIp } from '../lib/request.js';
import { log, short } from '../logger.js';
import { checkTenant, resolveTenant } from '../n8n/tenant.js';
import { bearerChallenge, resourceFor, resourceMetadataUrlFor, SCOPE } from '../oauth/metadata.js';
import type { Store } from '../store/index.js';

/**
 * Headers that must never be copied from the inbound request.
 *
 * Two groups: RFC 7230 hop-by-hop headers, which describe *this* connection and
 * are meaningless on the next one, and the tenant headers, which are ours to
 * set and a client's to be denied.
 *
 * Everything not listed is forwarded verbatim — including headers MCP added
 * after this was written (`Mcp-Method`, `Mcp-Name`, `Mcp-Param-*`). A denylist
 * is the right shape here: an allowlist would silently drop the next protocol
 * revision's routing headers, and the spec tells intermediaries to forward
 * headers they do not recognise.
 */
const DROPPED_REQUEST_HEADERS = new Set([
  // hop-by-hop
  'connection',
  'keep-alive',
  'proxy-authenticate',
  'proxy-authorization',
  'te',
  'trailer',
  'transfer-encoding',
  'upgrade',
  // set by us / recomputed by fetch
  'authorization',
  'host',
  'content-length',
  // tenant context — only this gateway may set these
  'x-n8n-url',
  'x-n8n-key',
  'x-instance-id',
  'x-session-id',
]);

/**
 * Response headers we do not pass back.
 *
 * `content-length` and `content-encoding` describe the upstream body as it was
 * framed on that connection; re-emitting them alongside a re-framed streaming
 * body is how an SSE response ends up truncated or, over HTTP/2, rejected as a
 * protocol error.
 */
const DROPPED_RESPONSE_HEADERS = new Set([
  'content-length',
  'content-encoding',
  'transfer-encoding',
  'connection',
  'keep-alive',
]);

export interface ProxyDeps {
  readonly config: Config;
  readonly store: Store;
}

/**
 * Stable, non-secret per-grant identifier for upstream session scoping.
 *
 * Derived from the grant id rather than being the grant id: that value is a
 * bearer-equivalent secret, and it would otherwise end up embedded in
 * n8n-mcp's session ids and log lines.
 */
function instanceIdFor(store: Store, grantId: string): string {
  return hashKey(store.keyring, `instance:${grantId}`).slice(0, 32);
}

/**
 * Is this something a downstream proxy will accept as an address?
 *
 * `clientIp` returns the sentinel `'unknown'` when it cannot determine one, and
 * that sentinel must never reach the wire.
 */
function isUsableAddress(value: string): boolean {
  if (!value || value === 'unknown') return false;
  // Strip an IPv6 zone/brackets before asking; `isIP` rejects both.
  const bare = value.replace(/^\[|\]$/g, '').split('%')[0] ?? '';
  return isIP(bare) !== 0;
}

/**
 * Copy the inbound headers, minus the ones we drop, and add ours.
 *
 * The order matters: our headers are set *after* the copy loop, so a client
 * that managed to slip one past the denylist would still be overwritten here.
 */
function buildUpstreamHeaders(input: {
  readonly inbound: Headers;
  readonly upstreamToken: string;
  readonly tenantOrigin: string;
  readonly apiKey: string;
  readonly instanceId: string;
  readonly clientAddress: string;
}): Headers {
  const headers = new Headers();
  for (const [name, value] of input.inbound) {
    if (!DROPPED_REQUEST_HEADERS.has(name.toLowerCase())) headers.set(name, value);
  }

  headers.set('authorization', `Bearer ${input.upstreamToken}`);
  headers.set('x-n8n-url', input.tenantOrigin);
  headers.set('x-n8n-key', input.apiKey);
  headers.set('x-instance-id', input.instanceId);

  // Forward the real client IP so n8n-mcp's own limiter (which counts failed
  // requests per IP) sees individual users rather than one very busy gateway.
  // Requires TRUST_PROXY=1 on the upstream container.
  //
  // Omitted entirely when we do not have an address. Sending the placeholder
  // is worse than sending nothing: with TRUST_PROXY set, express-rate-limit
  // parses the value and throws `ERR_ERL_INVALID_IP_ADDRESS` on a
  // non-address, which took down MCP sessions in an end-to-end run. Absent
  // means "use the socket"; "unknown" means "here is an address" and lies.
  if (isUsableAddress(input.clientAddress)) {
    headers.set('x-forwarded-for', input.clientAddress);
  }
  headers.set('x-forwarded-proto', 'https');

  return headers;
}

/**
 * Re-frame an upstream response for the client.
 *
 * The body is passed through as a stream — never read here. An SSE response can
 * stay open for the length of a tool call, and anything that accumulates it
 * turns a live stream into a timeout.
 */
function relayResponse(upstream: Response): Response {
  const headers = new Headers();
  for (const [name, value] of upstream.headers) {
    if (!DROPPED_RESPONSE_HEADERS.has(name.toLowerCase())) headers.set(name, value);
  }

  if ((upstream.headers.get('content-type') ?? '').includes('text/event-stream')) {
    // Defeat buffering everywhere it might happen: `no-transform` stops
    // intermediaries rewriting the body, and `X-Accel-Buffering: no` is the
    // nginx/Traefik opt-out. Without these the first SSE frame can sit in a
    // proxy buffer until the stream ends, which reads as a hung tool call.
    headers.set('cache-control', 'no-cache, no-transform');
    headers.set('x-accel-buffering', 'no');
  }

  return new Response(upstream.body, {
    status: upstream.status,
    statusText: upstream.statusText,
    headers,
  });
}

/** JSON-RPC shaped error, so a client parses it rather than choking on prose. */
function jsonRpcError(message: string): Record<string, unknown> {
  return { jsonrpc: '2.0', error: { code: -32603, message }, id: null };
}

export function createMcpProxy(deps: ProxyDeps) {
  const { config, store } = deps;

  return async (c: Context): Promise<Response> => {
    const rawHost = c.req.param('host') ?? '';

    // Allowlist check only, and deliberately no DNS yet: an unauthenticated
    // caller must not be able to make this gateway issue resolver queries.
    // The address check runs after authentication, below.
    const known = checkTenant(config, rawHost);
    if (!known.ok) {
      // A 404 with no detail. This does reveal whether a hostname is
      // allowlisted — but so does the protected-resource metadata endpoint,
      // which has to, so there is nothing extra given away here.
      return c.json({ error: 'not_found' }, 404);
    }

    const metadataUrl = resourceMetadataUrlFor(config, known.hostname);
    const challenge = (error: string, description: string, status: 401 | 403 = 401) => {
      c.header(
        'WWW-Authenticate',
        bearerChallenge({
          resourceMetadataUrl: metadataUrl,
          error,
          description,
          scope: SCOPE,
        }),
      );
      return c.json({ error, error_description: description }, status);
    };

    // ── Authenticate ─────────────────────────────────────────────────────────
    const authorization = c.req.header('authorization') ?? '';
    const presented = /^bearer /i.test(authorization) ? authorization.slice(7).trim() : '';
    if (!presented) {
      // The 401 must be at the HTTP layer, not a JSON-RPC error inside a 200.
      // A 200 wrapping {"isError": true} is handed to the model as a tool
      // result and the user never sees a Connect prompt.
      return challenge('invalid_token', 'missing bearer token');
    }

    const resolved = await store.resolveToken(presented);
    if (resolved?.token.kind !== 'access') {
      return challenge('invalid_token', 'the access token is invalid or has expired');
    }

    // ── Audience binding ─────────────────────────────────────────────────────
    if (resolved.token.resource !== resourceFor(config, known.hostname)) {
      log().warn({
        evt: 'audience_mismatch',
        path_host: known.hostname,
        token_host: resolved.grant.hostname,
        grant_id: short(resolved.grant.grantId),
      });
      return challenge('invalid_token', 'this token is not valid for this resource');
    }

    // ── Per-token rate limit ─────────────────────────────────────────────────
    if (config.RATE_LIMITER_ENABLED && config.RATE_LIMITER_MCP_MAX > 0) {
      const used = await store.countAttempt(
        'mcp',
        resolved.grant.grantId,
        config.RATE_LIMITER_MCP_WINDOW,
      );
      if (used > config.RATE_LIMITER_MCP_MAX) {
        log().warn({
          evt: 'mcp_rate_limited',
          host: known.hostname,
          username: resolved.grant.username,
        });
        c.header('Retry-After', String(config.RATE_LIMITER_MCP_WINDOW));
        return c.json(
          {
            jsonrpc: '2.0',
            error: { code: -32000, message: 'Rate limit exceeded' },
            id: null,
          },
          429,
        );
      }
    }

    const apiKey = unseal(store.keyring, resolved.grant.sealedKey);
    if (apiKey === null) {
      // The storage key was rotated under a live grant — the documented
      // "revoke everything" lever. Clean up and make the client re-authorize.
      await store.revokeGrant(resolved.grant.grantId);
      log().warn({ evt: 'grant_undecryptable', grant_id: short(resolved.grant.grantId) });
      return challenge('invalid_token', 'stored credentials could not be read; please reconnect');
    }

    // ── Address check ────────────────────────────────────────────────────────
    // Only now, with an authenticated caller, do we resolve the instance. A
    // failure here is a 502, not a 404: the tenant is real and configured, its
    // address just is not usable right now — either DNS is down or the name
    // resolved into private space, which is a configuration problem the
    // operator needs to see rather than a "connector does not exist".
    const tenant = await resolveTenant(config, known.hostname);
    if (!tenant.ok) {
      log().warn({ evt: 'tenant_unusable', host: known.hostname, reason: tenant.reason });
      return c.json(
        jsonRpcError(
          tenant.reason === 'private_address'
            ? 'the n8n instance resolves to a non-public address'
            : 'the n8n instance could not be resolved',
        ),
        502,
      );
    }

    // ── Build the upstream request ───────────────────────────────────────────
    const headers = buildUpstreamHeaders({
      inbound: c.req.raw.headers,
      upstreamToken: config.N8N_MCP_AUTH_TOKEN,
      tenantOrigin: tenant.origin,
      apiKey,
      instanceId: instanceIdFor(store, resolved.grant.grantId),
      clientAddress: clientIp(c, config.RATE_LIMITER_TRUSTED_PROXY_HOPS),
    });

    const method = c.req.method;
    const hasBody = method !== 'GET' && method !== 'HEAD';

    let upstream: Response;
    try {
      upstream = await fetch(`${config.N8N_MCP_URL}/mcp`, {
        method,
        headers,
        // Stream the request body rather than buffering it: an n8n workflow
        // payload can be large, and holding it in memory per in-flight request
        // is an avoidable failure mode. `duplex: 'half'` is required by the
        // fetch spec whenever the body is a stream.
        ...(hasBody && c.req.raw.body ? { body: c.req.raw.body, duplex: 'half' as const } : {}),
        // When the client hangs up, tear down the upstream call too. Without
        // this an abandoned SSE stream keeps an upstream session alive until
        // its idle timeout, and n8n-mcp caps concurrent sessions.
        signal: AbortSignal.any([c.req.raw.signal, AbortSignal.timeout(config.N8N_MCP_TIMEOUT_MS)]),
        redirect: 'manual',
      });
    } catch (error) {
      const aborted = c.req.raw.signal.aborted;
      if (aborted) {
        // The client left. Nothing to report and nobody to report it to.
        return new Response(null, { status: 499 });
      }
      log().error({ evt: 'upstream_unreachable', detail: String(error) });
      return c.json(jsonRpcError('MCP backend unreachable'), 502);
    }

    // ── Translate upstream auth failures ─────────────────────────────────────
    // n8n-mcp answering 401/403 means the credentials we hold stopped working —
    // either AUTH_TOKEN drifted between the two containers, or the tenant key
    // was revoked. Surfacing that as an OAuth challenge makes the client
    // re-authorize instead of showing the user an opaque tool error.
    if (upstream.status === 401 || upstream.status === 403) {
      await upstream.body?.cancel().catch(() => undefined);
      log().warn({
        evt: 'upstream_rejected',
        host: tenant.hostname,
        status: upstream.status,
      });
      return challenge('invalid_token', 'the MCP backend rejected the stored credentials');
    }

    return relayResponse(upstream);
  };
}

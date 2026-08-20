/**
 * Client identity: dynamic registration (RFC 7591) and Client ID Metadata
 * Documents.
 *
 * Two mechanisms, because the ecosystem is mid-migration:
 *
 *  - **DCR** (`POST /register`) is what every deployed MCP client understands
 *    today. Its flaw is operational: clients register a *fresh* client on every
 *    reconnect, so a busy deployment accrues thousands of records that differ
 *    only by id.
 *  - **CIMD** is the replacement. The client id *is* an https URL that serves
 *    the client's own metadata; there is nothing to register and nothing to
 *    accumulate. MCP marked DCR deprecated in favour of it, and advertising
 *    `client_id_metadata_document_supported` is how a client is told to prefer
 *    it. Claude Code already identifies this way.
 *
 * Both paths end at the same `OAuthClient` record, so /authorize and /token do
 * not care which was used.
 */

import { isIP } from 'node:net';
import type { Config } from '../config.js';
import { log, short } from '../logger.js';
import { hostResolvesPublic, isPublicAddress } from '../n8n/tenant.js';
import type { ClientSource, OAuthClient, Store } from '../store/index.js';

/** Cap on a fetched Client ID Metadata Document. Real ones are well under 4 KB. */
const MAX_CIMD_BYTES = 32 * 1024;
/** CIMD fetches sit on the authorize path, which Claude gives ~10s in total. */
const CIMD_TIMEOUT_MS = 4_000;

// ─── Redirect URI rules ──────────────────────────────────────────────────────

/**
 * Schemes that may never be a redirect target, whatever else is true of them.
 *
 * The rule below deliberately accepts *unrecognised* schemes, because that is
 * what an RFC 8252 §7.1 private-use redirect looks like and there is no registry
 * to check one against: `cursor:`, `vscode:` and `com.example.app:` are all
 * legitimate and share no syntax. Requiring the reverse-DNS form the RFC
 * recommends would reject the editor schemes that are actually in use.
 *
 * That openness is right for schemes naming an *application* and wrong for the
 * handful naming a *capability*. A registered `javascript:` or `data:` redirect
 * reaches two places that matter: the consent page's `form-action` directive,
 * and a `Location` header carrying an authorization code. No current browser
 * will navigate to either from a redirect — so this closes a hole that is not
 * open today rather than one that is. It is here because "the browsers we
 * tested decline to execute it" is not a property to rest an authorization
 * server on, and an embedded webview is under no obligation to agree.
 */
const FORBIDDEN_REDIRECT_SCHEMES: ReadonlySet<string> = new Set([
  'javascript:',
  'data:',
  'vbscript:',
  'blob:',
  'file:',
  'about:',
  'filesystem:',
  'view-source:',
]);

/**
 * Is this a syntactically acceptable redirect URI to register?
 *
 * Accepted:
 *   - any `https://` URI (the normal case — `https://claude.ai/api/mcp/auth_callback`)
 *   - `http://` on a loopback host, for RFC 8252 native clients such as Claude Code
 *   - a private-use scheme (`com.example.app:/cb`, `cursor://…`), also RFC 8252
 *
 * Rejected outright: plain `http://` to a non-loopback host, any URI with a
 * fragment (RFC 6749 §3.1.2 — the fragment is where the browser would put the
 * response, so a registered one cannot be honoured), and the capability schemes
 * above.
 */
export function isAcceptableRedirectUri(raw: string): boolean {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    return false;
  }
  if (url.hash) return false;

  // The URL parser lowercases the scheme, so `JavaScript:` arrives here as
  // `javascript:`. Lowercased again anyway: this set is a security control and
  // should not depend on a normalisation performed elsewhere.
  if (FORBIDDEN_REDIRECT_SCHEMES.has(url.protocol.toLowerCase())) return false;

  if (url.protocol === 'https:') return true;
  if (url.protocol === 'http:') return isLoopbackHost(url.hostname);
  // Anything else is a private-use scheme. RFC 8252 §7.1 allows these for
  // native apps; PKCE is what stops another local app from using the code.
  return url.protocol.endsWith(':') && url.protocol.length > 2;
}

function isLoopbackHost(hostname: string): boolean {
  const host = hostname.replace(/^\[|\]$/g, '').toLowerCase();
  if (host === 'localhost') return true;
  if (isIP(host)) {
    // 127.0.0.0/8 and ::1. Reuse the address classifier rather than string
    // matching, so `127.0.0.2` and `0:0:0:0:0:0:0:1` are handled too.
    return !isPublicAddress(host) && (host.startsWith('127.') || /^0*:.*:0*1$/.test(host));
  }
  return false;
}

/**
 * Does `candidate` match one of a client's registered redirect URIs?
 *
 * Exact string comparison, with one deliberate exception: RFC 8252 §7.3 says a
 * native client's loopback redirect must be matched **ignoring the port**,
 * because the client binds an ephemeral port at runtime and cannot know it at
 * registration time. Claude Code registers `http://localhost/callback` and
 * `http://127.0.0.1/callback` and then listens on something like :3118.
 * Strict string matching rejects it and the connector simply never works —
 * while claude.ai, which uses a fixed https callback, works fine, making it
 * look like a Claude Code bug.
 *
 * `localhost` and `127.0.0.1` are also treated as interchangeable, since a
 * client may register one and resolve to the other.
 */
export function matchesRedirectUri(registered: readonly string[], candidate: string): boolean {
  if (registered.includes(candidate)) return true;

  let want: URL;
  try {
    want = new URL(candidate);
  } catch {
    return false;
  }
  if (want.protocol !== 'http:' || !isLoopbackHost(want.hostname)) return false;

  for (const entry of registered) {
    let have: URL;
    try {
      have = new URL(entry);
    } catch {
      continue;
    }
    if (have.protocol !== 'http:' || !isLoopbackHost(have.hostname)) continue;
    // Everything but the port must be identical.
    if (have.pathname === want.pathname && have.search === want.search) return true;
  }
  return false;
}

/**
 * Operator-configured restriction on who may register at all.
 *
 * Empty means "any acceptable redirect URI", which is the MCP default and is
 * what lets a client we have never heard of connect. A deployment that only
 * ever serves Claude should list the two Anthropic callbacks and close the
 * door.
 */
export function isPermittedByOperator(config: Config, uris: readonly string[]): boolean {
  const allowed = config.MCP_ALLOWED_CLIENT_REDIRECT_URIS;
  if (!allowed.length) return true;
  return uris.every((uri) => allowed.some((prefix) => uri.startsWith(prefix)));
}

// ─── Dynamic client registration ─────────────────────────────────────────────

export interface RegistrationRequest {
  readonly redirect_uris?: unknown;
  readonly client_name?: unknown;
  readonly application_type?: unknown;
  readonly token_endpoint_auth_method?: unknown;
}

export type RegistrationResult =
  | { ok: true; client: OAuthClient }
  | { ok: false; error: string; description: string };

/**
 * Handle an RFC 7591 registration.
 *
 * Everything a client asks for beyond redirect URIs and a name is ignored
 * rather than negotiated: this server issues exactly one grant type set, one
 * response type, and public clients only. Echoing back what we actually support
 * (rather than what was requested) is what RFC 7591 §3.2.1 calls for and keeps
 * a client from believing it registered something it did not.
 */
export async function registerClient(
  config: Config,
  store: Store,
  body: RegistrationRequest,
): Promise<RegistrationResult> {
  const uris = Array.isArray(body.redirect_uris)
    ? body.redirect_uris.filter((u): u is string => typeof u === 'string' && u.length > 0)
    : [];

  if (!uris.length) {
    return {
      ok: false,
      error: 'invalid_redirect_uri',
      description: 'redirect_uris is required and must contain at least one URI',
    };
  }
  if (uris.length > 10) {
    return {
      ok: false,
      error: 'invalid_redirect_uri',
      description: 'at most 10 redirect URIs may be registered',
    };
  }
  const bad = uris.find((uri) => !isAcceptableRedirectUri(uri));
  if (bad !== undefined) {
    return {
      ok: false,
      error: 'invalid_redirect_uri',
      description: `${bad} is not an acceptable redirect URI (https, loopback http, or a private-use scheme)`,
    };
  }
  if (!isPermittedByOperator(config, uris)) {
    return {
      ok: false,
      error: 'invalid_redirect_uri',
      description: 'redirect URI is not permitted by this deployment',
    };
  }

  // `application_type` became required in MCP's 2026-07-28 revision. Older
  // clients omit it, so infer from the URIs rather than rejecting: a loopback
  // or private-use redirect is a native app by definition.
  const declared = body.application_type;
  const applicationType: 'web' | 'native' =
    declared === 'native' || declared === 'web'
      ? declared
      : uris.some((uri) => !uri.startsWith('https://'))
        ? 'native'
        : 'web';

  const client: OAuthClient = {
    clientId: `c_${crypto.randomUUID()}`,
    redirectUris: uris,
    clientName: typeof body.client_name === 'string' ? body.client_name.slice(0, 200) : null,
    source: 'dcr',
    applicationType,
    createdAt: Date.now(),
  };
  await store.putClient(client);
  log().info({
    evt: 'client_registered',
    client_id: short(client.clientId),
    name: client.clientName,
    application_type: applicationType,
    source: 'dcr',
  });
  return { ok: true, client };
}

// ─── Client ID Metadata Documents ────────────────────────────────────────────

/** A client id is a CIMD reference when it is an https URL with a path. */
export function looksLikeCimd(clientId: string): boolean {
  if (!clientId.startsWith('https://')) return false;
  try {
    const url = new URL(clientId);
    // "MUST contain a path component" — `https://example.com` alone is not a
    // document, and accepting it would let any origin claim an identity.
    return url.pathname.length > 1 && !url.hash;
  } catch {
    return false;
  }
}

/**
 * Fetch and validate a Client ID Metadata Document.
 *
 * This method takes a URL from an unauthenticated request and fetches it, which
 * is an SSRF primitive if left unguarded. Four guards, all required:
 *
 *   1. https only, with a path component
 *   2. the host must resolve entirely to public addresses
 *   3. redirects are not followed — a 302 to 169.254.169.254 would undo (2)
 *   4. bounded size and a short timeout
 *
 * The document is then validated per the spec: `client_id` inside the document
 * must equal the URL it was fetched from, which is what stops one site from
 * publishing a document claiming another site's identity.
 */
export async function resolveCimdClient(
  config: Config,
  store: Store,
  clientId: string,
): Promise<OAuthClient | null> {
  if (!looksLikeCimd(clientId)) return null;

  const url = new URL(clientId);
  if (!config.N8N_ALLOW_PRIVATE_ADDRESSES && !(await hostIsPublic(url.hostname))) {
    log().warn({ evt: 'cimd_rejected', reason: 'non_public_host', host: url.hostname });
    return null;
  }

  let response: Response;
  try {
    response = await fetch(clientId, {
      headers: { accept: 'application/json' },
      redirect: 'error',
      signal: AbortSignal.timeout(CIMD_TIMEOUT_MS),
    });
  } catch (error) {
    log().warn({ evt: 'cimd_fetch_failed', host: url.hostname, detail: String(error) });
    return null;
  }
  if (!response.ok) {
    await response.body?.cancel().catch(() => undefined);
    log().warn({ evt: 'cimd_fetch_failed', host: url.hostname, status: response.status });
    return null;
  }

  const text = await readBounded(response, MAX_CIMD_BYTES);
  if (text === null) return null;

  let document: Record<string, unknown>;
  try {
    const parsed: unknown = JSON.parse(text);
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return null;
    document = parsed as Record<string, unknown>;
  } catch {
    log().warn({ evt: 'cimd_invalid', reason: 'not_json', host: url.hostname });
    return null;
  }

  // The identity check. Without it, any https host could serve a document
  // naming someone else's client_id and inherit their registration.
  if (document['client_id'] !== clientId) {
    log().warn({ evt: 'cimd_invalid', reason: 'client_id_mismatch', host: url.hostname });
    return null;
  }

  const uris = Array.isArray(document['redirect_uris'])
    ? (document['redirect_uris'] as unknown[]).filter(
        (u): u is string => typeof u === 'string' && isAcceptableRedirectUri(u),
      )
    : [];
  if (!uris.length) {
    log().warn({ evt: 'cimd_invalid', reason: 'no_usable_redirect_uris', host: url.hostname });
    return null;
  }
  if (!isPermittedByOperator(config, uris)) {
    log().warn({ evt: 'cimd_rejected', reason: 'operator_policy', host: url.hostname });
    return null;
  }

  const applicationType: 'web' | 'native' =
    document['application_type'] === 'native' || uris.some((u) => !u.startsWith('https://'))
      ? 'native'
      : 'web';

  const client: OAuthClient = {
    clientId,
    redirectUris: uris,
    clientName:
      typeof document['client_name'] === 'string'
        ? (document['client_name'] as string).slice(0, 200)
        : null,
    source: 'cimd' satisfies ClientSource,
    applicationType,
    createdAt: Date.now(),
  };

  // Cached so the next authorize does not refetch. `putClient` gives this the
  // short AUTH_CIMD_CACHE_TTL rather than the registration lifetime, keyed off
  // `source` — a document the client controls must not be pinned for months,
  // because nothing revalidates it and a rotated redirect URI would be rejected
  // until it expired.
  await store.putClient(client);
  log().info({
    evt: 'client_registered',
    client_id: short(clientId, 40),
    name: client.clientName,
    application_type: applicationType,
    source: 'cimd',
  });
  return client;
}

/**
 * Look a client up: stored first, then CIMD. Returns null when neither applies.
 */
export async function findClient(
  config: Config,
  store: Store,
  clientId: string,
): Promise<OAuthClient | null> {
  const stored = await store.getClient(clientId);
  if (stored) return stored;
  return await resolveCimdClient(config, store, clientId);
}

// ─── helpers ─────────────────────────────────────────────────────────────────

/**
 * Address-space guard for the CIMD fetch, sharing the tenant path's resolver.
 *
 * This used to be its own `lookup()` with no deadline and no cache, which made
 * an unauthenticated `/authorize` worth one uncached resolver query to a host
 * the caller names. `dns.lookup` is getaddrinfo on a libuv thread and takes no
 * signal, so a name whose authoritative server simply never answers occupies a
 * slot in a pool that is four deep by default.
 *
 * `hostResolvesPublic` is three-valued; here `null` (unresolvable) and `false`
 * (resolved, not public) collapse to the same refusal. On the tenant path they
 * must not — an operator needs to tell an outage from a misconfiguration — but
 * a client document we cannot reach is simply a client we cannot identify.
 */
async function hostIsPublic(hostname: string): Promise<boolean> {
  return (await hostResolvesPublic(hostname)) === true;
}

async function readBounded(response: Response, limit: number): Promise<string | null> {
  const reader = response.body?.getReader();
  if (!reader) return null;
  const chunks: Buffer[] = [];
  let total = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      if (!value) continue;
      total += value.byteLength;
      if (total > limit) return null;
      chunks.push(Buffer.from(value));
    }
  } catch {
    return null;
  } finally {
    reader.releaseLock();
    await response.body?.cancel().catch(() => undefined);
  }
  return Buffer.concat(chunks).toString('utf8');
}

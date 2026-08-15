/**
 * The OAuth 2.1 authorization server.
 *
 * Endpoints: `/register` (RFC 7591), `/authorize`, `/token`, `/revoke`
 * (RFC 7009), plus the discovery documents from metadata.ts.
 *
 * The flow, end to end:
 *
 *   GET  /authorize?…&resource=https://gw/i/HOST/mcp
 *        ├─ validate client, redirect_uri, PKCE, resource → tenant
 *        ├─ park the request server-side, get a form handle
 *        └─ render the consent screen
 *   POST /authorize  (username + n8n API key)
 *        ├─ rate-limit, inspect the key, probe the instance
 *        ├─ seal the key into a Grant
 *        └─ 303 back to the client with ?code=…&state=…&iss=…
 *   POST /token  (code + code_verifier)
 *        └─ access + refresh token, both bound to the grant and the resource
 *
 * Two things in here are easy to get wrong and expensive to debug:
 *
 *  - **The consent redirect must be 303.** A 302 or 307 preserves the POST
 *    method, so `https://claude.ai/api/mcp/auth_callback` receives a POST,
 *    answers 405, and the token exchange never happens. The user sees a
 *    generic connection failure and every log line up to that point looks fine.
 *
 *  - **Never redirect an error to an unvalidated redirect_uri.** RFC 6749
 *    §4.1.2.1: if the client or the URI is unknown, the error is rendered on
 *    our own page. Redirecting instead turns this endpoint into an open
 *    redirect that reflects attacker-controlled parameters.
 */

import { createHash } from 'node:crypto';
import type { Context } from 'hono';
import { Hono } from 'hono';
import type { Config } from '../config.js';
import { randomToken, safeEqual, seal, unseal } from '../lib/crypto.js';
import { clientIp, formBody } from '../lib/request.js';
import { log, short } from '../logger.js';
import { validateCredential } from '../n8n/credential.js';
import { probeApiKey } from '../n8n/probe.js';
import { checkTenant } from '../n8n/tenant.js';
import type { Grant, Store } from '../store/index.js';
import { errorText, pickLocale } from '../ui/i18n.js';
import { consentPage, errorPage } from '../ui/pages.js';
import { findClient, matchesRedirectUri, registerClient } from './clients.js';
import {
  authorizationServerMetadata,
  OFFLINE_SCOPE,
  protectedResourceMetadata,
  resourceFor,
  SCOPE,
} from './metadata.js';

export interface OAuthDeps {
  readonly config: Config;
  readonly store: Store;
}

/**
 * Rate-limit buckets. Named rather than ad-hoc strings so the set is visible in
 * one place and cannot drift between the check and the increment.
 */
const BUCKET = { login: 'login', token: 'token', submit: 'submit' } as const;

/**
 * Consent submissions one IP may make per login window, as a multiple of
 * `RATE_LIMITER_LOGIN_MAX`.
 *
 * Separate from the lockout because it answers a different question. The
 * lockout asks "is someone guessing this account's key" and must therefore
 * count only verdicts on a key. This asks "is someone using the consent form
 * as a probe engine", which every submission contributes to regardless of how
 * it ends. At the default of 10 that allows 60 submissions per 15 minutes per
 * address — far beyond any human, well below a useful amplifier.
 */
const SUBMIT_BUDGET_FACTOR = 6;

export function createOAuthRoutes(deps: OAuthDeps): Hono {
  const { config, store } = deps;
  const app = new Hono();
  const locales = (c: { req: { header: (n: string) => string | undefined } }) =>
    pickLocale(c.req.header('accept-language'));

  // ───────────────────────────────────────────────────────────────────────────
  // Discovery
  // ───────────────────────────────────────────────────────────────────────────

  app.get('/.well-known/oauth-authorization-server', (c) =>
    c.json(authorizationServerMetadata(config)),
  );

  /**
   * Served with the same body as the RFC 8414 document.
   *
   * Clients try `oauth-authorization-server` first and fall back to
   * `openid-configuration`; ours answers 200 on the first, so this is only
   * reached by clients that skip straight to the OIDC path. It costs one route
   * and removes a whole class of "discovery failed" reports. We are not an
   * OpenID Provider and the document says nothing that claims we are.
   */
  app.get('/.well-known/openid-configuration', (c) => c.json(authorizationServerMetadata(config)));

  /**
   * RFC 9728 protected-resource metadata, one document per tenant.
   *
   * Note the shape of the route: the well-known segment comes FIRST and the
   * resource path is appended after it. That is RFC 9728 §3 path *insertion*,
   * and it is the opposite of where OIDC puts its well-known segment.
   */
  app.get('/.well-known/oauth-protected-resource/i/:host/mcp', (c) => {
    const tenant = checkTenant(config, c.req.param('host'));
    if (!tenant.ok) {
      return c.json({ error: 'not_found', error_description: 'unknown resource' }, 404);
    }
    return c.json(protectedResourceMetadata(config, tenant.hostname));
  });

  // ───────────────────────────────────────────────────────────────────────────
  // Dynamic client registration
  // ───────────────────────────────────────────────────────────────────────────

  app.post('/register', async (c) => {
    const body = await c.req.json().catch(() => ({}));
    const result = await registerClient(config, store, body as Record<string, unknown>);
    if (!result.ok) {
      return c.json({ error: result.error, error_description: result.description }, 400);
    }
    const { client } = result;
    // RFC 7591 §3.2.1: echo what the server actually granted, not what was
    // asked for. `client_secret` is absent on purpose — public client.
    return c.json(
      {
        client_id: client.clientId,
        client_id_issued_at: Math.floor(client.createdAt / 1000),
        redirect_uris: client.redirectUris,
        ...(client.clientName ? { client_name: client.clientName } : {}),
        application_type: client.applicationType,
        token_endpoint_auth_method: 'none',
        grant_types: ['authorization_code', 'refresh_token'],
        response_types: ['code'],
        scope: `${SCOPE} ${OFFLINE_SCOPE}`,
      },
      201,
    );
  });

  // ───────────────────────────────────────────────────────────────────────────
  // Authorize
  // ───────────────────────────────────────────────────────────────────────────

  /** Bounce an error back to a redirect_uri we have already validated. */
  const redirectError = (
    c: Context,
    redirectUri: string,
    state: string | null,
    error: string,
    description: string,
  ) => {
    const url = new URL(redirectUri);
    url.searchParams.set('error', error);
    url.searchParams.set('error_description', description);
    if (state) url.searchParams.set('state', state);
    // RFC 9207: `iss` goes on error responses too, so a client can tell which
    // authorization server rejected it before acting on the message.
    url.searchParams.set('iss', config.baseUrl);
    return c.redirect(url.toString(), 302);
  };

  app.get('/authorize', async (c) => {
    const locale = locales(c);
    const q = c.req.query();
    const fail = (code: string) =>
      c.html(errorPage(locale, config.MCP_DISPLAY_NAME, errorText(locale, code)), 400);

    const clientId = q['client_id'] ?? '';
    const client = clientId ? await findClient(config, store, clientId) : null;
    if (!client) {
      log().warn({ evt: 'authorize_unknown_client', client_id: short(clientId, 40) });
      return fail('unknown_client');
    }

    const redirectUri = q['redirect_uri'] ?? '';
    if (!redirectUri || !matchesRedirectUri(client.redirectUris, redirectUri)) {
      // Deliberately NOT redirected — see the file header.
      log().warn({ evt: 'authorize_bad_redirect', client_id: short(client.clientId, 40) });
      return fail('invalid_redirect');
    }

    const state = q['state'] ?? null;

    if (q['response_type'] !== 'code') {
      return redirectError(
        c,
        redirectUri,
        state,
        'unsupported_response_type',
        'only response_type=code is supported',
      );
    }
    // PKCE is mandatory, S256 only. OAuth 2.1 removes `plain` for any client
    // capable of SHA-256, and every MCP client is.
    const codeChallenge = q['code_challenge'] ?? '';
    if (!codeChallenge || q['code_challenge_method'] !== 'S256') {
      return redirectError(
        c,
        redirectUri,
        state,
        'invalid_request',
        'PKCE with code_challenge_method=S256 is required',
      );
    }

    const hostname = hostFromResource(config, q['resource']);
    if (!hostname) {
      return redirectError(
        c,
        redirectUri,
        state,
        'invalid_target',
        'resource must be this gateway’s MCP URL for a permitted n8n instance',
      );
    }
    // Allowlist only here. The address check runs a moment later, when the
    // consent POST actually connects to the instance to validate the key.
    const tenant = checkTenant(config, hostname);
    if (!tenant.ok) {
      log().warn({ evt: 'authorize_tenant_rejected', host: hostname, reason: tenant.reason });
      return redirectError(
        c,
        redirectUri,
        state,
        'invalid_target',
        'unknown or disallowed resource',
      );
    }

    const requestId = await store.createPendingAuth({
      clientId: client.clientId,
      redirectUri,
      state,
      codeChallenge,
      hostname: tenant.hostname,
      resource: resourceFor(config, tenant.hostname),
      createdAt: Date.now(),
    });

    return c.html(
      consentPage({
        locale,
        displayName: config.MCP_DISPLAY_NAME,
        hostname: tenant.hostname,
        clientName: client.clientName,
        requestId,
        username: '',
        error: null,
      }),
    );
  });

  app.post('/authorize', async (c) => {
    const locale = locales(c);
    const form = await formBody(c);
    const requestId = form['request_id'] ?? '';

    // CLAIMED, not read. Validating the key takes seconds against a remote
    // instance, and the form has no client-side guard against a second submit
    // in that window (it ships no script, and the page runs under
    // `script-src 'none'`). A non-destructive read let both submits through to
    // `createGrant`, minting two long-lived grants — two sealed copies of the
    // same API key — of which the user only ever learns about one. An atomic
    // claim makes the second submit lose, and losing reads as "session
    // expired", which is exactly what happened to it.
    const pending = await store.takePendingAuth(requestId);

    if (!pending) {
      return c.html(
        errorPage(locale, config.MCP_DISPLAY_NAME, errorText(locale, 'session_expired')),
        400,
      );
    }

    const client = await findClient(config, store, pending.clientId);
    if (!client || !matchesRedirectUri(client.redirectUris, pending.redirectUri)) {
      // The client's registration changed or expired while the form was open.
      // The claim above already removed the record; there is nothing to put back.
      return c.html(
        errorPage(locale, config.MCP_DISPLAY_NAME, errorText(locale, 'unknown_client')),
        400,
      );
    }

    const username = (form['username'] ?? '').trim().slice(0, 200);
    const apiKey = (form['api_key'] ?? '').trim();

    /**
     * Re-render the same form, keeping the request alive for another attempt.
     *
     * Restoring the claim is what makes this a retry rather than a dead end.
     * Every non-success exit below routes through here, so the claim is put
     * back on all of them without each one having to remember to.
     */
    const retry = async (code: string, status: 400 | 429 = 400) => {
      await store.restorePendingAuth(requestId, pending);
      return c.html(
        consentPage({
          locale,
          displayName: config.MCP_DISPLAY_NAME,
          hostname: pending.hostname,
          clientName: client.clientName,
          requestId,
          username,
          error: errorText(locale, code),
        }),
        status,
      );
    };

    // ── Brute-force gate ─────────────────────────────────────────────────────
    // Keyed on the client IP AND the typed username. IP alone punishes everyone
    // behind one NAT for a single fat-fingered colleague; username alone lets
    // an attacker spread guesses across names. Either bucket tripping is enough.
    const ip = clientIp(c, config.RATE_LIMITER_TRUSTED_PROXY_HOPS);
    if (config.RATE_LIMITER_ENABLED) {
      const [byIp, byUser] = await Promise.all([
        store.attemptCount(BUCKET.login, ip),
        username ? store.attemptCount(BUCKET.login, `u:${username}`) : Promise.resolve(0),
      ]);
      if (Math.max(byIp, byUser) >= config.RATE_LIMITER_LOGIN_MAX) {
        log().warn({ evt: 'login_rate_limited', host: pending.hostname, ip });
        return await retry('rate_limited_login', 429);
      }
    }

    // ── Volume gate ──────────────────────────────────────────────────────────
    // The lockout above counts only credential VERDICTS, deliberately: an
    // unreachable instance must never lock out the people who depend on it.
    // The cost of that is every other outcome going uncounted, and each one
    // still buys the caller an outbound probe from this gateway. This second
    // bucket bounds the request volume without touching the lockout semantics,
    // and it counts every submission — including the ones that succeed.
    //
    // The ceiling is a generous multiple of the lockout, so it is reached only
    // by something automated; a human fumbling a paste cannot trip it.
    if (config.RATE_LIMITER_ENABLED) {
      const submissions = await store.countAttempt(
        BUCKET.submit,
        ip,
        config.RATE_LIMITER_LOGIN_WINDOW,
      );
      if (submissions > config.RATE_LIMITER_LOGIN_MAX * SUBMIT_BUDGET_FACTOR) {
        log().warn({
          evt: 'authorize_flooded',
          host: pending.hostname,
          ip,
          submissions,
        });
        return await retry('rate_limited_login', 429);
      }
    }

    const countFailure = async () => {
      if (!config.RATE_LIMITER_ENABLED) return;
      await Promise.all([
        store.countAttempt(BUCKET.login, ip, config.RATE_LIMITER_LOGIN_WINDOW),
        username
          ? store.countAttempt(BUCKET.login, `u:${username}`, config.RATE_LIMITER_LOGIN_WINDOW)
          : Promise.resolve(0),
      ]);
    };

    if (!username) return await retry('no_username');
    if (!apiKey) return await retry('empty');

    // ── Validate the credential ──────────────────────────────────────────────
    // Offline inspection, then the SSRF-guarded address check, then one probe
    // against the instance. See n8n/credential.ts for which failures count
    // toward the lockout and why.
    const check = await validateCredential(config, pending.hostname, apiKey);
    if (!check.ok) {
      if (check.countsAsFailure) await countFailure();
      log().warn({
        evt: 'credential_rejected',
        host: pending.hostname,
        code: check.code,
        detail: check.detail,
      });
      return await retry(check.code);
    }

    // ── Consent granted ──────────────────────────────────────────────────────
    await store.clearAttempts(BUCKET.login, ip);
    if (username) await store.clearAttempts(BUCKET.login, `u:${username}`);

    const grant = await store.createGrant({
      hostname: pending.hostname,
      sealedKey: seal(store.keyring, apiKey),
      clientId: client.clientId,
      resource: pending.resource,
      username,
      n8nUserId: check.n8nUserId,
    });

    const code = randomToken();
    await store.putCode(code, {
      grantId: grant.grantId,
      clientId: client.clientId,
      redirectUri: pending.redirectUri,
      codeChallenge: pending.codeChallenge,
      resource: pending.resource,
    });

    log().info({
      evt: 'consent_granted',
      host: pending.hostname,
      username,
      n8n_user: short(grant.n8nUserId),
      client_id: short(client.clientId, 40),
      grant_id: short(grant.grantId),
    });

    const back = new URL(pending.redirectUri);
    back.searchParams.set('code', code);
    if (pending.state) back.searchParams.set('state', pending.state);
    back.searchParams.set('iss', config.baseUrl);

    // 303, not 302 or 307. See the file header — this one line is the
    // difference between a working connector and a 405 at the callback.
    return c.redirect(back.toString(), 303);
  });

  // ───────────────────────────────────────────────────────────────────────────
  // Token
  // ───────────────────────────────────────────────────────────────────────────

  app.post('/token', async (c) => {
    const form = await formBody(c);
    const ip = clientIp(c, config.RATE_LIMITER_TRUSTED_PROXY_HOPS);

    if (config.RATE_LIMITER_ENABLED) {
      const attempts = await store.countAttempt(BUCKET.token, ip, config.RATE_LIMITER_TOKEN_WINDOW);
      if (attempts > config.RATE_LIMITER_TOKEN_MAX) {
        log().warn({ evt: 'token_rate_limited', ip });
        return c.json({ error: 'invalid_request', error_description: 'too many requests' }, 429);
      }
    }

    const grantType = form['grant_type'] ?? '';
    if (grantType === 'authorization_code') return await exchangeCode(c, form);
    if (grantType === 'refresh_token') return await refresh(c, form);
    return c.json(
      {
        error: 'unsupported_grant_type',
        error_description: 'supported: authorization_code, refresh_token',
      },
      400,
    );
  });

  type TokenCtx = Context;

  async function exchangeCode(c: TokenCtx, form: Record<string, string>) {
    // Single-use by construction: takeCode is an atomic read-and-delete, so a
    // replayed code finds nothing even if two requests race.
    const record = await store.takeCode(form['code'] ?? '');
    if (!record) {
      return c.json(
        { error: 'invalid_grant', error_description: 'unknown, expired or already used code' },
        400,
      );
    }
    if (record.clientId !== form['client_id']) {
      return c.json(
        { error: 'invalid_grant', error_description: 'code was issued to a different client' },
        400,
      );
    }
    if (record.redirectUri !== form['redirect_uri']) {
      return c.json(
        { error: 'invalid_grant', error_description: 'redirect_uri does not match the request' },
        400,
      );
    }

    // RFC 8707: when the client names a resource at the token endpoint it must
    // be the one the code was issued for. Silently ignoring a mismatch would
    // let a code minted for tenant A be exchanged for a token claiming tenant B.
    const requestedResource = form['resource'];
    if (requestedResource && normalizeResource(requestedResource) !== record.resource) {
      return c.json(
        { error: 'invalid_target', error_description: 'resource does not match the authorization' },
        400,
      );
    }

    const verifier = form['code_verifier'] ?? '';
    const computed = createHash('sha256').update(verifier).digest('base64url');
    if (!verifier || !safeEqual(computed, record.codeChallenge)) {
      log().warn({ evt: 'pkce_failed', client_id: short(record.clientId, 40) });
      return c.json({ error: 'invalid_grant', error_description: 'PKCE verification failed' }, 400);
    }

    const grant = await store.getGrant(record.grantId);
    if (!grant) {
      return c.json({ error: 'invalid_grant', error_description: 'grant no longer exists' }, 400);
    }

    log().info({ evt: 'token_issued', grant: 'code', host: grant.hostname });
    return c.json(await issueTokens(grant));
  }

  async function refresh(c: TokenCtx, form: Record<string, string>) {
    // Rotation: the presented refresh token is consumed here, so it cannot be
    // used twice. OAuth 2.1 requires this for public clients.
    const resolved = await store.takeToken(form['refresh_token'] ?? '');
    if (resolved?.token.kind !== 'refresh') {
      return c.json({ error: 'invalid_grant', error_description: 'unknown refresh token' }, 400);
    }
    const { grant } = resolved;

    if (form['client_id'] && form['client_id'] !== resolved.token.clientId) {
      return c.json({ error: 'invalid_grant', error_description: 'client mismatch' }, 400);
    }

    // ── Re-validate the stored key ───────────────────────────────────────────
    // A key deleted or rotated in n8n should end the grant at the next refresh
    // rather than keep working for the rest of the refresh window.
    //
    // Two asymmetries, both deliberate:
    //  - Only a verdict from n8n on the key itself revokes. An unreachable
    //    instance must not log out every user of that instance during a
    //    maintenance window — and neither must an edge that started demanding
    //    its own login (`proxy_auth`), which says nothing about the key.
    //  - The probe timeout is capped well below the ~30s a client allows for a
    //    refresh, because blowing that budget fails the refresh anyway — and
    //    then looks like our bug rather than a slow n8n.
    const apiKey = unseal(store.keyring, grant.sealedKey);
    if (apiKey === null) {
      // Undecryptable: the storage key was rotated. That is the intended
      // "revoke everything" lever, so treat it as a dead grant.
      await store.revokeGrant(grant.grantId);
      return c.json(
        { error: 'invalid_grant', error_description: 'stored credentials are no longer readable' },
        400,
      );
    }

    const probe = await probeApiKey(`https://${grant.hostname}`, apiKey, {
      timeoutMs: Math.min(config.N8N_PROBE_TIMEOUT_MS, 5_000),
    });
    if (!probe.ok && (probe.code === 'bad_key' || probe.code === 'insufficient_permissions')) {
      await store.revokeGrant(grant.grantId);
      log().warn({
        evt: 'grant_revoked',
        reason: probe.code,
        host: grant.hostname,
        username: grant.username,
      });
      return c.json(
        { error: 'invalid_grant', error_description: 'the n8n API key is no longer valid' },
        400,
      );
    }

    // The fail-open above is deliberate, but it must not also be silent. The
    // interactive path logs `credential_rejected` for every non-ok probe;
    // without this line the unattended path logs nothing at all, so an instance
    // that has been unreachable for a week looks exactly like a healthy one.
    if (!probe.ok) {
      log().warn({
        evt: 'refresh_probe_failed',
        reason: probe.code,
        host: grant.hostname,
        username: grant.username,
        detail: probe.detail,
      });
    }

    await store.touchGrant(grant);
    log().info({ evt: 'token_issued', grant: 'refresh', host: grant.hostname });
    return c.json(await issueTokens(grant));
  }

  async function issueTokens(grant: Grant) {
    const accessToken = randomToken();
    const refreshToken = randomToken();
    const base = {
      grantId: grant.grantId,
      clientId: grant.clientId,
      resource: grant.resource,
      issuedAt: Date.now(),
    };
    await Promise.all([
      store.putToken(accessToken, { ...base, kind: 'access' }, config.AUTH_ACCESS_TOKEN_TTL),
      store.putToken(refreshToken, { ...base, kind: 'refresh' }, config.AUTH_REFRESH_TOKEN_TTL),
    ]);
    return {
      access_token: accessToken,
      token_type: 'Bearer',
      expires_in: config.AUTH_ACCESS_TOKEN_TTL,
      refresh_token: refreshToken,
      scope: SCOPE,
    };
  }

  // ───────────────────────────────────────────────────────────────────────────
  // Revocation (RFC 7009)
  // ───────────────────────────────────────────────────────────────────────────

  /**
   * Not required by the MCP spec, implemented anyway because it is the only
   * clean way for a user to disconnect: revoking either token drops the whole
   * grant, and with it the stored n8n API key.
   *
   * RFC 7009 §2.2 requires 200 even for an unknown token — telling a caller
   * whether a token existed is an oracle.
   */
  app.post('/revoke', async (c) => {
    const form = await formBody(c);
    const presented = form['token'] ?? '';
    if (presented) {
      const resolved = (await store.resolveToken(presented)) ?? (await store.takeToken(presented));
      if (resolved) {
        await store.revokeGrant(resolved.grant.grantId);
        await store.deleteToken(presented);
        log().info({
          evt: 'grant_revoked',
          reason: 'client_request',
          host: resolved.grant.hostname,
          username: resolved.grant.username,
        });
      }
    }
    return c.body(null, 200);
  });

  return app;
}

// ─── helpers ─────────────────────────────────────────────────────────────────

/**
 * Strip a trailing slash from a resource identifier before comparing.
 *
 * Clients are told to send the canonical form, and Claude does. Being lenient
 * about exactly one trailing slash costs nothing and removes a failure mode
 * where the user typed the connector URL with a slash.
 */
export function normalizeResource(raw: string): string {
  return raw.replace(/\/+$/, '');
}

/**
 * Extract the tenant hostname from an RFC 8707 resource indicator.
 *
 * Returns null unless the value is exactly `${baseUrl}/i/<host>/mcp`. Parsing
 * rather than pattern-matching the tail matters: `…/i/evil/mcp/../../x` and
 * `…/i/evil/mcp?x=1` must not be read as a tenant.
 */
export function hostFromResource(config: Config, resource: string | undefined): string | null {
  if (!resource) return null;
  const normalized = normalizeResource(resource);
  if (!normalized.startsWith(`${config.baseUrl}/`)) return null;

  let url: URL;
  try {
    url = new URL(normalized);
  } catch {
    return null;
  }
  if (url.search || url.hash) return null;

  const match = /^\/i\/([^/]+)\/mcp$/.exec(url.pathname);
  if (!match?.[1]) return null;
  return decodeURIComponent(match[1]).toLowerCase();
}

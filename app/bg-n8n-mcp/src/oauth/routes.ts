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
import type { AppEnv } from '../app.js';
import type { Config } from '../config.js';
import { randomToken, safeEqual, seal, unseal } from '../lib/crypto.js';
import { clientIp, formBody } from '../lib/request.js';
import { log, short } from '../logger.js';
import { validateCredential } from '../n8n/credential.js';
import { probeApiKey } from '../n8n/probe.js';
import { checkTenant } from '../n8n/tenant.js';
import type { Grant, OAuthClient, RotationRecord, Store } from '../store/index.js';
import { errorText, pickLocale } from '../ui/i18n.js';
import { consentPage, errorPage } from '../ui/pages.js';
import {
  findClient,
  looksLikeCimd,
  matchesRedirectUri,
  registerClient,
  resolveCimdClient,
} from './clients.js';
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
const BUCKET = {
  login: 'login',
  token: 'token',
  /** Coarse address-keyed backstop for /token; see the endpoint for why. */
  tokenIp: 'tokenip',
  submit: 'submit',
  register: 'register',
  cimd: 'cimd',
  /** Consecutive `bad_key` verdicts against one grant, on the refresh path. */
  badKey: 'badkey',
} as const;

/**
 * How much more /token traffic one address may make than one client.
 *
 * The address bucket exists only to bound a caller inventing a fresh
 * `client_id` per request. It must sit far above what a busy shared egress
 * legitimately produces, or it re-creates the very collapse the client-keyed
 * bucket was introduced to fix.
 */
const TOKEN_IP_BUDGET_FACTOR = 20;

/**
 * How long the loser of a rotation race waits for the winner to publish.
 *
 * Rotation is decided by one atomic `takeToken`, so the loser learns it lost
 * *before* the winner has finished writing what it minted. A single miss is
 * therefore ambiguous — the token may be unknown, or the winner may be two
 * store round trips from publishing — and answering `invalid_grant` on that
 * first miss tells a client with a perfectly live grant to throw it away.
 *
 * One settle-and-recheck separates the two cases. It is bounded and it happens
 * only on a miss, so a caller presenting garbage tokens buys 50ms of nothing
 * rather than a held connection; polling to a deadline would have made an
 * unknown token into an amplifier. 50ms is roughly ten times the round trips
 * the winner still owes at that point (two token writes and the grace record).
 */
const REFRESH_REPLAY_SETTLE_MS = 50;

/**
 * How many consecutive `bad_key` verdicts end a grant.
 *
 * One is not evidence. The refresh path probes the user's own n8n on every
 * refresh — hourly, unattended — and a challenge-less 401 or a bare 403 is what
 * a Cloudflare block page, an n8n mid-restart and a licence-check window all
 * return. Acting on a single sample deleted the grant, which killed every token
 * pointing at it, and the reconnect the user then attempted ran the *same*
 * probe and told them their key was bad. They would mint a new n8n key, watch
 * it fail identically, and the condition would clear on its own an hour later.
 *
 * Three consecutive verdicts across separate refreshes is a key that is
 * genuinely gone. Failing open in the meantime grants nothing: the n8n key is
 * the real authorization, so if it truly is dead the proxied calls fail anyway.
 */
const BAD_KEY_STRIKES = 3;

/**
 * How far apart two consecutive strikes may be before the count resets.
 *
 * Derived from the access-token lifetime rather than fixed, because the refresh
 * cadence follows it and `AUTH_ACCESS_TOKEN_TTL` accepts anything up to a day.
 * A hardcoded window silently disables the guard on any deployment whose tokens
 * outlive it. The bucket slides (see SLIDING_BUCKETS), so this bounds the gap
 * between strikes, not the total time to reach three.
 */
const badKeyStrikeWindow = (accessTokenTtl: number): number =>
  Math.max(4 * 3_600, accessTokenTtl * 2);

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

/**
 * The pair a concurrent winner published for this token, if there is one.
 *
 * Looks once, and on a miss gives the winner one short moment before looking
 * again — see REFRESH_REPLAY_SETTLE_MS for why a first miss is ambiguous and
 * why the wait is a single settle rather than a poll to a deadline.
 */
async function lookUpReplay(store: Store, presented: string): Promise<RotationRecord | null> {
  const first = await store.getRotation(presented);
  if (first) return first;
  await new Promise((resolve) => setTimeout(resolve, REFRESH_REPLAY_SETTLE_MS));
  return await store.getRotation(presented);
}

/**
 * The two gates a consent submission passes before it costs an outbound probe.
 *
 * Order matters and is why they live together: the brute-force gate only
 * *reads*, the volume gate *counts*. Running the volume gate first would charge
 * a caller who is already locked out, and under the fixed windows this store
 * now uses that is wasted work rather than a lockout — but it would still make
 * the two counters disagree about what happened.
 *
 * Returns true when the submission must be refused; the caller decides how to
 * say so, because only it holds the half-rendered form.
 */
async function consentGatesBlock(input: {
  readonly config: Config;
  readonly store: Store;
  readonly ip: string;
  readonly username: string;
  readonly hostname: string;
}): Promise<boolean> {
  const { config, store, ip, username, hostname } = input;
  if (!config.RATE_LIMITER_ENABLED) return false;

  // Keyed on the client IP AND the typed username. IP alone punishes everyone
  // behind one NAT for a single fat-fingered colleague; username alone lets an
  // attacker spread guesses across names. Either bucket tripping is enough.
  const [byIp, byUser] = await Promise.all([
    store.attemptCount(BUCKET.login, ip),
    username ? store.attemptCount(BUCKET.login, `u:${username}`) : Promise.resolve(0),
  ]);
  if (Math.max(byIp, byUser) >= config.RATE_LIMITER_LOGIN_MAX) {
    log().warn({ evt: 'login_rate_limited', host: hostname, ip });
    return true;
  }

  // The lockout above counts only credential VERDICTS, deliberately: an
  // unreachable instance must never lock out the people who depend on it. The
  // cost of that is every other outcome going uncounted, and each one still buys
  // the caller an outbound probe from this gateway. This second bucket bounds
  // request volume without touching the lockout semantics, and it counts every
  // submission — including the ones that succeed.
  //
  // The ceiling is a generous multiple of the lockout, so it is reached only by
  // something automated; a human fumbling a paste cannot trip it.
  const submissions = await store.countAttempt(BUCKET.submit, ip, config.RATE_LIMITER_LOGIN_WINDOW);
  if (submissions > config.RATE_LIMITER_LOGIN_MAX * SUBMIT_BUDGET_FACTOR) {
    log().warn({ evt: 'authorize_flooded', host: hostname, ip, submissions });
    return true;
  }

  return false;
}

export function createOAuthRoutes(deps: OAuthDeps): Hono<AppEnv> {
  const { config, store } = deps;
  const app = new Hono<AppEnv>();
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
    // Bounded before the body is even read. Registration is unauthenticated —
    // that is the MCP default and what lets an unknown client connect — so the
    // only thing standing between one caller and an arbitrary number of
    // AUTH_CLIENT_TTL-lived records is this counter.
    //
    // Counted on every attempt rather than only on success, deliberately: a
    // caller looping malformed bodies costs the same JSON parse and store round
    // trip as one looping valid ones, and "it was rejected" is not a reason to
    // let it be free.
    if (config.RATE_LIMITER_ENABLED) {
      const ip = clientIp(c, config.RATE_LIMITER_TRUSTED_PROXY_HOPS);
      const used = await store.countAttempt(
        BUCKET.register,
        ip,
        config.RATE_LIMITER_REGISTER_WINDOW,
      );
      if (used > config.RATE_LIMITER_REGISTER_MAX) {
        log().warn({ evt: 'register_rate_limited', ip, attempts: used });
        c.header('Retry-After', String(config.RATE_LIMITER_REGISTER_WINDOW));
        return c.json(
          { error: 'invalid_request', error_description: 'too many registrations' },
          429,
        );
      }
    }

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

  /**
   * Name the callback origin in `form-action` for this response.
   *
   * Every page that renders the consent form must do this. The form posts to
   * this server, but the answer is a 303 to the AI client — and browsers apply
   * `form-action` to that redirect as well, so an unlisted origin means the
   * redirect is dropped and the user watches a button do nothing.
   */
  const allowConsentRedirect = (c: Context, redirectUri: string) => {
    // An unparseable URI never reaches here — it is validated first — and if it
    // somehow did, `null` leaves the tighter policy in place, which is the
    // right failure.
    const origin = consentRedirectTarget(redirectUri);
    if (origin) c.set('consentRedirectOrigin', origin);
  };

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

  /**
   * Resolve the client named on `GET /authorize`, with the CIMD fetch bounded.
   *
   * `findClient` tries the store and then, for an https client id, fetches the
   * Client ID Metadata Document that id points at. That second half is the only
   * place an **unauthenticated** request makes this gateway resolve and connect
   * to a host the caller chose, so it is the half that needs a budget.
   *
   * The store lookup is done here rather than left to `findClient` for one
   * reason: it is what lets the budget apply to *uncached* resolutions only. A
   * deployment where every client uses CIMD — which is where MCP is heading —
   * would otherwise spend the budget on its own legitimate traffic and start
   * turning users away. An attacker naming a fresh URL every time is always a
   * cache miss and always pays.
   *
   * Returns the literal `'rate_limited'` rather than null so the caller can tell
   * "no such client" from "ask again later"; answering the first for the second
   * would send a user to check a client id that was never the problem.
   */
  const resolveAuthorizeClient = async (
    c: Context,
    clientId: string,
  ): Promise<OAuthClient | null | 'rate_limited'> => {
    const stored = await store.getClient(clientId);
    if (stored) return stored;
    if (!looksLikeCimd(clientId)) return null;

    if (config.RATE_LIMITER_ENABLED) {
      const ip = clientIp(c, config.RATE_LIMITER_TRUSTED_PROXY_HOPS);
      const used = await store.countAttempt(BUCKET.cimd, ip, config.RATE_LIMITER_CIMD_WINDOW);
      if (used > config.RATE_LIMITER_CIMD_MAX) {
        log().warn({ evt: 'cimd_rate_limited', ip, attempts: used });
        return 'rate_limited';
      }
    }

    return await resolveCimdClient(config, store, clientId);
  };

  app.get('/authorize', async (c) => {
    const locale = locales(c);
    const q = c.req.query();
    const fail = (code: string, status: 400 | 429 = 400) =>
      c.html(errorPage(locale, config.MCP_DISPLAY_NAME, errorText(locale, code)), status);

    const clientId = q['client_id'] ?? '';
    const resolved = clientId ? await resolveAuthorizeClient(c, clientId) : null;
    if (resolved === 'rate_limited') {
      c.header('Retry-After', String(config.RATE_LIMITER_CIMD_WINDOW));
      return fail('rate_limited_request', 429);
    }
    const client = resolved;
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

    allowConsentRedirect(c, redirectUri);
    return c.html(
      consentPage({
        locale,
        displayName: config.MCP_DISPLAY_NAME,
        hostname: tenant.hostname,
        clientName: client.clientName,
        redirectTarget: consentRedirectTarget(redirectUri),
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
      // Two very different things arrive here and used to get one answer.
      //
      // A request that was already carried through to a grant is the common
      // one: the form is submitted twice — a second click while the probe
      // runs, a back button, a reload — and the second submit finds the
      // record spent. Telling that user "sign-in took too long, reconnect in
      // your AI client" is false. They are connected. Observed in production
      // as a 303 followed eleven seconds later by an expiry page, which sent
      // everyone hunting for a failure that had not happened.
      //
      // A request that genuinely expired, or was never issued, is the other.
      const alreadyDone = await store.wasConsentCompleted(requestId);
      log().warn({
        evt: alreadyDone ? 'consent_resubmitted' : 'consent_expired',
        had_request_id: requestId !== '',
        ip: clientIp(c, config.RATE_LIMITER_TRUSTED_PROXY_HOPS),
      });
      return c.html(
        errorPage(
          locale,
          config.MCP_DISPLAY_NAME,
          errorText(locale, alreadyDone ? 'consent_already_done' : 'session_expired'),
        ),
        alreadyDone ? 200 : 400,
      );
    }

    const client = await findClient(config, store, pending.clientId);
    if (!client || !matchesRedirectUri(client.redirectUris, pending.redirectUri)) {
      // This exit sits *outside* the try/finally below, so it has to restore the
      // claim itself — `pending` is right here, so the old comment claiming
      // there was nothing to put back was simply wrong.
      //
      // It matters because the common way to arrive here is not a client that
      // changed its registration. For a CIMD client `findClient` may refetch the
      // document, and any timeout, non-2xx, redirect, non-public DNS answer or
      // oversized body lands on this branch — throwing away a request the user
      // had just typed their n8n API key into, over a transient network fault.
      // Restoring it costs nothing and lets them press the button again.
      await store.restorePendingAuth(requestId, pending);
      log().warn({
        evt: 'consent_unknown_client',
        host: pending.hostname,
        client_id: short(pending.clientId, 40),
        reason: client ? 'redirect_uri_mismatch' : 'unresolved',
      });
      return c.html(
        errorPage(locale, config.MCP_DISPLAY_NAME, errorText(locale, 'unknown_client')),
        400,
      );
    }

    // The claim is held from here on. Every ordinary exit below puts it back
    // through `retry`, but a thrown error has no such exit — and before the
    // claim existed, a throw simply left the record in place for the user to
    // try again. `finally` restores that property.
    //
    // `spent` flips when a grant exists, not at the redirect: if something
    // throws after createGrant, putting the claim back would let the user
    // consent a second time and mint a second grant holding a second sealed
    // copy of one API key — the exact defect the claim was introduced to
    // prevent. An orphaned grant is the safer of the two failures.
    let spent = false;
    try {
      const username = (form['username'] ?? '').trim().slice(0, 200);
      const apiKey = (form['api_key'] ?? '').trim();

      /**
       * Re-render the same form, keeping the request alive for another attempt.
       *
       * It does not put the claim back itself. The `finally` above owns that,
       * which is what makes the guarantee hold for exits this function does
       * not cover — a thrown error most of all. Two places restoring the same
       * record would work, and would also mean the invariant is stated twice
       * and can drift.
       */
      const retry = async (code: string, status: 400 | 429 = 400) => {
        // Also on a retry: the next submit from this re-rendered form is the
        // one that may succeed, and it needs the same permission to land.
        allowConsentRedirect(c, pending.redirectUri);
        return c.html(
          consentPage({
            locale,
            displayName: config.MCP_DISPLAY_NAME,
            hostname: pending.hostname,
            clientName: client.clientName,
            redirectTarget: consentRedirectTarget(pending.redirectUri),
            requestId,
            username,
            error: errorText(locale, code),
          }),
          status,
        );
      };

      // ── Rate gates ───────────────────────────────────────────────────────────
      const ip = clientIp(c, config.RATE_LIMITER_TRUSTED_PROXY_HOPS);
      if (await consentGatesBlock({ config, store, ip, username, hostname: pending.hostname })) {
        return await retry('rate_limited_login', 429);
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

      spent = true;

      const code = randomToken();
      await store.putCode(code, {
        grantId: grant.grantId,
        clientId: client.clientId,
        redirectUri: pending.redirectUri,
        codeChallenge: pending.codeChallenge,
        resource: pending.resource,
      });

      // Only now, with a code actually issued, is this consent complete — and
      // only now may a resubmit be told "you are already connected". Marking
      // it a step earlier, next to `spent`, would say that to someone whose
      // code was never issued and who therefore still has to start over.
      await store.markConsentCompleted(requestId);

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
    } finally {
      if (!spent) await store.restorePendingAuth(requestId, pending);
    }
  });

  // ───────────────────────────────────────────────────────────────────────────
  // Token
  // ───────────────────────────────────────────────────────────────────────────

  app.post('/token', async (c) => {
    const form = await formBody(c);
    const ip = clientIp(c, config.RATE_LIMITER_TRUSTED_PROXY_HOPS);

    if (config.RATE_LIMITER_ENABLED) {
      // Keyed on the client, not on the address. /token is reached
      // server-to-server by hosted AI clients — claude.ai calls it from
      // Anthropic's broker egress, never from the user's browser — so an
      // address-keyed budget is one budget shared by every user behind that
      // broker. At 60/60s the first busy user takes down everyone else's
      // ability to refresh *and* to reconnect.
      //
      // Keyed on the PAIR, never on the assertion alone. `client_id` is not a
      // secret — for a CIMD client it is a public https URL shared by every user
      // of that AI client — so a bucket keyed on it alone is one a stranger can
      // spend: 61 requests a minute carrying someone else's client_id would 429
      // every genuine refresh AND every reconnect for all users of that client.
      // Mixing the address back in keeps the per-client fairness and makes the
      // bucket unreachable by anyone but its own caller.
      const asserted = form['client_id'] ?? '';
      const [byClient, byAddress] = await Promise.all([
        store.countAttempt(
          BUCKET.token,
          asserted ? `c:${asserted}|ip:${ip}` : `ip:${ip}`,
          config.RATE_LIMITER_TOKEN_WINDOW,
        ),
        store.countAttempt(BUCKET.tokenIp, ip, config.RATE_LIMITER_TOKEN_WINDOW),
      ]);
      if (
        byClient > config.RATE_LIMITER_TOKEN_MAX ||
        byAddress > config.RATE_LIMITER_TOKEN_MAX * TOKEN_IP_BUDGET_FACTOR
      ) {
        log().warn({ evt: 'token_rate_limited', ip, by_client: byClient, by_address: byAddress });
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
    const presented = form['refresh_token'] ?? '';
    const resolved = await store.takeToken(presented);
    if (resolved?.token.kind !== 'refresh') {
      // Not necessarily invalid. `takeToken` is atomic, so when a client fires
      // two refreshes at once — or retries one whose response it never received
      // — exactly one wins and this is the loser holding a token that existed a
      // moment ago. Answering `invalid_grant` tells it, per RFC 6749 §5.2, to
      // discard a grant that is perfectly alive, and the user is disconnected
      // by a race rather than by a fault.
      //
      // Within the grace window we re-serve the pair the winner already got.
      // Nothing new is minted; see Store.putRotation.
      const replayed =
        config.AUTH_REFRESH_ROTATION_GRACE > 0 ? await lookUpReplay(store, presented) : null;
      // Checked against the grant, not just the window: the pair in the record
      // dies the moment the grant is revoked, and answering 200 with dead
      // tokens would tell the client everything is fine.
      if (replayed && (await store.getGrant(replayed.grantId))) {
        log().info({ evt: 'refresh_replayed' });
        return c.json(replayed.response);
      }
      // This branch used to return without a word, so the one failure a client
      // reports as "the connector stopped working" left no trace at all.
      log().warn({
        evt: 'refresh_rejected',
        reason: resolved ? 'not_a_refresh_token' : 'unknown_token',
        presented: presented !== '',
      });
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

    // ── Mint, and remember, BEFORE any network call ──────────────────────────
    // The race this covers is two refreshes arriving milliseconds apart, and the
    // probe below blocks for up to five seconds against someone else's server.
    // Writing the grace record after it left exactly that race unhandled: the
    // loser looked for the record microseconds after losing, found nothing, and
    // got `invalid_grant` — the outcome the window exists to prevent.
    //
    // Minting early is safe. If the probe below revokes the grant, this pair
    // dies with it: both tokens are pointers into `grant:<id>`, and the replay
    // path above re-checks the grant before serving. Nothing usable escapes.
    const issued = await issueTokens(grant);
    if (config.AUTH_REFRESH_ROTATION_GRACE > 0) {
      await store.putRotation(
        presented,
        { grantId: grant.grantId, response: issued },
        config.AUTH_REFRESH_ROTATION_GRACE,
      );
    }

    const probe = await probeApiKey(`https://${grant.hostname}`, apiKey, {
      timeoutMs: Math.min(config.N8N_PROBE_TIMEOUT_MS, 5_000),
    });
    //
    // `insufficient_permissions` is deliberately no longer in this set. It says
    // the key is real and the role changed — an operator's doing, which logging
    // the user out does not undo. It is logged below like any other fail-open.
    if (!probe.ok && probe.code === 'bad_key') {
      const strikes = await store.countAttempt(
        BUCKET.badKey,
        grant.grantId,
        badKeyStrikeWindow(config.AUTH_ACCESS_TOKEN_TTL),
      );
      if (strikes >= BAD_KEY_STRIKES) {
        await store.revokeGrant(grant.grantId);
        await store.clearAttempts(BUCKET.badKey, grant.grantId);
        log().warn({
          evt: 'grant_revoked',
          reason: probe.code,
          strikes,
          host: grant.hostname,
          username: grant.username,
        });
        return c.json(
          { error: 'invalid_grant', error_description: 'the n8n API key is no longer valid' },
          400,
        );
      }
      log().warn({
        evt: 'bad_key_strike',
        strikes,
        needed: BAD_KEY_STRIKES,
        host: grant.hostname,
        username: grant.username,
      });
    }

    // Strikes only mean something consecutively, so any healthy probe wipes them.
    if (probe.ok) await store.clearAttempts(BUCKET.badKey, grant.grantId);

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
    return c.json(issued);
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
 * The origin a completed consent will hand the authorization code to.
 *
 * One function with two consumers — the CSP `form-action` source, and the label
 * the user reads on the consent screen — and that is the whole point. Those two
 * must never disagree: a screen that says `claude.ai` while the policy permits
 * somewhere else is worse than showing nothing at all, because it converts a
 * user's correct instinct to check into false reassurance.
 *
 * `.origin` is the literal string "null" for every non-special scheme, and this
 * server accepts private-use schemes on purpose (`cursor://…`,
 * `com.example.app:/cb`, RFC 8252 §7.1). Emitting that "null" would produce a
 * CSP host-source that can never match — wordlessly identical to the
 * `form-action 'self'` that broke the flow in the first place — and would read
 * as gibberish on the page. For those the scheme itself is both the correct CSP
 * scheme-source and the identifying thing to show; dots are legal in one, so a
 * reverse-DNS scheme survives intact.
 *
 * Returns null only for a URI that does not parse, which validation has already
 * excluded by the time either consumer calls this.
 */
export function consentRedirectTarget(redirectUri: string): string | null {
  let url: URL;
  try {
    url = new URL(redirectUri);
  } catch {
    return null;
  }
  return url.origin === 'null' ? url.protocol : url.origin;
}

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

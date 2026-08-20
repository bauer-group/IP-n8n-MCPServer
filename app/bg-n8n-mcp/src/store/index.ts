/**
 * Typed storage for OAuth state.
 *
 * The shape worth understanding is the **grant indirection**. The draft this
 * replaces copied the sealed n8n API key into every access and refresh token it
 * issued. That works, and it has two consequences that only show up later:
 * the credential ends up duplicated across N records, and there is no way to
 * revoke one user without rotating the master key for everybody.
 *
 * Here, tokens hold a `grantId` and nothing else of value:
 *
 *     code  ─┐
 *     access ├─→ grant:<id> ──→ { hostname, sealedKey, username, n8nUserId }
 *     refresh┘
 *
 * Deleting `grant:<id>` invalidates every token that points at it, at once,
 * on the next request. That single indirection is what turns "revoke this
 * user" from a break-glass operation into a one-line call — used by the RFC
 * 7009 revocation endpoint and by the refresh path when n8n rejects a key.
 *
 * Every key is stored under an HMAC of the secret, never the secret itself, so
 * a Redis dump does not hand an attacker a set of working bearer tokens.
 */

import type { Config } from '../config.js';
import { deriveKeyring, hashKey, type Keyring, randomToken } from '../lib/crypto.js';
import { log } from '../logger.js';
import type { StoreBackend } from './backend.js';
import { MemoryBackend } from './memory.js';
import { RedisBackend } from './redis.js';

// ─── Record shapes ───────────────────────────────────────────────────────────

/** How a client established its identity. See oauth/clients.ts. */
export type ClientSource = 'dcr' | 'cimd';

export interface OAuthClient {
  readonly clientId: string;
  readonly redirectUris: readonly string[];
  readonly clientName: string | null;
  readonly source: ClientSource;
  /**
   * RFC 7591 `application_type`, required by MCP from revision 2026-07-28.
   * `native` clients (Claude Code and other RFC 8252 clients) are the ones
   * allowed a loopback redirect URI with an ephemeral port.
   */
  readonly applicationType: 'web' | 'native';
  readonly createdAt: number;
}

/**
 * The authorization a user granted: a specific n8n instance, reachable with a
 * specific key, for a specific client. This is the only record that holds the
 * credential.
 */
export interface Grant {
  readonly grantId: string;
  readonly hostname: string;
  /** AES-256-GCM sealed n8n API key. Never logged, never sent to a client. */
  readonly sealedKey: string;
  readonly clientId: string;
  /** RFC 8707 audience: the canonical MCP URL this grant is valid for. */
  readonly resource: string;
  /** Self-asserted at login. An audit label, not a credential. */
  readonly username: string;
  /** n8n user id read from the API key's JWT `sub`, when it is one. */
  readonly n8nUserId: string | null;
  readonly createdAt: number;
}

export interface AuthCode {
  readonly grantId: string;
  readonly clientId: string;
  readonly redirectUri: string;
  /** PKCE S256 challenge. The verifier is checked against this at /token. */
  readonly codeChallenge: string;
  readonly resource: string;
}

/**
 * A `/authorize` request that has been validated but not yet consented to.
 *
 * This is held server-side and referenced from the consent form by an opaque
 * id, rather than being round-tripped through a hidden field. The difference
 * matters: with the context in the form, a user (or anything that can rewrite
 * the page) could change `redirectUri` or `resource` between the GET that
 * validated them and the POST that acts on them, and the POST handler would
 * have no original to compare against.
 */
export interface PendingAuth {
  readonly clientId: string;
  readonly redirectUri: string;
  readonly state: string | null;
  readonly codeChallenge: string;
  readonly hostname: string;
  readonly resource: string;
  readonly createdAt: number;
}

export interface TokenRecord {
  readonly grantId: string;
  readonly kind: 'access' | 'refresh';
  readonly clientId: string;
  readonly resource: string;
  readonly issuedAt: number;
}

/** A token resolved together with the grant it points at. */
export interface ResolvedToken {
  readonly token: TokenRecord;
  readonly grant: Grant;
}

// ─── Key namespaces ──────────────────────────────────────────────────────────
//
// Prefixes are short because they are stored millions of times over a
// deployment's life, and distinct so `redis-cli --scan --pattern 'grant:*'`
// answers an operator's question directly.

const NS = {
  client: 'client:',
  grant: 'grant:',
  code: 'code:',
  token: 'tok:',
  pending: 'pend:',
  done: 'done:',
  rate: 'rl:',
} as const;

/**
 * How long a consent screen may sit open before its request expires.
 *
 * Thirty minutes. Ten was the original guess at "long enough to go and create
 * an API key in another tab", and it was wrong in the direction that costs a
 * user the whole flow: the real journey is log in to n8n, find Settings → n8n
 * API, create a key, name it, copy it, come back — with an interruption
 * somewhere in the middle. Expiring mid-journey drops them on an error page
 * whose only advice is to start over in the AI client.
 *
 * The record holds no credential — clientId, redirectUri, state, the PKCE
 * challenge (public by construction), hostname and resource. The single-use
 * secret in this flow is the authorization code, and that still lives
 * AUTH_CODE_TTL seconds (120 by default). Lengthening this widens the window
 * for submitting an abandoned tab, not for replaying anything.
 */
const PENDING_AUTH_TTL_SECONDS = 1_800;

// ─── Store ───────────────────────────────────────────────────────────────────

export class Store {
  readonly #backend: StoreBackend;
  readonly #keyring: Keyring;
  readonly #config: Config;

  constructor(backend: StoreBackend, config: Config) {
    this.#backend = backend;
    this.#keyring = deriveKeyring(config.storageKey);
    this.#config = config;
  }

  /** Build the configured backend and wrap it. Called once, from main.ts. */
  static async open(config: Config): Promise<Store> {
    if (config.storeKind === 'memory') {
      log().warn({
        evt: 'store_memory',
        msg: 'in-memory store selected — every grant is lost on restart',
      });
      return new Store(new MemoryBackend(), config);
    }
    const backend = await RedisBackend.connect(config.AUTH_REDIS_URL);
    log().info({
      evt: 'store_redis',
      // Strip any inline password before this reaches a log collector.
      url: config.AUTH_REDIS_URL.replace(/\/\/[^@]*@/, '//***@'),
    });
    return new Store(backend, config);
  }

  get keyring(): Keyring {
    return this.#keyring;
  }

  async healthy(): Promise<boolean> {
    return await this.#backend.ping();
  }

  async close(): Promise<void> {
    await this.#backend.close();
  }

  // ── Serialisation helpers ──────────────────────────────────────────────────

  async #read<T>(key: string): Promise<T | null> {
    const raw = await this.#backend.get(key);
    return raw ? (JSON.parse(raw) as T) : null;
  }

  async #consume<T>(key: string): Promise<T | null> {
    const raw = await this.#backend.take(key);
    return raw ? (JSON.parse(raw) as T) : null;
  }

  // ── Clients ────────────────────────────────────────────────────────────────

  /**
   * Persist a client record.
   *
   * The lifetime is decided here, from what the record *is*, rather than passed
   * in by the caller — because the two kinds are not one thing with two labels
   * and they fail in opposite directions:
   *
   *  - a `dcr` record **is** the registration. Losing it means the client has
   *    to register again, so it lives AUTH_CLIENT_TTL: long enough to cover a
   *    returning user whose grant expired months ago.
   *  - a `cimd` record is a **cache** of a document the client publishes and
   *    controls. Losing it costs one refetch. Keeping it is the costly
   *    direction: `getClient` wins on every lookup and nothing revalidates, so
   *    a client that rotates its redirect URIs stays rejected for exactly this
   *    long. Hence AUTH_CIMD_CACHE_TTL, in hours rather than months.
   *
   * Deciding it from `client.source` rather than at the two call sites is what
   * keeps the rule un-drifted: a third caller cannot pick the wrong one.
   */
  async putClient(client: OAuthClient): Promise<void> {
    const ttlSeconds =
      client.source === 'cimd' ? this.#config.AUTH_CIMD_CACHE_TTL : this.#config.AUTH_CLIENT_TTL;
    await this.#backend.set(NS.client + client.clientId, JSON.stringify(client), ttlSeconds);
  }

  async getClient(clientId: string): Promise<OAuthClient | null> {
    if (!clientId) return null;
    return await this.#read<OAuthClient>(NS.client + clientId);
  }

  // ── Grants ─────────────────────────────────────────────────────────────────

  /**
   * Persist a grant and return its id.
   *
   * The grant's TTL matches the refresh-token lifetime, and `touchGrant`
   * extends it on every successful refresh. So an actively used connector
   * lives indefinitely, while one that is abandoned expires on its own — which
   * means a sealed n8n API key does not sit in Redis forever after someone
   * stops using Claude.
   */
  async createGrant(input: Omit<Grant, 'grantId' | 'createdAt'>): Promise<Grant> {
    const grant: Grant = { ...input, grantId: randomToken(), createdAt: Date.now() };
    await this.#backend.set(
      NS.grant + grant.grantId,
      JSON.stringify(grant),
      this.#config.AUTH_REFRESH_TOKEN_TTL,
    );
    return grant;
  }

  async getGrant(grantId: string): Promise<Grant | null> {
    if (!grantId) return null;
    return await this.#read<Grant>(NS.grant + grantId);
  }

  /** Extend a grant's lifetime. Called on every successful refresh. */
  async touchGrant(grant: Grant): Promise<void> {
    await this.#backend.set(
      NS.grant + grant.grantId,
      JSON.stringify(grant),
      this.#config.AUTH_REFRESH_TOKEN_TTL,
    );
  }

  /**
   * Revoke a grant. Every access and refresh token pointing at it stops working
   * on its next use, because token lookup dereferences the grant and finds
   * nothing.
   */
  async revokeGrant(grantId: string): Promise<void> {
    await this.#backend.del(NS.grant + grantId);
  }

  // ── Pending authorization requests ─────────────────────────────────────────

  /** Park a validated /authorize request and return its form handle. */
  async createPendingAuth(request: PendingAuth): Promise<string> {
    const requestId = randomToken();
    await this.#backend.set(
      NS.pending + hashKey(this.#keyring, requestId),
      JSON.stringify(request),
      PENDING_AUTH_TTL_SECONDS,
    );
    return requestId;
  }

  /**
   * Read a pending request WITHOUT consuming it.
   *
   * Non-destructive on purpose: a mistyped API key must re-render the same form
   * rather than dropping the user into "session expired". The record is
   * consumed only once a code has actually been issued.
   */
  async getPendingAuth(requestId: string): Promise<PendingAuth | null> {
    if (!requestId) return null;
    return await this.#read<PendingAuth>(NS.pending + hashKey(this.#keyring, requestId));
  }

  async consumePendingAuth(requestId: string): Promise<void> {
    if (!requestId) return;
    await this.#backend.del(NS.pending + hashKey(this.#keyring, requestId));
  }

  /**
   * Claim a pending request: read and delete in one atomic step.
   *
   * The consent POST claims before it does any work, because the work takes
   * seconds — a key probe against a remote instance — and the form offers no
   * way to stop a user pressing submit twice while it runs. Two claims of one
   * record cannot both succeed, so two grants holding two sealed copies of the
   * same API key can no longer be minted from one consent.
   *
   * A failed attempt puts the record back with `restorePendingAuth`, which is
   * what keeps a mistyped key on the same form rather than dropping the user
   * into "session expired".
   */
  async takePendingAuth(requestId: string): Promise<PendingAuth | null> {
    if (!requestId) return null;
    return await this.#consume<PendingAuth>(NS.pending + hashKey(this.#keyring, requestId));
  }

  /**
   * Remember that a consent request was carried through to a grant.
   *
   * Without this, a second submit of a form whose request has already been
   * spent is indistinguishable from one that expired, and both were reported
   * as "sign-in took too long". That message is wrong in the first case and
   * actively misleading: the user is told to reconnect when they are, in
   * fact, already connected. Observed in production as a 303 followed eleven
   * seconds later by an expiry page.
   *
   * Keyed by the same HMAC as the request itself, so the raw handle is never
   * written down, and holding nothing but a marker.
   */
  async markConsentCompleted(requestId: string): Promise<void> {
    if (!requestId) return;
    await this.#backend.set(
      NS.done + hashKey(this.#keyring, requestId),
      '1',
      PENDING_AUTH_TTL_SECONDS,
    );
  }

  /** True when this request was already carried through to a grant. */
  async wasConsentCompleted(requestId: string): Promise<boolean> {
    if (!requestId) return false;
    return (await this.#backend.get(NS.done + hashKey(this.#keyring, requestId))) !== null;
  }

  /**
   * Put a claimed record back so this attempt was not the user's last.
   *
   * The TTL is the remainder of the ORIGINAL deadline, never a fresh one:
   * restoring at full TTL would let a caller hold a pending request open
   * indefinitely by retrying. Returns false when nothing was restored because
   * that deadline has already passed.
   */
  async restorePendingAuth(requestId: string, request: PendingAuth): Promise<boolean> {
    if (!requestId) return false;
    const elapsed = Math.floor((Date.now() - request.createdAt) / 1000);
    const remaining = PENDING_AUTH_TTL_SECONDS - elapsed;
    if (remaining <= 0) return false;
    await this.#backend.set(
      NS.pending + hashKey(this.#keyring, requestId),
      JSON.stringify(request),
      remaining,
    );
    return true;
  }

  // ── Authorization codes ────────────────────────────────────────────────────

  async putCode(code: string, record: AuthCode): Promise<void> {
    await this.#backend.set(
      NS.code + hashKey(this.#keyring, code),
      JSON.stringify(record),
      this.#config.AUTH_CODE_TTL,
    );
  }

  /** Redeem a code. Atomic and single-use — a replay finds nothing. */
  async takeCode(code: string): Promise<AuthCode | null> {
    if (!code) return null;
    return await this.#consume<AuthCode>(NS.code + hashKey(this.#keyring, code));
  }

  // ── Tokens ─────────────────────────────────────────────────────────────────

  async putToken(token: string, record: TokenRecord, ttlSeconds: number): Promise<void> {
    await this.#backend.set(
      NS.token + hashKey(this.#keyring, token),
      JSON.stringify(record),
      ttlSeconds,
    );
  }

  /**
   * Resolve a bearer token to its record and grant.
   *
   * Returns null when either half is missing — an expired token, or a live
   * token whose grant was revoked. Callers do not distinguish, and should not:
   * both mean "re-authorize".
   */
  async resolveToken(token: string): Promise<ResolvedToken | null> {
    if (!token) return null;
    const record = await this.#read<TokenRecord>(NS.token + hashKey(this.#keyring, token));
    if (!record) return null;
    const grant = await this.getGrant(record.grantId);
    if (!grant) return null;
    return { token: record, grant };
  }

  /**
   * Consume a refresh token, returning it with its grant.
   *
   * Single-use by construction: OAuth 2.1 requires refresh-token rotation for
   * public clients, and taking the old one here is what makes the rotation
   * real rather than nominal.
   */
  async takeToken(token: string): Promise<ResolvedToken | null> {
    if (!token) return null;
    const record = await this.#consume<TokenRecord>(NS.token + hashKey(this.#keyring, token));
    if (!record) return null;
    const grant = await this.getGrant(record.grantId);
    if (!grant) return null;
    return { token: record, grant };
  }

  async deleteToken(token: string): Promise<void> {
    if (!token) return;
    await this.#backend.del(NS.token + hashKey(this.#keyring, token));
  }

  // ── Rate limiting ──────────────────────────────────────────────────────────

  /**
   * Count one attempt against `bucket`/`identity` and return the running total.
   *
   * The identity is hashed before it becomes a key: these buckets are keyed by
   * client IP and by username, and neither belongs in a Redis keyspace an
   * operator might screenshot into a ticket.
   */
  async countAttempt(bucket: string, identity: string, windowSeconds: number): Promise<number> {
    return await this.#backend.incr(
      `${NS.rate}${bucket}:${hashKey(this.#keyring, identity)}`,
      windowSeconds,
    );
  }

  async attemptCount(bucket: string, identity: string): Promise<number> {
    const raw = await this.#backend.get(`${NS.rate}${bucket}:${hashKey(this.#keyring, identity)}`);
    const value = Number(raw ?? 0);
    return Number.isFinite(value) ? value : 0;
  }

  async clearAttempts(bucket: string, identity: string): Promise<void> {
    await this.#backend.del(`${NS.rate}${bucket}:${hashKey(this.#keyring, identity)}`);
  }
}

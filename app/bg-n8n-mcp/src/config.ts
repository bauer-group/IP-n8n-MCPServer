/**
 * Configuration — the single place the environment is read.
 *
 * Everything is parsed and validated once, at boot, with Zod. A misconfigured
 * deployment fails to start with a precise message rather than serving traffic
 * with a subtly wrong security posture: an unset tenant allowlist, a 20-byte
 * encryption key, an `http://` public base URL. All three used to be
 * "works, until it matters".
 *
 * Naming follows the sibling BAUER GROUP MCP servers (IP-Shlink-MCPServer,
 * IP-ZAMMAD-MCPServer) so an operator who has deployed one recognises the
 * other: ENVIRONMENT, PUBLIC_BASE_URL, MCP_*, LOG_*, AUTH_*, RATE_LIMITER_*.
 */

import { z } from 'zod';

// ─── Primitives ──────────────────────────────────────────────────────────────

/** A positive integer given as a string in the environment. */
const intFromEnv = (min: number, max: number) =>
  z.coerce.number().int().min(min).max(max).describe(`integer between ${min} and ${max}`);

/** `"true"` / `"1"` / `"yes"` (case-insensitive) are true; everything else false. */
const boolFromEnv = z
  .string()
  .transform((v) => ['true', '1', 'yes', 'on'].includes(v.trim().toLowerCase()));

/**
 * Comma-separated list, whitespace-tolerant, empty entries dropped.
 *
 * Note for anyone adding a field: Zod 4 changed `.default()` to short-circuit —
 * the default is returned as the OUTPUT without being parsed. So the default
 * for a csv field must be `[]`, not `''`. `.default('')` type-checks under a
 * loose tsconfig and then hands `''` to code expecting an array.
 */
const csv = z.string().transform((v) =>
  v
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean),
);

// ─── Schema ──────────────────────────────────────────────────────────────────

const EnvSchema = z.object({
  // ── Stack identity ────────────────────────────────────────────────────────
  ENVIRONMENT: z.enum(['production', 'staging', 'development']).default('production'),

  /**
   * The public origin of THIS gateway. It is baked into every OAuth document
   * (issuer, authorization_endpoint, resource identifiers), so it must match
   * exactly what the client typed — including scheme and the absence of a
   * trailing slash. A mismatch here surfaces to the user as an opaque
   * "connection failed" in Claude, hours after the deploy.
   */
  PUBLIC_BASE_URL: z.url(),

  MCP_HOST: z.string().default('::'),
  MCP_PORT: intFromEnv(1, 65535).default(8080),

  MCP_DISPLAY_NAME: z.string().min(1).default('BAUER GROUP n8n'),
  MCP_ICON_URL: z.string().default(''),
  MCP_WEBSITE_URL: z.string().default('https://go.bauer-group.com/mcp-server'),

  LOG_FORMAT: z.enum(['json', 'console']).default('json'),
  LOG_LEVEL: z.enum(['trace', 'debug', 'info', 'warn', 'error', 'fatal']).default('info'),

  // ── Upstream: the n8n-mcp container ───────────────────────────────────────
  /**
   * Internal address of n8n-mcp running with MCP_MODE=http and
   * ENABLE_MULTI_TENANT=true. It never faces the internet; this gateway is its
   * only client.
   */
  N8N_MCP_URL: z.url().default('http://n8n-mcp:3000'),

  /**
   * n8n-mcp's own AUTH_TOKEN. Upstream requires >= 32 characters and rejects
   * its shipped placeholder, so we do too — one boot-time error beats a 401
   * that looks like a user problem.
   */
  N8N_MCP_AUTH_TOKEN: z
    .string()
    .min(32, 'must be at least 32 characters (openssl rand -base64 32)')
    .refine((v) => !v.startsWith('CHANGE_ME'), 'must not contain the CHANGE_ME placeholder')
    .refine(
      (v) => v !== 'REPLACE_THIS_AUTH_TOKEN_32_CHARS_MIN_abcdefgh',
      "must not be n8n-mcp's shipped default token",
    ),

  /** Upstream request timeout. Must exceed n8n-mcp's 15s SSE keep-alive. */
  N8N_MCP_TIMEOUT_MS: intFromEnv(5_000, 600_000).default(120_000),

  // ── Which n8n instances may be addressed ──────────────────────────────────
  /**
   * Exact hostnames and/or `*.suffix` wildcards, comma-separated. This is the
   * form most deployments should use — a list is auditable at a glance and has
   * no way to accidentally mean "everything".
   */
  N8N_ALLOWED_HOSTS: csv.default([]),

  /**
   * Regex escape hatch for host sets a list cannot express. Anchors are added
   * in code (see compileHostMatcher), so a pattern that forgets `^`/`$` still
   * cannot become a substring match.
   */
  N8N_ALLOWED_HOST_PATTERN: z.string().default(''),

  /**
   * Allow n8n instances that resolve to private, loopback, link-local or CGNAT
   * addresses. Off by default: with it on, an allowlisted name whose DNS points
   * at 169.254.169.254 turns this gateway into a cloud-metadata reader
   * (the shape of GHSA-4ggg-h7ph-26qr, upstream in n8n-mcp).
   */
  N8N_ALLOW_PRIVATE_ADDRESSES: boolFromEnv.default(false),

  /**
   * Timeout for the key-validation probe against the user's n8n instance.
   *
   * Applies in full only to the interactive login, where a human is waiting on
   * the consent form. The refresh path caps it at 5s (see oauth/routes.ts),
   * because a refresh runs inside an MCP client's own budget and blowing that
   * fails the refresh anyway. Raising this above 5000 therefore changes login
   * alone; lowering it below 5000 tightens both.
   */
  N8N_PROBE_TIMEOUT_MS: intFromEnv(1_000, 60_000).default(8_000),

  // ── OAuth ─────────────────────────────────────────────────────────────────
  /**
   * 32 bytes, base64. Encrypts every stored n8n API key (AES-256-GCM) and is
   * the HKDF root for the store's key-hashing pepper. Rotating it invalidates
   * every grant at once — which is exactly the break-glass revocation lever.
   */
  AUTH_STORAGE_ENCRYPTION_KEY: z.string().min(1),

  /** Empty selects the in-memory store; see storeKind below for the guard. */
  AUTH_REDIS_URL: z.string().default(''),

  AUTH_ACCESS_TOKEN_TTL: intFromEnv(60, 86_400).default(3_600),
  AUTH_REFRESH_TOKEN_TTL: intFromEnv(3_600, 31_536_000).default(2_592_000),
  AUTH_CODE_TTL: intFromEnv(30, 600).default(120),
  /** How long a dynamically registered client record survives without use. */
  AUTH_CLIENT_TTL: intFromEnv(86_400, 31_536_000).default(31_536_000),

  /**
   * Optional allowlist of redirect URI prefixes accepted at dynamic client
   * registration. Empty means any https:// URI may register, which is the
   * MCP-spec default and is what makes "add a custom connector" work for
   * clients we have never heard of. Restrict it if this gateway is only ever
   * meant to serve Claude.
   */
  MCP_ALLOWED_CLIENT_REDIRECT_URIS: csv.default([]),

  // ── Rate limiting ─────────────────────────────────────────────────────────
  RATE_LIMITER_ENABLED: boolFromEnv.default(true),
  /** Failed key submissions per identity before the login form locks out. */
  RATE_LIMITER_LOGIN_MAX: intFromEnv(1, 1_000).default(10),
  RATE_LIMITER_LOGIN_WINDOW: intFromEnv(60, 86_400).default(900),
  /** Token-endpoint attempts per client IP per window. */
  RATE_LIMITER_TOKEN_MAX: intFromEnv(1, 10_000).default(60),
  RATE_LIMITER_TOKEN_WINDOW: intFromEnv(10, 3_600).default(60),
  /** MCP calls per access token per window. 0 disables just this limiter. */
  RATE_LIMITER_MCP_MAX: intFromEnv(0, 100_000).default(600),
  RATE_LIMITER_MCP_WINDOW: intFromEnv(10, 3_600).default(60),
  /**
   * How many proxies sit in front of this container. 1 = a single Traefik.
   * Bump to 2 if you stack Cloudflare (or another edge) in front of Traefik.
   * The client IP is taken this many entries from the RIGHT of
   * X-Forwarded-For; everything further left is client-controlled and is
   * ignored. Getting this wrong is how an attacker spoofs their way out of a
   * rate limit.
   */
  RATE_LIMITER_TRUSTED_PROXY_HOPS: intFromEnv(0, 10).default(1),
});

export type Env = z.infer<typeof EnvSchema>;

// ─── Derived settings ────────────────────────────────────────────────────────

export interface Config extends Env {
  /** PUBLIC_BASE_URL with any trailing slashes removed. */
  readonly baseUrl: string;
  /** AUTH_STORAGE_ENCRYPTION_KEY decoded — exactly 32 bytes. */
  readonly storageKey: Buffer;
  /** Where grants live. Redis in production; memory is development-only. */
  readonly storeKind: 'redis' | 'memory';
  /** Compiled tenant allowlist. */
  readonly isAllowedHost: (hostname: string) => boolean;
  /** True when running with ENVIRONMENT=development. */
  readonly isDevelopment: boolean;
}

/**
 * Build the host matcher from the list form, the regex form, or both.
 *
 * Both are matched against an already-parsed hostname (see tenant.ts), never a
 * raw user string — a regex applied to raw input is bypassable through
 * userinfo (`host@evil.com`), a port, a path, or a unicode homoglyph, and the
 * draft this server replaces got that right only by accident of ordering.
 */
export function compileHostMatcher(
  hosts: readonly string[],
  pattern: string,
): (hostname: string) => boolean {
  const exact = new Set<string>();
  const suffixes: string[] = [];

  for (const entry of hosts) {
    const lower = entry.toLowerCase();
    if (lower.startsWith('*.')) {
      // `*.example.com` matches `a.example.com` but deliberately NOT the
      // apex `example.com`: a wildcard that also grants the parent is how a
      // tenant allowlist ends up including the operator's own instance.
      suffixes.push(lower.slice(1)); // keep the leading dot
    } else {
      exact.add(lower);
    }
  }

  let regex: RegExp | null = null;
  if (pattern.trim()) {
    let src = pattern.trim();
    if (!src.startsWith('^')) src = `^${src}`;
    if (!src.endsWith('$')) src = `${src}$`;
    try {
      regex = new RegExp(src, 'i');
    } catch (error) {
      throw new Error(`N8N_ALLOWED_HOST_PATTERN is not a valid regular expression: ${error}`);
    }
  }

  return (hostname: string): boolean => {
    const h = hostname.toLowerCase();
    if (exact.has(h)) return true;
    for (const suffix of suffixes) {
      if (h.endsWith(suffix) && h.length > suffix.length) return true;
    }
    return regex?.test(h) ?? false;
  };
}

/**
 * Decode and check the storage key. Base64 is what `openssl rand -base64 32`
 * produces, which is what the docs and scripts/generate-env.mjs tell operators
 * to run; anything that does not decode to exactly 32 bytes is rejected rather
 * than stretched, because silently hashing a short key to length would make a
 * weak secret look like a strong one.
 */
function decodeStorageKey(raw: string): Buffer {
  const key = Buffer.from(raw, 'base64');
  if (key.length !== 32) {
    throw new Error(
      `AUTH_STORAGE_ENCRYPTION_KEY must be exactly 32 bytes when base64-decoded ` +
        `(got ${key.length}). Generate one with: openssl rand -base64 32`,
    );
  }
  return key;
}

/**
 * Parse the environment into a validated Config, or throw with every problem
 * listed at once. Reporting all failures together matters: an operator filling
 * in a fresh .env should not have to restart the container six times to find
 * six missing values.
 */
export function loadConfig(source: NodeJS.ProcessEnv = process.env): Config {
  const parsed = EnvSchema.safeParse(source);
  if (!parsed.success) {
    const details = parsed.error.issues
      .map((issue) => `  - ${issue.path.join('.') || '(root)'}: ${issue.message}`)
      .join('\n');
    throw new Error(`Invalid configuration:\n${details}`);
  }

  const env = parsed.data;
  const isDevelopment = env.ENVIRONMENT === 'development';
  const baseUrl = env.PUBLIC_BASE_URL.replace(/\/+$/, '');

  // ── Fail-closed invariants ────────────────────────────────────────────────

  // OAuth over plain HTTP leaks the authorization code and every access token
  // to anything on the path. Allowed only for a local development loop.
  if (!baseUrl.startsWith('https://') && !isDevelopment) {
    throw new Error(
      `PUBLIC_BASE_URL must use https:// outside ENVIRONMENT=development (got ${baseUrl})`,
    );
  }

  // An empty allowlist is not "allow everything" — it is a deployment that
  // forgot to say who it serves. Refusing to start is the only safe reading.
  if (!env.N8N_ALLOWED_HOSTS.length && !env.N8N_ALLOWED_HOST_PATTERN.trim()) {
    throw new Error(
      'Set N8N_ALLOWED_HOSTS (recommended) or N8N_ALLOWED_HOST_PATTERN — ' +
        'without one, no n8n instance can be addressed and every connector path would 404',
    );
  }

  const storeKind: 'redis' | 'memory' = env.AUTH_REDIS_URL.trim() ? 'redis' : 'memory';

  // The in-memory store drops every grant on restart, so a routine container
  // update would silently log out every connected user.
  if (storeKind === 'memory' && !isDevelopment) {
    throw new Error(
      'AUTH_REDIS_URL is required outside ENVIRONMENT=development — ' +
        'the in-memory store loses every grant on restart',
    );
  }

  // Refresh tokens that outlive their grant are the classic way a revoked user
  // keeps working for a month.
  if (env.AUTH_REFRESH_TOKEN_TTL < env.AUTH_ACCESS_TOKEN_TTL) {
    throw new Error('AUTH_REFRESH_TOKEN_TTL must be >= AUTH_ACCESS_TOKEN_TTL');
  }

  return {
    ...env,
    baseUrl,
    storageKey: decodeStorageKey(env.AUTH_STORAGE_ENCRYPTION_KEY),
    storeKind,
    isAllowedHost: compileHostMatcher(env.N8N_ALLOWED_HOSTS, env.N8N_ALLOWED_HOST_PATTERN),
    isDevelopment,
  };
}

// ─── Module singleton ────────────────────────────────────────────────────────

let cached: Config | null = null;

/** The process-wide config. Parsed on first call, then reused. */
export function getConfig(): Config {
  cached ??= loadConfig();
  return cached;
}

/** Test seam: drop the cached config so the next getConfig() re-reads env. */
export function resetConfig(): void {
  cached = null;
}

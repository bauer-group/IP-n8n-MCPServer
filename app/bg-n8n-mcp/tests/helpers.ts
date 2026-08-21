/**
 * Shared test scaffolding.
 *
 * The integration tests drive the real Hono app over `app.fetch`, with only two
 * things faked: the store backend (in-memory) and `fetch` (so no test ever
 * reaches a real n8n or a real n8n-mcp). Everything else — routing, middleware,
 * OAuth logic, sealing, the proxy's header handling — is the production code.
 */

import { createApp } from '../src/app.js';
import { type Config, loadConfig } from '../src/config.js';
import { setLogger } from '../src/logger.js';
import { normalizePath } from '../src/middleware/security.js';
import { Store } from '../src/store/index.js';
import { MemoryBackend } from '../src/store/memory.js';

/** A logger that discards everything, so test output stays readable. */
export function silentLogger(): void {
  const noop = () => undefined;
  setLogger({
    trace: noop,
    debug: noop,
    info: noop,
    warn: noop,
    error: noop,
    fatal: noop,
    silent: noop,
    level: 'silent',
    child: () => silentStub,
  } as never);
}

const silentStub = new Proxy(
  {},
  {
    get: () => () => undefined,
  },
);

/** 32 zero bytes, base64 — deterministic so sealed values are comparable. */
export const TEST_STORAGE_KEY = Buffer.alloc(32, 7).toString('base64');
export const TEST_UPSTREAM_TOKEN = 'test-upstream-token-at-least-32-chars-long';
export const BASE_URL = 'https://mcp.test.example';
export const TENANT = 'flow.acme.example';

export function testEnv(overrides: Record<string, string> = {}): NodeJS.ProcessEnv {
  return {
    ENVIRONMENT: 'development',
    PUBLIC_BASE_URL: BASE_URL,
    N8N_MCP_URL: 'http://n8n-mcp.internal:3000',
    N8N_MCP_AUTH_TOKEN: TEST_UPSTREAM_TOKEN,
    AUTH_STORAGE_ENCRYPTION_KEY: TEST_STORAGE_KEY,
    N8N_ALLOWED_HOSTS: `${TENANT},*.wild.example`,
    // Tests must not depend on a resolver. The address check is covered
    // directly in tenant.test.ts against the pure classifier functions.
    N8N_ALLOW_PRIVATE_ADDRESSES: 'true',
    LOG_LEVEL: 'error',
    ...overrides,
  };
}

export function testConfig(overrides: Record<string, string> = {}): Config {
  return loadConfig(testEnv(overrides));
}

export interface Harness {
  readonly config: Config;
  readonly store: Store;
  /** Drives the app exactly as main.ts does, path normalisation included. */
  fetch(input: string, init?: RequestInit): Promise<Response>;
}

export function createHarness(overrides: Record<string, string> = {}): Harness {
  silentLogger();
  const config = testConfig(overrides);
  const store = new Store(new MemoryBackend(0), config);
  const app = createApp({ config, store, version: 'test' });
  return {
    config,
    store,
    fetch: async (input, init) =>
      await app.fetch(normalizePath(new Request(new URL(input, BASE_URL), init))),
  };
}

// ─── fetch stubbing ──────────────────────────────────────────────────────────

export interface StubbedCall {
  readonly url: string;
  readonly method: string;
  readonly headers: Record<string, string>;
}

export interface FetchStub {
  readonly calls: StubbedCall[];
  restore(): void;
}

/**
 * Replace the global `fetch` with a handler, recording every call.
 *
 * Used for both the n8n probe and the n8n-mcp upstream, since the proxy tests
 * care most about *which headers were sent* — the whole point of the tenant
 * header injection and stripping.
 */
export function stubFetch(
  handler: (request: Request, init?: RequestInit) => Response | Promise<Response>,
): FetchStub {
  const original = globalThis.fetch;
  const calls: StubbedCall[] = [];

  globalThis.fetch = (async (input: string | URL | Request, init?: RequestInit) => {
    const request = input instanceof Request ? input : new Request(input, init);
    calls.push({
      url: request.url,
      method: request.method,
      headers: Object.fromEntries(request.headers),
    });
    // `init` is handed through as well, unchanged. `new Request(input, init)`
    // above re-derives a *dependent* abort signal, and a test that needs to
    // observe an abort must watch the signal the caller actually passed rather
    // than that copy — the copy has been seen not to mirror a late abort once
    // enough work has run in the same worker. Everything the gateway puts on
    // the wire is still asserted through `request`; only signals need `init`.
    return await handler(request, init);
  }) as typeof fetch;

  return {
    calls,
    restore() {
      globalThis.fetch = original;
    },
  };
}

/** The response shape n8n's `GET /api/v1/workflows?limit=1` returns. */
export function n8nWorkflowsOk(): Response {
  return new Response(JSON.stringify({ data: [], nextCursor: null }), {
    status: 200,
    headers: { 'content-type': 'application/json' },
  });
}

// ─── PKCE ────────────────────────────────────────────────────────────────────

export async function pkcePair(): Promise<{ verifier: string; challenge: string }> {
  const { createHash, randomBytes } = await import('node:crypto');
  const verifier = randomBytes(32).toString('base64url');
  return { verifier, challenge: createHash('sha256').update(verifier).digest('base64url') };
}

// ─── n8n API key fixtures ────────────────────────────────────────────────────

/** Build a JWT-shaped n8n API key. The signature is never verified by us. */
export function makeN8nKey(payload: Record<string, unknown> = {}): string {
  const b64 = (value: unknown) => Buffer.from(JSON.stringify(value)).toString('base64url');
  const header = b64({ alg: 'HS256', typ: 'JWT' });
  const body = b64({
    sub: 'user-uuid-1234',
    iss: 'n8n',
    aud: 'public-api',
    iat: Math.floor(Date.now() / 1000) - 60,
    ...payload,
  });
  return `${header}.${body}.c2lnbmF0dXJl`;
}

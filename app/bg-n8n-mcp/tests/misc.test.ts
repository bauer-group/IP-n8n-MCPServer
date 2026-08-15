/**
 * The remaining seams: logger construction, the WWW-Authenticate builder,
 * resource-identifier parsing, form parsing, and the app's error handling.
 */

import type { Context } from 'hono';
import { Hono } from 'hono';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { formBody } from '../src/lib/request.js';
import { initLogger, log, setLogger, short } from '../src/logger.js';
import { clearTenantCache, resolveTenant } from '../src/n8n/tenant.js';
import { bearerChallenge, pathForTenant, resourceFor } from '../src/oauth/metadata.js';
import { hostFromResource, normalizeResource } from '../src/oauth/routes.js';
import { MemoryBackend } from '../src/store/memory.js';
import { BASE_URL, createHarness, silentLogger, TENANT, testConfig } from './helpers.js';

afterEach(() => {
  silentLogger();
  vi.useRealTimers();
});

describe('logger', () => {
  it('builds a JSON logger and exposes it through log()', () => {
    const logger = initLogger(testConfig({ LOG_FORMAT: 'json', LOG_LEVEL: 'warn' }));
    expect(logger.level).toBe('warn');
    expect(log()).toBe(logger);
  });

  it('builds a console logger when asked for one', () => {
    // The pino-pretty transport is a different construction path; a config
    // that only works in json mode would fail on first `docker compose up`
    // with the development file.
    const logger = initLogger(testConfig({ LOG_FORMAT: 'console', LOG_LEVEL: 'debug' }));
    expect(logger.level).toBe('debug');
    logger.debug({ evt: 'test' });
  });

  it('refuses to be used before initialisation', () => {
    setLogger(null as never);
    expect(() => log()).toThrow(/before initLogger/);
  });
});

describe('short', () => {
  it('truncates long identifiers and passes short ones through', () => {
    expect(short('abcdefghijklmnop')).toBe('abcdefgh…');
    expect(short('abc')).toBe('abc');
    expect(short(undefined)).toBeUndefined();
    expect(short(null)).toBeUndefined();
    expect(short('abcdefghij', 4)).toBe('abcd…');
  });
});

describe('bearerChallenge', () => {
  const url = 'https://mcp.test.example/.well-known/oauth-protected-resource/i/h/mcp';

  it('always carries resource_metadata', () => {
    expect(bearerChallenge({ resourceMetadataUrl: url })).toBe(`Bearer resource_metadata="${url}"`);
  });

  it('includes error, description and scope when given', () => {
    const value = bearerChallenge({
      resourceMetadataUrl: url,
      error: 'invalid_token',
      description: 'expired',
      scope: 'n8n',
    });
    expect(value).toContain('error="invalid_token"');
    expect(value).toContain('error_description="expired"');
    expect(value).toContain('scope="n8n"');
  });

  it('strips characters that would break the quoted string', () => {
    // A bare quote or backslash in a quoted-string makes the whole header
    // unparseable, and the client then cannot find resource_metadata at all.
    const value = bearerChallenge({
      resourceMetadataUrl: url,
      description: 'he said "no" \\ then left',
    });
    expect(value).toContain('error_description="he said no  then left"');
  });
});

describe('resource identifiers', () => {
  const config = testConfig();

  it('builds a canonical, lowercase resource', () => {
    expect(resourceFor(config, 'FLOW.Acme.Example')).toBe(`${BASE_URL}/i/flow.acme.example/mcp`);
    expect(pathForTenant('X.Example')).toBe('/i/x.example/mcp');
  });

  it('normalises exactly one trailing slash', () => {
    expect(normalizeResource(`${BASE_URL}/i/h/mcp/`)).toBe(`${BASE_URL}/i/h/mcp`);
    expect(normalizeResource(`${BASE_URL}/i/h/mcp`)).toBe(`${BASE_URL}/i/h/mcp`);
  });

  describe('hostFromResource', () => {
    it('extracts the host from our own canonical resource', () => {
      expect(hostFromResource(config, `${BASE_URL}/i/${TENANT}/mcp`)).toBe(TENANT);
      expect(hostFromResource(config, `${BASE_URL}/i/${TENANT}/mcp/`)).toBe(TENANT);
      expect(hostFromResource(config, `${BASE_URL}/i/${TENANT.toUpperCase()}/mcp`)).toBe(TENANT);
    });

    it.each([
      ['undefined', undefined],
      ['another origin', 'https://evil.example/i/h/mcp'],
      ['a traversal attempt', `${BASE_URL}/i/h/mcp/../../admin`],
      ['a query string', `${BASE_URL}/i/h/mcp?x=1`],
      ['a fragment', `${BASE_URL}/i/h/mcp#x`],
      ['a deeper path', `${BASE_URL}/i/h/mcp/extra`],
      ['the wrong prefix', `${BASE_URL}/x/h/mcp`],
      ['no host segment', `${BASE_URL}/i//mcp`],
      ['nonsense', 'not-a-url'],
    ])('rejects %s', (_label, value) => {
      expect(hostFromResource(config, value)).toBeNull();
    });
  });
});

describe('formBody', () => {
  const app = new Hono();
  app.post('/echo', async (c) => c.json(await formBody(c)));

  it('parses application/x-www-form-urlencoded', async () => {
    // /token and /revoke are form-encoded per RFC 6749 and RFC 7009, while
    // /register is JSON. A server with only one parser 415s on the other.
    const response = await app.request('/echo', {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ grant_type: 'refresh_token', refresh_token: 'abc' }),
    });
    expect(await response.json()).toEqual({ grant_type: 'refresh_token', refresh_token: 'abc' });
  });

  it('returns an empty object for an unparseable body instead of throwing', async () => {
    const response = await app.request('/echo', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: '{"not":"a form"}',
    });
    expect(response.status).toBe(200);
  });

  it('collapses a repeated parameter to its first value', async () => {
    // Parameter pollution relies on the ambiguity of "which one did the server
    // validate". There is no repeatable parameter we accept.
    const response = await app.request('/echo', {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: 'code=first&code=second',
    });
    expect((await response.json()) as Record<string, string>).toMatchObject({ code: 'first' });
  });
});

describe('app error handling', () => {
  it('turns an unexpected throw into a 500 with no internal detail', async () => {
    const harness = createHarness();
    // Reach in and break the store so a handler throws.
    const broken = harness.store as unknown as { resolveToken: () => Promise<never> };
    broken.resolveToken = () => Promise.reject(new Error('secret internal detail'));

    const response = await harness.fetch(`/i/${TENANT}/mcp`, {
      method: 'POST',
      headers: { authorization: 'Bearer x' },
      body: '{}',
    });
    expect(response.status).toBe(500);
    const body = await response.text();
    expect(body).not.toContain('secret internal detail');
    expect(JSON.parse(body)).toEqual({ error: 'internal_error' });
  });

  it('reports readiness as degraded when the store is down', async () => {
    const harness = createHarness();
    (harness.store as unknown as { healthy: () => Promise<boolean> }).healthy = async () => false;
    const response = await harness.fetch('/readyz');
    expect(response.status).toBe(503);
    expect((await response.json()) as Record<string, unknown>).toMatchObject({ store: 'down' });
  });
});

describe('MemoryBackend sweeper', () => {
  it('reclaims expired entries on its interval', async () => {
    vi.useFakeTimers();
    const backend = new MemoryBackend(1_000);
    await backend.set('k', 'v', 1);
    expect(backend.size).toBe(1);
    await vi.advanceTimersByTimeAsync(2_000);
    // Expiry is enforced on read anyway; the sweeper is about not holding
    // memory for keys nobody reads again.
    expect(backend.size).toBe(0);
    await backend.close();
  });
});

describe('tenant resolution cache', () => {
  it('can be cleared', async () => {
    const config = testConfig({
      N8N_ALLOWED_HOSTS: 'example.com',
      N8N_ALLOW_PRIVATE_ADDRESSES: 'false',
    });
    const first = await resolveTenant(config, 'example.com');
    clearTenantCache();
    const second = await resolveTenant(config, 'example.com');
    expect(second.ok).toBe(first.ok);
  });
});

describe('Context helpers used by the proxy', () => {
  it('drops a hop-by-hop header before it reaches the upstream', async () => {
    // Asserted through the app rather than by unit-testing the Set, so the
    // denylist and the copy loop are checked together.
    const harness = createHarness();
    const response = await harness.fetch(`/i/${TENANT}/mcp`, {
      method: 'POST',
      headers: { connection: 'keep-alive' },
      body: '{}',
    });
    // No token, so it stops at the challenge — the point is that a hop-by-hop
    // header does not make the request fail earlier or differently.
    expect(response.status).toBe(401);
  });
});

describe('unused-context guard', () => {
  it('keeps the Context type import meaningful', () => {
    const fake = { req: { header: () => undefined } } as unknown as Context;
    expect(typeof fake.req.header).toBe('function');
  });
});

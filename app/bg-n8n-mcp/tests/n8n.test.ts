/**
 * API-key inspection and the live probe against an n8n instance.
 */

import { describe, expect, it } from 'vitest';
import { inspectApiKey, isExpiredKey } from '../src/n8n/api-key.js';
import { probeApiKey } from '../src/n8n/probe.js';
import { makeN8nKey, n8nWorkflowsOk } from './helpers.js';

const NOW = Date.UTC(2026, 0, 1);
const seconds = (ms: number) => Math.floor(ms / 1000);

describe('inspectApiKey', () => {
  it('reads the claims from a real n8n key', () => {
    const key = makeN8nKey({ sub: 'abc-123' });
    const result = inspectApiKey(key);
    expect(result.kind).toBe('n8n');
    if (result.kind !== 'n8n') return;
    expect(result.claims.subject).toBe('abc-123');
    expect(result.claims.issuer).toBe('n8n');
    expect(result.claims.audience).toBe('public-api');
  });

  it('flags an expired key without a network round trip', () => {
    const key = makeN8nKey({ exp: seconds(NOW) - 3600 });
    expect(inspectApiKey(key, NOW)).toEqual({ kind: 'invalid', reason: 'expired' });
  });

  it('accepts a key expiring in the future', () => {
    const key = makeN8nKey({ exp: seconds(NOW) + 3600 });
    expect(inspectApiKey(key, NOW).kind).toBe('n8n');
  });

  it('tolerates small clock skew at the boundary', () => {
    // A key expiring within the next few seconds should not be rejected
    // mid-form-submit over a clock difference.
    const key = makeN8nKey({ exp: seconds(NOW) - 10 });
    expect(inspectApiKey(key, NOW).kind).toBe('n8n');
  });

  it('names a wrong-audience n8n JWT rather than letting n8n 401 it', () => {
    const key = makeN8nKey({ aud: 'internal' });
    expect(inspectApiKey(key, NOW)).toEqual({ kind: 'invalid', reason: 'wrong_audience' });
  });

  it('rejects an empty value', () => {
    expect(inspectApiKey('   ')).toEqual({ kind: 'invalid', reason: 'empty' });
  });

  describe('treats anything it cannot read as opaque, not invalid', () => {
    // The gateway must not invent a key format n8n does not have. Only the
    // instance gets to say a key is bad.
    it.each([
      ['a non-JWT string', 'n8n_api_abcdef123456'],
      ['two segments', 'aaa.bbb'],
      ['undecodable base64', 'aaa.!!!!.ccc'],
      [
        'a JWT with no subject',
        `${Buffer.from('{}').toString('base64url')}.${Buffer.from('{"iss":"n8n"}').toString('base64url')}.sig`,
      ],
    ])('%s', (_label, value) => {
      expect(inspectApiKey(value).kind).toBe('opaque');
    });
  });

  it('does not reject a third-party JWT for its audience', () => {
    // Only a key that positively claims `iss: n8n` is judged on its audience;
    // a gateway-issued key from some other system is simply opaque to us.
    const key = `${Buffer.from('{}').toString('base64url')}.${Buffer.from(
      JSON.stringify({ sub: 'x', iss: 'other', aud: 'whatever' }),
    ).toString('base64url')}.sig`;
    expect(inspectApiKey(key).kind).toBe('n8n');
  });
});

describe('isExpiredKey', () => {
  it('is true only for a decidably expired key', () => {
    expect(isExpiredKey(makeN8nKey({ exp: seconds(NOW) - 1000 }), NOW)).toBe(true);
    expect(isExpiredKey(makeN8nKey({ exp: seconds(NOW) + 1000 }), NOW)).toBe(false);
    expect(isExpiredKey('opaque-key', NOW)).toBe(false);
  });
});

describe('probeApiKey', () => {
  const origin = 'https://flow.acme.example';
  const key = 'test-key';

  const probeWith = (impl: typeof fetch) =>
    probeApiKey(origin, key, { timeoutMs: 1000, fetchImpl: impl });

  it('accepts a well-formed n8n response', async () => {
    const result = await probeWith(async () => n8nWorkflowsOk());
    expect(result).toEqual({ ok: true });
  });

  it('sends the key in the header n8n expects and does not follow redirects', async () => {
    let seen: Request | undefined;
    await probeWith(async (input, init) => {
      seen = input instanceof Request ? input : new Request(input, init);
      return n8nWorkflowsOk();
    });
    expect(seen?.headers.get('x-n8n-api-key')).toBe(key);
    expect(seen?.url).toBe(`${origin}/api/v1/workflows?limit=1`);
    // Following a redirect would re-send the API key to whatever host the
    // redirect names — a credential-leak primitive, not a convenience.
    expect(seen?.redirect).toBe('manual');
  });

  it.each([
    [401, 'bad_key'],
    [403, 'insufficient_permissions'],
    [404, 'api_disabled'],
    [429, 'rate_limited'],
    [500, 'unreachable'],
  ])('maps HTTP %i to %s', async (status, code) => {
    const result = await probeWith(async () => new Response('', { status }));
    expect(result).toEqual(expect.objectContaining({ ok: false, code }));
  });

  it('treats a redirect as "no API here" rather than retrying it', async () => {
    const result = await probeWith(
      async () => new Response('', { status: 302, headers: { location: 'https://elsewhere' } }),
    );
    expect(result).toEqual(expect.objectContaining({ ok: false, code: 'not_n8n' }));
  });

  it('reports an unreachable host distinctly from a rejected key', async () => {
    const result = await probeWith(async () => {
      throw new TypeError('fetch failed');
    });
    expect(result).toEqual(expect.objectContaining({ ok: false, code: 'unreachable' }));
  });

  it('rejects a 200 that is not an n8n payload', async () => {
    // A login page or a catch-all proxy answering 200 must not read as success.
    const result = await probeWith(
      async () =>
        new Response('<html>Sign in</html>', {
          status: 200,
          headers: { 'content-type': 'text/html' },
        }),
    );
    expect(result).toEqual(expect.objectContaining({ ok: false, code: 'not_n8n' }));
  });

  it('rejects a 200 whose JSON lacks the data array', async () => {
    const result = await probeWith(
      async () =>
        new Response(JSON.stringify({ message: 'ok' }), {
          status: 200,
          headers: { 'content-type': 'application/json' },
        }),
    );
    expect(result).toEqual(expect.objectContaining({ ok: false, code: 'not_n8n' }));
  });
});

/**
 * The MCP proxy.
 *
 * These tests assert what actually reaches n8n-mcp, because that is where the
 * gateway's security properties live: the caller's token must not go upstream,
 * the caller's tenant headers must not survive, ours must be present, and a
 * token for one tenant must not work on another.
 */

import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import {
  BASE_URL,
  createHarness,
  type FetchStub,
  type Harness,
  makeN8nKey,
  n8nWorkflowsOk,
  pkcePair,
  stubFetch,
  TENANT,
  TEST_UPSTREAM_TOKEN,
} from './helpers.js';

const REDIRECT = 'https://claude.ai/api/mcp/auth_callback';
const OTHER_TENANT = 'other.wild.example';

let harness: Harness;
let stub: FetchStub;
/** What the stubbed upstream answers. Reassigned per test. */
let upstream: (request: Request) => Response | Promise<Response>;

beforeEach(() => {
  harness = createHarness();
  upstream = () =>
    new Response(JSON.stringify({ jsonrpc: '2.0', result: {}, id: 1 }), {
      status: 200,
      headers: { 'content-type': 'application/json', 'mcp-session-id': 'sess-123' },
    });
  stub = stubFetch(async (request) => {
    // The n8n probe during consent, versus the n8n-mcp upstream during proxying.
    if (request.url.includes('/api/v1/workflows')) return n8nWorkflowsOk();
    return await upstream(request);
  });
});

afterEach(() => stub.restore());

/** Run the whole OAuth flow and return a usable access token. */
async function accessTokenFor(tenant: string, apiKey = makeN8nKey()): Promise<string> {
  const resource = `${BASE_URL}/i/${tenant}/mcp`;
  const registration = (await (
    await harness.fetch('/register', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ client_name: 'Claude', redirect_uris: [REDIRECT] }),
    })
  ).json()) as { client_id: string };

  const { verifier, challenge } = await pkcePair();
  const page = await harness.fetch(
    `/authorize?response_type=code&client_id=${registration.client_id}` +
      `&redirect_uri=${encodeURIComponent(REDIRECT)}&code_challenge=${challenge}` +
      `&code_challenge_method=S256&resource=${encodeURIComponent(resource)}`,
  );
  const requestId = /name="request_id" value="([^"]+)"/.exec(await page.text())?.[1] as string;

  const consent = await harness.fetch('/authorize', {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      request_id: requestId,
      username: 'kb@example.com',
      api_key: apiKey,
    }),
  });
  const code = new URL(consent.headers.get('location') as string).searchParams.get(
    'code',
  ) as string;

  const tokens = (await (
    await harness.fetch('/token', {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code,
        code_verifier: verifier,
        client_id: registration.client_id,
        redirect_uri: REDIRECT,
      }),
    })
  ).json()) as Record<string, string>;
  return tokens['access_token'] as string;
}

/** The most recent call the stub saw against the upstream MCP endpoint. */
function lastUpstreamCall() {
  return [...stub.calls].reverse().find((call) => call.url.endsWith('/mcp'));
}

describe('authentication', () => {
  it('401s without a token and includes the challenge', async () => {
    const response = await harness.fetch(`/i/${TENANT}/mcp`, { method: 'POST', body: '{}' });
    expect(response.status).toBe(401);
    expect(response.headers.get('www-authenticate')).toContain('Bearer');
  });

  it('401s on a made-up token', async () => {
    const response = await harness.fetch(`/i/${TENANT}/mcp`, {
      method: 'POST',
      headers: { authorization: 'Bearer nope' },
      body: '{}',
    });
    expect(response.status).toBe(401);
  });

  it('rejects a refresh token presented as a bearer', async () => {
    // Only an `access` record may authenticate an MCP call.
    const token = await accessTokenFor(TENANT);
    expect(token).toBeTruthy();
    const response = await harness.fetch(`/i/${TENANT}/mcp`, {
      method: 'POST',
      headers: { authorization: 'Bearer definitely-a-refresh-token' },
      body: '{}',
    });
    expect(response.status).toBe(401);
  });

  it('404s an unknown tenant without consulting the token', async () => {
    const response = await harness.fetch('/i/evil.example/mcp', {
      method: 'POST',
      headers: { authorization: `Bearer ${await accessTokenFor(TENANT)}` },
      body: '{}',
    });
    expect(response.status).toBe(404);
  });

  it('does not resolve DNS before the caller is authenticated', async () => {
    // Otherwise an unauthenticated caller can make this gateway issue resolver
    // queries for any allowlisted name, at any rate they like.
    const before = stub.calls.length;
    await harness.fetch(`/i/${TENANT}/mcp`, { method: 'POST', body: '{}' });
    expect(stub.calls.length).toBe(before);
  });
});

describe('audience binding', () => {
  it('refuses a token issued for a different tenant', async () => {
    // Without this the per-tenant paths are decoration: any valid token would
    // address any allowlisted instance.
    const token = await accessTokenFor(TENANT);
    const response = await harness.fetch(`/i/${OTHER_TENANT}/mcp`, {
      method: 'POST',
      headers: { authorization: `Bearer ${token}` },
      body: '{}',
    });
    expect(response.status).toBe(401);
    expect(response.headers.get('www-authenticate')).toContain('invalid_token');
  });

  it('accepts the token on its own tenant', async () => {
    const token = await accessTokenFor(TENANT);
    const response = await harness.fetch(`/i/${TENANT}/mcp`, {
      method: 'POST',
      headers: { authorization: `Bearer ${token}` },
      body: '{}',
    });
    expect(response.status).toBe(200);
  });
});

describe('upstream request shaping', () => {
  it('replaces the caller token with the upstream secret', async () => {
    // Forwarding the client's token is forbidden outright by the MCP spec —
    // it is the confused-deputy vulnerability the spec names.
    const token = await accessTokenFor(TENANT);
    await harness.fetch(`/i/${TENANT}/mcp`, {
      method: 'POST',
      headers: { authorization: `Bearer ${token}` },
      body: '{}',
    });
    const call = lastUpstreamCall();
    expect(call?.headers['authorization']).toBe(`Bearer ${TEST_UPSTREAM_TOKEN}`);
    expect(call?.headers['authorization']).not.toContain(token);
  });

  it('injects the tenant URL and the user’s own API key', async () => {
    const apiKey = makeN8nKey({ sub: 'user-9' });
    const token = await accessTokenFor(TENANT, apiKey);
    await harness.fetch(`/i/${TENANT}/mcp`, {
      method: 'POST',
      headers: { authorization: `Bearer ${token}` },
      body: '{}',
    });
    const call = lastUpstreamCall();
    expect(call?.headers['x-n8n-url']).toBe(`https://${TENANT}`);
    expect(call?.headers['x-n8n-key']).toBe(apiKey);
  });

  it('strips client-supplied tenant headers', async () => {
    // A client must never be able to redirect the upstream call at its own n8n.
    const token = await accessTokenFor(TENANT);
    await harness.fetch(`/i/${TENANT}/mcp`, {
      method: 'POST',
      headers: {
        authorization: `Bearer ${token}`,
        'x-n8n-url': 'https://evil.example',
        'x-n8n-key': 'attacker-key',
        'x-instance-id': 'spoofed',
        'x-session-id': 'spoofed',
      },
      body: '{}',
    });
    const call = lastUpstreamCall();
    expect(call?.headers['x-n8n-url']).toBe(`https://${TENANT}`);
    expect(call?.headers['x-n8n-key']).not.toBe('attacker-key');
    expect(call?.headers['x-instance-id']).not.toBe('spoofed');
    expect(call?.headers['x-session-id']).toBeUndefined();
  });

  it('sends a per-grant instance id, not the tenant hostname', async () => {
    // n8n-mcp's default session strategy evicts every session sharing an
    // instance id. A per-tenant value would mean one user connecting kicks
    // every other user of that instance off.
    const first = await accessTokenFor(TENANT);
    await harness.fetch(`/i/${TENANT}/mcp`, {
      method: 'POST',
      headers: { authorization: `Bearer ${first}` },
      body: '{}',
    });
    const idA = lastUpstreamCall()?.headers['x-instance-id'];

    const second = await accessTokenFor(TENANT);
    await harness.fetch(`/i/${TENANT}/mcp`, {
      method: 'POST',
      headers: { authorization: `Bearer ${second}` },
      body: '{}',
    });
    const idB = lastUpstreamCall()?.headers['x-instance-id'];

    expect(idA).toBeTruthy();
    expect(idA).not.toBe(idB);
    expect(idA).not.toContain(TENANT);
  });

  it('forwards the MCP session and protocol headers untouched', async () => {
    const token = await accessTokenFor(TENANT);
    await harness.fetch(`/i/${TENANT}/mcp`, {
      method: 'POST',
      headers: {
        authorization: `Bearer ${token}`,
        'mcp-session-id': 'client-session',
        'mcp-protocol-version': '2025-11-25',
        accept: 'application/json, text/event-stream',
      },
      body: '{}',
    });
    const call = lastUpstreamCall();
    expect(call?.headers['mcp-session-id']).toBe('client-session');
    expect(call?.headers['mcp-protocol-version']).toBe('2025-11-25');
    expect(call?.headers['accept']).toBe('application/json, text/event-stream');
  });

  it('forwards headers from protocol revisions this code predates', async () => {
    // The header handling is a denylist precisely so a future revision's
    // routing headers are not silently dropped.
    const token = await accessTokenFor(TENANT);
    await harness.fetch(`/i/${TENANT}/mcp`, {
      method: 'POST',
      headers: {
        authorization: `Bearer ${token}`,
        'mcp-method': 'tools/call',
        'mcp-name': 'n8n_list_workflows',
      },
      body: '{}',
    });
    const call = lastUpstreamCall();
    expect(call?.headers['mcp-method']).toBe('tools/call');
    expect(call?.headers['mcp-name']).toBe('n8n_list_workflows');
  });

  it('proxies GET and DELETE, not just POST', async () => {
    // GET carries the SSE stream and DELETE tears a session down; registering
    // only POST breaks streaming and leaks upstream sessions.
    const token = await accessTokenFor(TENANT);
    for (const method of ['GET', 'DELETE'] as const) {
      const response = await harness.fetch(`/i/${TENANT}/mcp`, {
        method,
        headers: { authorization: `Bearer ${token}`, 'mcp-session-id': 'sess-1' },
      });
      expect(response.status).toBe(200);
      expect(lastUpstreamCall()?.method).toBe(method);
    }
  });
});

describe('upstream response handling', () => {
  it('passes the session id back to the client', async () => {
    const token = await accessTokenFor(TENANT);
    const response = await harness.fetch(`/i/${TENANT}/mcp`, {
      method: 'POST',
      headers: { authorization: `Bearer ${token}` },
      body: '{}',
    });
    expect(response.headers.get('mcp-session-id')).toBe('sess-123');
  });

  it('marks an SSE response as unbuffered', async () => {
    // Without these a proxy can hold the first frame until the stream ends,
    // which reads to the user as a hung tool call.
    upstream = () =>
      new Response('event: message\ndata: {}\n\n', {
        status: 200,
        headers: { 'content-type': 'text/event-stream' },
      });
    const token = await accessTokenFor(TENANT);
    const response = await harness.fetch(`/i/${TENANT}/mcp`, {
      method: 'POST',
      headers: { authorization: `Bearer ${token}`, accept: 'text/event-stream' },
      body: '{}',
    });
    expect(response.headers.get('x-accel-buffering')).toBe('no');
    expect(response.headers.get('cache-control')).toContain('no-transform');
    expect(response.headers.get('content-length')).toBeNull();
  });

  it('turns an upstream 401 into an OAuth challenge', async () => {
    // Otherwise the user sees an opaque tool error instead of a Connect prompt.
    upstream = () => new Response('{}', { status: 401 });
    const token = await accessTokenFor(TENANT);
    const response = await harness.fetch(`/i/${TENANT}/mcp`, {
      method: 'POST',
      headers: { authorization: `Bearer ${token}` },
      body: '{}',
    });
    expect(response.status).toBe(401);
    expect(response.headers.get('www-authenticate')).toContain('resource_metadata=');
  });

  it('reports an unreachable backend as 502, not 500', async () => {
    upstream = () => {
      throw new TypeError('ECONNREFUSED');
    };
    const token = await accessTokenFor(TENANT);
    const response = await harness.fetch(`/i/${TENANT}/mcp`, {
      method: 'POST',
      headers: { authorization: `Bearer ${token}` },
      body: '{}',
    });
    expect(response.status).toBe(502);
  });

  it('relays a non-2xx upstream status verbatim', async () => {
    upstream = () =>
      new Response(JSON.stringify({ jsonrpc: '2.0', error: { code: -32602 }, id: null }), {
        status: 400,
        headers: { 'content-type': 'application/json' },
      });
    const token = await accessTokenFor(TENANT);
    const response = await harness.fetch(`/i/${TENANT}/mcp`, {
      method: 'POST',
      headers: { authorization: `Bearer ${token}` },
      body: '{}',
    });
    expect(response.status).toBe(400);
  });
});

describe('rate limiting', () => {
  it('429s a token that exceeds its per-window budget', async () => {
    const limited = createHarness({ RATE_LIMITER_MCP_MAX: '3', RATE_LIMITER_MCP_WINDOW: '60' });
    harness = limited;
    const token = await accessTokenFor(TENANT);

    const statuses: number[] = [];
    for (let i = 0; i < 6; i += 1) {
      const response = await limited.fetch(`/i/${TENANT}/mcp`, {
        method: 'POST',
        headers: { authorization: `Bearer ${token}` },
        body: '{}',
      });
      statuses.push(response.status);
    }
    expect(statuses.at(-1)).toBe(429);
    expect(statuses[0]).toBe(200);
  });
});

describe('X-Forwarded-For hygiene', () => {
  it('never forwards the "unknown" sentinel as an address', async () => {
    // Found by the end-to-end test, not by this file. `clientIp` returns
    // 'unknown' when it cannot determine an address; forwarding that verbatim
    // made the backend's express-rate-limit throw ERR_ERL_INVALID_IP_ADDRESS
    // under TRUST_PROXY, which killed live MCP sessions. Absent means "use the
    // socket"; "unknown" claims to be an address and is not.
    //
    // The harness calls app.fetch directly, so there is no socket and no
    // X-Forwarded-For — exactly the situation that produced the sentinel.
    const token = await accessTokenFor(TENANT);
    await harness.fetch(`/i/${TENANT}/mcp`, {
      method: 'POST',
      headers: { authorization: `Bearer ${token}` },
      body: '{}',
    });
    const forwarded = lastUpstreamCall()?.headers['x-forwarded-for'];
    expect(forwarded).not.toBe('unknown');
    if (forwarded !== undefined) {
      expect(forwarded).toMatch(/^[0-9a-fA-F.:]+$/);
    }
  });

  it('forwards a real client address when one is known', async () => {
    const proxied = createHarness({ RATE_LIMITER_TRUSTED_PROXY_HOPS: '1' });
    harness = proxied;
    const token = await accessTokenFor(TENANT);
    await proxied.fetch(`/i/${TENANT}/mcp`, {
      method: 'POST',
      headers: { authorization: `Bearer ${token}`, 'x-forwarded-for': '203.0.113.9' },
      body: '{}',
    });
    expect(lastUpstreamCall()?.headers['x-forwarded-for']).toBe('203.0.113.9');
  });
});

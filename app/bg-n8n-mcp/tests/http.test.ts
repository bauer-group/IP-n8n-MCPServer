/**
 * Request helpers, security headers, HTML escaping and the public pages.
 */

import type { Context } from 'hono';
import { describe, expect, it } from 'vitest';
import { clientIp } from '../src/lib/request.js';
import { normalizePath } from '../src/middleware/security.js';
import { errorText, pickLocale } from '../src/ui/i18n.js';
import { consentPage, errorPage, escapeHtml } from '../src/ui/pages.js';
import { fill } from '../src/ui/static.js';
import { BASE_URL, createHarness, TENANT } from './helpers.js';

/** Minimal Context stand-in — clientIp only reads headers and c.env. */
function ctx(headers: Record<string, string>, remoteAddress = '10.0.0.1'): Context {
  return {
    req: { header: (name: string) => headers[name.toLowerCase()] },
    env: { incoming: { socket: { remoteAddress } } },
  } as unknown as Context;
}

describe('clientIp', () => {
  it('ignores X-Forwarded-For when no proxy is configured', () => {
    // With hops=0 the header is entirely client-controlled.
    expect(clientIp(ctx({ 'x-forwarded-for': '1.2.3.4' }), 0)).toBe('10.0.0.1');
  });

  it('takes the entry our own proxy appended, not the leftmost', () => {
    // The left end of X-Forwarded-For is whatever the caller wrote. Trusting it
    // hands every rate limit in this server to anyone willing to set a header.
    expect(clientIp(ctx({ 'x-forwarded-for': '9.9.9.9, 203.0.113.7' }), 1)).toBe('203.0.113.7');
  });

  it('walks further right for a stacked edge proxy', () => {
    expect(clientIp(ctx({ 'x-forwarded-for': '9.9.9.9, 203.0.113.7, 172.16.0.1' }), 2)).toBe(
      '203.0.113.7',
    );
  });

  it('falls back to the socket when the chain is shorter than configured', () => {
    // A short chain means the request did not arrive the expected way; trusting
    // it would let an attacker choose their own bucket.
    expect(clientIp(ctx({ 'x-forwarded-for': '9.9.9.9' }), 3)).toBe('10.0.0.1');
  });

  it('tolerates whitespace and empty entries', () => {
    expect(clientIp(ctx({ 'x-forwarded-for': ' 1.1.1.1 ,  203.0.113.7 ' }), 1)).toBe('203.0.113.7');
  });

  it('reports "unknown" rather than throwing with no socket', () => {
    expect(clientIp({ req: { header: () => undefined }, env: {} } as unknown as Context, 0)).toBe(
      'unknown',
    );
  });
});

describe('normalizePath', () => {
  it('lowercases the path but leaves the query alone', () => {
    const normalized = normalizePath(
      new Request('https://mcp.test.example/I/Flow.ACME.example/MCP?State=AbC'),
    );
    const url = new URL(normalized.url);
    expect(url.pathname).toBe('/i/flow.acme.example/mcp');
    expect(url.search).toBe('?State=AbC');
  });

  it('returns the same object when nothing changes', () => {
    const request = new Request('https://mcp.test.example/healthz');
    expect(normalizePath(request)).toBe(request);
  });

  it('preserves method and headers', () => {
    const normalized = normalizePath(
      new Request('https://mcp.test.example/I/x/MCP', {
        method: 'POST',
        headers: { authorization: 'Bearer t' },
        body: '{}',
      }),
    );
    expect(normalized.method).toBe('POST');
    expect(normalized.headers.get('authorization')).toBe('Bearer t');
  });
});

describe('escapeHtml', () => {
  it('neutralises the characters that break out of text and attributes', () => {
    expect(escapeHtml('<script>alert("x")</script>')).toBe(
      '&lt;script&gt;alert(&quot;x&quot;)&lt;/script&gt;',
    );
    expect(escapeHtml("it's & more")).toBe('it&#39;s &amp; more');
  });
});

describe('consentPage', () => {
  const base = {
    locale: 'de' as const,
    displayName: 'BAUER GROUP n8n',
    hostname: TENANT,
    clientName: null,
    redirectTarget: 'https://claude.ai',
    requestId: 'req-1',
    username: '',
    error: null,
  };

  it('renders the three inputs of the concept: instance, username, key', () => {
    const html = consentPage(base);
    expect(html).toContain(TENANT);
    expect(html).toContain('name="username"');
    expect(html).toContain('name="api_key"');
    expect(html).toContain('type="password"');
  });

  it('escapes a hostile client name', () => {
    // client_name comes straight from an unauthenticated registration request.
    const html = consentPage({ ...base, clientName: '<img src=x onerror=alert(1)>' });
    expect(html).not.toContain('<img src=x');
    expect(html).toContain('&lt;img src=x');
  });

  it('keeps the typed username after a failed attempt', () => {
    const html = consentPage({ ...base, username: 'kb@example.com', error: 'nope' });
    expect(html).toContain('value="kb@example.com"');
    expect(html).toContain('nope');
  });

  it('posts back to /authorize', () => {
    expect(consentPage(base)).toContain('action="/authorize"');
  });

  it('names the origin the authorization will be handed to', () => {
    // The client NAME is chosen by whoever registered; the origin is not. It is
    // the only thing on this page that distinguishes the app the user meant to
    // connect from one merely calling itself by that name.
    const html = consentPage(base);
    expect(html).toContain('<code>https://claude.ai</code>');
    expect(html).toContain('Weiterleitung an');
  });

  it('shows the scheme for a private-use redirect, not the string "null"', () => {
    // `new URL('cursor://cb').origin` is the literal "null"; printing that would
    // be gibberish exactly where the user is meant to be checking something.
    const html = consentPage({ ...base, redirectTarget: 'cursor:' });
    expect(html).toContain('<code>cursor:</code>');
    expect(html).not.toContain('>null<');
  });

  it('omits the row entirely rather than guessing when there is no target', () => {
    const html = consentPage({ ...base, redirectTarget: null });
    expect(html).not.toContain('Weiterleitung an');
    // The rest of the page is unaffected.
    expect(html).toContain('name="api_key"');
  });

  it('escapes a hostile redirect target', () => {
    const html = consentPage({ ...base, redirectTarget: '<img src=x onerror=alert(1)>' });
    expect(html).not.toContain('<img src=x');
    expect(html).toContain('&lt;img src=x');
  });
});

describe('errorPage', () => {
  it('escapes the message', () => {
    expect(errorPage('en', 'App', '<b>x</b>')).toContain('&lt;b&gt;x&lt;/b&gt;');
  });
});

describe('i18n', () => {
  it('picks German by default and English when asked', () => {
    expect(pickLocale(undefined)).toBe('de');
    expect(pickLocale('en-GB,en;q=0.9')).toBe('en');
    expect(pickLocale('de-AT,de;q=0.9')).toBe('de');
    expect(pickLocale('fr-FR')).toBe('de');
    // First recognised tag wins, in header order.
    expect(pickLocale('fr,en;q=0.8,de;q=0.7')).toBe('en');
  });

  it('has a message for every failure code both languages share', () => {
    for (const code of [
      'bad_key',
      'insufficient_permissions',
      'proxy_auth',
      'api_disabled',
      'rate_limited',
      'unreachable',
      'not_n8n',
      'expired',
    ]) {
      expect(errorText('de', code)).not.toBe(code);
      expect(errorText('en', code)).not.toBe(code);
    }
  });

  it('falls back rather than showing a raw code', () => {
    expect(errorText('de', 'something_new')).toBe(errorText('de', 'invalid_request'));
  });
});

describe('security headers', () => {
  const harness = createHarness();

  it('sets a strict CSP with no script on the consent screen', async () => {
    // The consent screen is where a credential is typed. No inline script may
    // run on it, whatever ends up in the markup.
    const response = await harness.fetch('/authorize?client_id=unknown');
    const csp = response.headers.get('content-security-policy') as string;
    expect(csp).toContain("script-src 'none'");
    expect(csp).toContain("frame-ancestors 'none'");
    expect(csp).toContain("form-action 'self'");
    expect(response.headers.get('cache-control')).toBe('no-store');
  });

  it('lets the consent form redirect to the client callback', async () => {
    // The bug this pins: browsers apply form-action to the redirect that
    // FOLLOWS a form submission, not only to the submission. With
    // `form-action 'self'` alone the consent POST succeeded server-side —
    // grant created, code issued, 303 sent — and the browser silently refused
    // to follow it. The user saw a Connect button that did nothing, the AI
    // client never received the code, and the logs showed a completed sign-in.
    const clientId = await (async () => {
      const r = await harness.fetch('/register', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          client_name: 'Claude',
          redirect_uris: ['https://claude.ai/api/mcp/auth_callback'],
          token_endpoint_auth_method: 'none',
          grant_types: ['authorization_code'],
          response_types: ['code'],
        }),
      });
      return ((await r.json()) as { client_id: string }).client_id;
    })();

    const page = await harness.fetch(
      `/authorize?response_type=code&client_id=${clientId}` +
        `&redirect_uri=${encodeURIComponent('https://claude.ai/api/mcp/auth_callback')}` +
        '&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256' +
        `&resource=${encodeURIComponent(`${BASE_URL}/i/${TENANT}/mcp`)}`,
    );
    expect(page.status).toBe(200);

    const csp = page.headers.get('content-security-policy') as string;
    expect(csp).toContain("form-action 'self' https://claude.ai");
    // Only the origin — never the full callback path, and never a wildcard.
    expect(csp).not.toContain('/api/mcp/auth_callback');
  });

  it('names the callback origin for every client shape, not just claude.ai', async () => {
    // Three clients that reach this server in practice and differ in exactly
    // the field this policy is built from. If the origin were hardcoded, or
    // taken from anywhere but the validated redirect URI, one of these would
    // silently lose its redirect the way claude.ai did.
    const cases = [
      {
        name: 'web/claude',
        type: 'web',
        uri: 'https://claude.ai/api/mcp/auth_callback',
        origin: 'https://claude.ai',
      },
      {
        name: 'web/chatgpt',
        type: 'web',
        uri: 'https://chatgpt.com/connector_platform_oauth_redirect',
        origin: 'https://chatgpt.com',
      },
      {
        name: 'web/copilot',
        type: 'web',
        uri: 'https://copilot.microsoft.com/mcp/callback',
        origin: 'https://copilot.microsoft.com',
      },
      // RFC 8252 native client on an ephemeral loopback port — Claude Code.
      {
        name: 'native/loopback',
        type: 'native',
        uri: 'http://127.0.0.1:49731/callback',
        origin: 'http://127.0.0.1:49731',
      },
      // RFC 8252 §7.1 private-use schemes, which isAcceptableRedirectUri
      // accepts by name. `new URL(...).origin` is the literal string "null"
      // for every one of these; emitting that yields a host-source matching
      // nothing, which silently reinstates the policy that broke the flow.
      {
        name: 'native/private-scheme',
        type: 'native',
        uri: 'cursor://anysphere.cursor-retrieval/cb',
        origin: 'cursor:',
      },
      {
        name: 'native/reverse-dns',
        type: 'native',
        uri: 'com.example.app:/cb',
        origin: 'com.example.app:',
      },
    ];

    for (const t of cases) {
      const reg = await harness.fetch('/register', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          client_name: t.name,
          redirect_uris: [t.uri],
          application_type: t.type,
          token_endpoint_auth_method: 'none',
          grant_types: ['authorization_code'],
          response_types: ['code'],
        }),
      });
      expect(reg.status, `${t.name} registration`).toBe(201);
      const clientId = ((await reg.json()) as { client_id: string }).client_id;

      const page = await harness.fetch(
        `/authorize?response_type=code&client_id=${clientId}` +
          `&redirect_uri=${encodeURIComponent(t.uri)}` +
          '&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256' +
          `&resource=${encodeURIComponent(`${BASE_URL}/i/${TENANT}/mcp`)}`,
      );
      expect(page.status, `${t.name} authorize`).toBe(200);
      const csp = page.headers.get('content-security-policy') as string;
      expect(csp, `${t.name} csp`).toContain(`form-action 'self' ${t.origin}`);
      expect(csp, `${t.name} never emits a null source`).not.toContain("'self' null");
    }
  });

  it('does not widen form-action on pages that never redirect out', async () => {
    const csp = (await harness.fetch('/')).headers.get('content-security-policy') as string;
    expect(csp).toContain("form-action 'self'");
    expect(csp).not.toContain('claude.ai');
  });

  it('uses a nonce, not unsafe-inline, for the landing page script', async () => {
    const response = await harness.fetch('/');
    const csp = response.headers.get('content-security-policy') as string;
    expect(csp).toMatch(/script-src 'nonce-[A-Za-z0-9+/=]+'/);
    expect(csp).not.toContain("script-src 'unsafe-inline'");
    const nonce = /script-src 'nonce-([^']+)'/.exec(csp)?.[1] as string;
    expect(await response.text()).toContain(`nonce="${nonce}"`);
  });

  it('sets the standard hardening headers', async () => {
    const response = await harness.fetch('/healthz');
    expect(response.headers.get('x-content-type-options')).toBe('nosniff');
    expect(response.headers.get('x-frame-options')).toBe('DENY');
    expect(response.headers.get('referrer-policy')).toBe('no-referrer');
  });

  it('sets HSTS on an https base URL', async () => {
    expect((await harness.fetch('/healthz')).headers.get('strict-transport-security')).toContain(
      'max-age=31536000',
    );
  });

  it('omits HSTS when running over plain http in development', async () => {
    const local = createHarness({ PUBLIC_BASE_URL: 'http://localhost:8080' });
    expect((await local.fetch('/healthz')).headers.get('strict-transport-security')).toBeNull();
  });

  it('answers a CORS preflight with the MCP headers', async () => {
    const response = await createHarness().fetch(`/i/${TENANT}/mcp`, {
      method: 'OPTIONS',
      headers: { origin: 'https://claude.ai' },
    });
    expect(response.status).toBe(204);
    expect(response.headers.get('access-control-allow-headers')).toContain('Mcp-Session-Id');
    expect(response.headers.get('access-control-allow-methods')).toContain('DELETE');
    expect(response.headers.get('access-control-allow-origin')).toBe('https://claude.ai');
  });

  it('does not require an Origin header', async () => {
    // Anthropic's broker calls server-to-server and sends none; requiring one
    // is a documented cause of initialize timeouts.
    const response = await createHarness().fetch(`/i/${TENANT}/mcp`, {
      method: 'POST',
      body: '{}',
    });
    expect(response.status).toBe(401);
  });

  it('echoes a request id', async () => {
    const response = await harness.fetch('/healthz', { headers: { 'x-request-id': 'trace-1' } });
    expect(response.headers.get('x-request-id')).toBe('trace-1');
  });

  it('generates a request id when the inbound one is not sane', async () => {
    const response = await harness.fetch('/healthz', {
      headers: { 'x-request-id': 'not a valid id!!' },
    });
    expect(response.headers.get('x-request-id')).not.toBe('not a valid id!!');
  });
});

describe('public pages', () => {
  const harness = createHarness();

  it('serves a landing page with the connector URL pattern', async () => {
    const html = await (await harness.fetch('/')).text();
    expect(html).toContain(`${BASE_URL}/i/&lt;n8n-host&gt;/mcp`);
  });

  it('does not disclose which instances are configured', async () => {
    // The landing page is unauthenticated; the tenant list is not public.
    expect(await (await harness.fetch('/')).text()).not.toContain(TENANT);
  });

  describe('landing page language', () => {
    const landing = (acceptLanguage?: string) =>
      harness.fetch('/', acceptLanguage ? { headers: { 'accept-language': acceptLanguage } } : {});

    it('answers a German browser in German', async () => {
      const response = await landing('de-DE,de;q=0.9,en;q=0.8');
      const html = await response.text();
      expect(html).toContain('lang="de"');
      expect(html).toContain('jeder Nutzer verbindet sich');
      expect(html).toContain('Verbinden aus Claude');
    });

    it('answers an English browser in English', async () => {
      const html = await (await landing('en-GB,en;q=0.9')).text();
      expect(html).toContain('lang="en"');
      expect(html).toContain('every user connects with their own');
      expect(html).toContain('Connecting from Claude');
    });

    it('falls back to German when the browser states no preference', async () => {
      // Same default as the consent screen, so the two pages cannot disagree.
      const html = await (await landing()).text();
      expect(html).toContain('lang="de"');
    });

    it('hands the localized labels to the script rather than hardcoding them', async () => {
      // The status pill and the copy button are written by client-side JS. If
      // those strings stayed as literals in the script, a translated page would
      // still flip to "Operational" a second after it loaded.
      const html = await (await landing('de')).text();
      expect(html).toContain('Betriebsbereit');
      expect(html).toContain('Kopiert');
      expect(html).not.toMatch(/textContent = 'Operational'/);
    });

    it('keeps the endpoint table and Claude labels in English, and marks them so', async () => {
      // Deliberate: RFC names are terminology, and the Claude labels are quoted
      // UI a user has to find on their own screen. lang="en" is the other half
      // of that decision — without it a screen reader on the German page reads
      // them with German phonetics. WCAG 2.1 AA, 3.1.2 Language of Parts.
      for (const language of ['de', 'en']) {
        const html = await (await landing(language)).text();
        expect(html).toContain('RFC 9728');
        expect(html).toContain('<table lang="en">');
        expect(html).toContain(
          '<strong lang="en">Settings → Connectors → Add custom connector</strong>',
        );
        expect(html).toContain('<strong lang="en">Connect</strong>');
      }
    });

    it('substitutes every placeholder in both languages', async () => {
      // Both directions matter. The negative catches a placeholder that failed
      // to substitute; the positive catches one a translation dropped, which
      // fails silently — the sentence still reads, the markup is just gone.
      for (const language of ['de', 'en']) {
        const html = await (await landing(language)).text();
        const steps = html.slice(html.indexOf('<ol>'), html.indexOf('</ol>'));

        expect(html).toContain('<code>&lt;n8n-host&gt;</code>');
        expect(html).toContain('<code>flow.example.com</code>');
        expect(steps).toContain('<code>&lt;n8n-host&gt;</code>');
        expect(steps).toContain('<strong lang="en">Connect</strong>');
        expect(html).not.toMatch(/\{host\}|\{example\}|\{action\}/);
      }
    });
  });

  describe('fill', () => {
    it('escapes the template but not the fragments', () => {
      // The whole point of the ordering: prose cannot introduce markup, and
      // the caller's fragment is the only thing that arrives as HTML.
      expect(fill('a <b> {x}', { x: '<strong>ok</strong>' })).toBe(
        'a &lt;b&gt; <strong>ok</strong>',
      );
    });

    it('leaves an unknown placeholder visible rather than blanking it', () => {
      // A translation that invents a placeholder should look wrong in review,
      // not silently lose a word.
      expect(fill('{nope}', {})).toBe('{nope}');
    });

    it('does not resolve inherited object properties', () => {
      // `\w+` matches `constructor` and `toString`. A bare index lookup finds
      // those on Object.prototype and splices the result in as raw HTML —
      // after escaping has already run, so nothing downstream neutralises it.
      expect(fill('{constructor}', {})).toBe('{constructor}');
      expect(fill('{toString}', {})).toBe('{toString}');
      expect(fill('{__proto__}', {})).toBe('{__proto__}');
    });
  });

  it('serves the logo', async () => {
    const response = await harness.fetch('/logo.svg');
    expect(response.headers.get('content-type')).toContain('image/svg+xml');
  });

  it('reports liveness and readiness', async () => {
    expect((await harness.fetch('/healthz')).status).toBe(200);
    const ready = await harness.fetch('/readyz');
    expect(ready.status).toBe(200);
    expect((await ready.json()) as Record<string, unknown>).toMatchObject({ store: 'up' });
  });

  it('404s an unknown path as JSON', async () => {
    const response = await harness.fetch('/nope');
    expect(response.status).toBe(404);
    expect((await response.json()) as { error: string }).toEqual({ error: 'not_found' });
  });
});

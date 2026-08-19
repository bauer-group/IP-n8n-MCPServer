/**
 * Cross-cutting middleware: request correlation, security headers, CORS, and
 * one small piece of defensive routing.
 */

import { randomUUID } from 'node:crypto';
import type { MiddlewareHandler } from 'hono';
import type { AppEnv } from '../app.js';
import type { Config } from '../config.js';
import { clientIp } from '../lib/request.js';
import { log } from '../logger.js';

/**
 * Attach a request id and log the outcome of every request.
 *
 * The id is echoed as `X-Request-Id` so a user reporting "it failed at 14:02"
 * can paste one string and land on the exact log line. An inbound
 * `X-Request-Id` is honoured when it looks sane, so a trace started at Traefik
 * carries through.
 */
export function requestContext(config: Config): MiddlewareHandler<AppEnv> {
  return async (c, next) => {
    const inbound = c.req.header('x-request-id');
    const requestId = inbound && /^[\w.-]{1,128}$/.test(inbound) ? inbound : randomUUID();
    c.set('requestId', requestId);
    c.header('X-Request-Id', requestId);

    const started = performance.now();
    await next();

    // The MCP endpoint is the hot path; logging every request at info level
    // would drown the events that matter. Successful proxy calls go to debug,
    // everything else — and every non-2xx — stays at info.
    const status = c.res.status;
    const isProxy = c.req.path.startsWith('/i/');
    const level = status >= 500 ? 'error' : status >= 400 ? 'warn' : isProxy ? 'debug' : 'info';

    log()[level]({
      evt: 'request',
      req_id: requestId,
      method: c.req.method,
      path: c.req.path,
      status,
      ms: Math.round(performance.now() - started),
      ip: clientIp(c, config.RATE_LIMITER_TRUSTED_PROXY_HOPS),
    });
  };
}

/**
 * Security headers.
 *
 * HTML responses (the consent screen) get a strict CSP: no scripts at all, no
 * external anything, forms may only post back to us. `frame-ancestors 'none'`
 * is correct here rather than something to relax — AI clients open the consent
 * screen as a top-level popup and never frame it, so a framed consent screen is
 * an attack, not a use case.
 *
 * HSTS is emitted only on https, so a development run over http does not pin
 * the browser to a scheme the dev server does not speak.
 */
export function securityHeaders(config: Config): MiddlewareHandler<AppEnv> {
  /**
   * `nonce` is set only by the landing page, which needs a few lines of script
   * for the status badge and the copy button. The consent screen — the page
   * where a credential is typed — never sets one, so it is served under
   * `script-src 'none'` and no inline script can run on it at all, whatever
   * ends up in the markup.
   */
  const htmlPolicy = (nonce: string | undefined, formAction: string | undefined) =>
    [
      "default-src 'none'",
      // The stylesheet is inlined in a <style> element; with script governed by
      // a nonce (or forbidden outright) this cannot be escalated into
      // execution.
      "style-src 'unsafe-inline'",
      nonce ? `script-src 'nonce-${nonce}'` : "script-src 'none'",
      "img-src 'self' data:",
      "connect-src 'self'",
      // 'self' alone breaks the flow this server exists for. The consent POST
      // answers 303 to the AI client's callback, and browsers apply
      // form-action to that redirect too — so the callback origin has to be
      // named or the redirect is dropped without a word to the user. The
      // origin comes from the client's REGISTERED redirect URI, validated
      // before the form was ever rendered, so this widens nothing an attacker
      // controls.
      formAction ? `form-action 'self' ${formAction}` : "form-action 'self'",
      "frame-ancestors 'none'",
      "base-uri 'none'",
    ].join('; ');

  return async (c, next) => {
    await next();

    c.header('X-Content-Type-Options', 'nosniff');
    c.header('X-Frame-Options', 'DENY');
    c.header('Referrer-Policy', 'no-referrer');
    c.header('Cross-Origin-Opener-Policy', 'same-origin');
    c.header('Permissions-Policy', 'geolocation=(), microphone=(), camera=()');

    if (config.baseUrl.startsWith('https://')) {
      c.header('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
    }

    const contentType = c.res.headers.get('content-type') ?? '';
    if (contentType.includes('text/html')) {
      c.header(
        'Content-Security-Policy',
        htmlPolicy(c.get('cspNonce'), c.get('consentRedirectOrigin')),
      );
      // The consent screen carries a credential in its form. Never cached.
      c.header('Cache-Control', 'no-store');
    } else if (contentType.includes('application/json') && c.req.path.startsWith('/.well-known/')) {
      // Discovery documents are cached globally by clients for ~5 minutes
      // anyway; saying so explicitly keeps intermediaries from doing something
      // longer, which would make a metadata fix take hours to land.
      c.header('Cache-Control', 'public, max-age=300');
    }
  };
}

/**
 * CORS for browser-based MCP clients.
 *
 * The MCP specification says nothing about CORS, and says a great deal about
 * validating `Origin` to prevent DNS rebinding. Those two pull in opposite
 * directions, and the resolution is dictated by how remote connectors actually
 * work: Anthropic's broker calls this server **server-to-server and sends no
 * Origin at all**. Requiring one is listed by Anthropic as a common cause of
 * `initialize` timeouts. So: no Origin, no problem.
 *
 * `Access-Control-Expose-Headers` is the part that matters. Without
 * `WWW-Authenticate` exposed, a browser-based client receives an opaque 401 and
 * cannot read the challenge that tells it where to authenticate — it simply
 * fails, with nothing in any log to explain why.
 */
export function cors(): MiddlewareHandler<AppEnv> {
  return async (c, next) => {
    const origin = c.req.header('origin');

    if (origin) {
      // Reflect rather than `*`: `*` is incompatible with credentialed
      // requests, and some clients send one. We do not use cookies, so
      // reflecting an origin grants nothing an attacker could not obtain by
      // calling the endpoint directly with the same bearer token.
      c.header('Access-Control-Allow-Origin', origin);
      c.header('Vary', 'Origin');
    }

    if (c.req.method === 'OPTIONS') {
      c.header('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS');
      c.header(
        'Access-Control-Allow-Headers',
        'Authorization, Content-Type, Accept, Mcp-Session-Id, MCP-Protocol-Version, Last-Event-ID',
      );
      c.header('Access-Control-Max-Age', '86400');
      return c.body(null, 204);
    }

    await next();

    c.header('Access-Control-Expose-Headers', 'WWW-Authenticate, Mcp-Session-Id, X-Request-Id');
    return undefined;
  };
}

/**
 * Lowercase the request path before it reaches the router.
 *
 * Two reasons, one general and one specific. General: every path this server
 * serves is lowercase by construction, and the tenant segment is a hostname,
 * which is case-insensitive by definition — so `/I/Flow.ACME.com/MCP` and
 * `/i/flow.acme.com/mcp` name the same thing and should not 404 differently.
 * Specific: claude.ai has been observed title-casing path segments on connector
 * requests, which produces a 404 the user cannot diagnose and we cannot see the
 * cause of.
 *
 * This is applied by wrapping `app.fetch`, NOT as middleware: Hono resolves the
 * route before middleware runs, so rewriting the path from inside a middleware
 * would change what the handler sees without changing which handler was picked.
 *
 * Only the path is touched — query string, headers and body are untouched.
 */
export function normalizePath(request: Request): Request {
  const url = new URL(request.url);
  const lowered = url.pathname.toLowerCase();
  if (lowered === url.pathname) return request;
  url.pathname = lowered;
  return new Request(url, request);
}

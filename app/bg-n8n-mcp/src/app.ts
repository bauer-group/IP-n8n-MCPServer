/**
 * HTTP surface assembly.
 *
 * Route map:
 *
 *   GET  /                                                    landing page
 *   GET  /healthz                                             liveness
 *   GET  /readyz                                              readiness (store)
 *   GET  /logo.svg
 *   GET  /.well-known/oauth-authorization-server              RFC 8414
 *   GET  /.well-known/openid-configuration                    same document
 *   GET  /.well-known/oauth-protected-resource/i/:host/mcp    RFC 9728
 *   POST /register                                            RFC 7591
 *   GET  /authorize                                           consent screen
 *   POST /authorize                                           consent submit
 *   POST /token
 *   POST /revoke                                              RFC 7009
 *   *    /i/:host/mcp                                         the MCP proxy
 */

import { randomBytes } from 'node:crypto';
import { Hono } from 'hono';
import type { Config } from './config.js';
import { log } from './logger.js';
import { cors, requestContext, securityHeaders } from './middleware/security.js';
import { createOAuthRoutes } from './oauth/routes.js';
import { createMcpProxy } from './proxy/mcp.js';
import type { Store } from './store/index.js';
import { pickLocale } from './ui/i18n.js';
import { landingPage, logoSvg } from './ui/static.js';

export interface AppEnv {
  Variables: {
    requestId: string;
    /**
     * Set only by routes that legitimately need inline script (the landing
     * page). Its absence is what pins every other HTML response — including
     * the consent screen — to `script-src 'none'`.
     */
    cspNonce?: string;
  };
}

export interface AppDeps {
  readonly config: Config;
  readonly store: Store;
  readonly version: string;
}

export function createApp(deps: AppDeps): Hono<AppEnv> {
  const { config, store, version } = deps;
  const app = new Hono<AppEnv>();

  app.use('*', requestContext(config));
  app.use('*', cors());
  app.use('*', securityHeaders(config));

  // ── Public pages ───────────────────────────────────────────────────────────

  app.get('/', (c) => {
    const nonce = randomBytes(16).toString('base64');
    c.set('cspNonce', nonce);
    // Same negotiation the consent screen uses. Without it this page stayed
    // English while the login it links to came back in German, which reads as
    // a broken translation rather than the scope gap it was.
    return c.html(landingPage(config, version, nonce, pickLocale(c.req.header('accept-language'))));
  });

  app.get('/logo.svg', (c) => {
    c.header('Content-Type', 'image/svg+xml');
    c.header('Cache-Control', 'public, max-age=86400');
    return c.body(logoSvg());
  });

  /**
   * Liveness. Answers as long as the process can serve a request, and nothing
   * more — this is what the container HEALTHCHECK polls, and tying it to Redis
   * would turn a brief Redis blip into an orchestrator killing a process that
   * was about to recover.
   */
  app.get('/healthz', (c) => c.json({ status: 'ok', version }));

  /**
   * Readiness. Reports whether this instance can actually serve traffic, which
   * means the grant store has to be reachable — without it every token lookup
   * fails. Use this one for load-balancer membership.
   */
  app.get('/readyz', async (c) => {
    const storeOk = await store.healthy();
    return c.json(
      { status: storeOk ? 'ok' : 'degraded', store: storeOk ? 'up' : 'down', version },
      storeOk ? 200 : 503,
    );
  });

  // ── OAuth ──────────────────────────────────────────────────────────────────

  app.route('/', createOAuthRoutes({ config, store }));

  // ── MCP proxy ──────────────────────────────────────────────────────────────

  const proxy = createMcpProxy({ config, store });
  // GET (SSE stream), POST (JSON-RPC) and DELETE (session teardown) are all
  // part of the Streamable HTTP transport for pre-2026-07-28 clients, and
  // n8n-mcp implements all three. Registering only POST — the obvious reading
  // of "an MCP endpoint" — breaks streaming and leaks upstream sessions.
  app.on(['GET', 'POST', 'DELETE'], '/i/:host/mcp', proxy);

  // ── Fallbacks ──────────────────────────────────────────────────────────────

  app.notFound((c) => c.json({ error: 'not_found' }, 404));

  app.onError((error, c) => {
    // Never leak an internal message or stack to the caller; log it against the
    // request id so it can still be found.
    log().error({
      evt: 'unhandled_error',
      req_id: c.get('requestId'),
      path: c.req.path,
      detail: error instanceof Error ? error.stack : String(error),
    });
    return c.json({ error: 'internal_error' }, 500);
  });

  return app;
}

/**
 * Process entrypoint.
 *
 * Boot order matters and is deliberate:
 *
 *   1. parse config   — a bad environment must fail here, loudly, before a
 *                       socket is bound and a load balancer starts sending
 *                       traffic to a half-configured instance
 *   2. init logger    — so everything after this point is structured
 *   3. open the store — a Redis that is unreachable at boot is a boot failure,
 *                       not a runtime surprise on the first login
 *   4. bind
 *
 * Steps 1 and 3 failing before the listener exists is the whole point: an
 * orchestrator restarts a container that never became healthy, and does not
 * route to one that never bound.
 */

import { serve } from '@hono/node-server';
import { createApp } from './app.js';
import { loadConfig } from './config.js';
import { initLogger, log } from './logger.js';
import { normalizePath } from './middleware/security.js';
import { Store } from './store/index.js';

/**
 * Stamped by the Docker build from package.json, so a running container can
 * report exactly which image it is. Falls back for a `pnpm dev` run.
 */
const VERSION = process.env['APP_VERSION'] ?? '0.0.0-dev';

/** Grace period for in-flight requests on SIGTERM before the process exits. */
const SHUTDOWN_TIMEOUT_MS = 15_000;

async function main(): Promise<void> {
  // Config is parsed before the logger exists, so this one failure has to go to
  // stderr directly — there is nothing else yet, and swallowing it would leave
  // an operator with a container that exits silently.
  let config: ReturnType<typeof loadConfig>;
  try {
    config = loadConfig();
  } catch (error) {
    process.stderr.write(
      `${error instanceof Error ? error.message : String(error)}\n\n` +
        'See .env.example, or run: node scripts/generate-env.mjs\n',
    );
    process.exit(78); // EX_CONFIG — "the configuration is wrong", not "it crashed"
  }

  initLogger(config);

  const store = await Store.open(config);
  const app = createApp({ config, store, version: VERSION });

  const server = serve({
    // normalizePath runs outside Hono because routing is resolved before any
    // middleware executes; see middleware/security.ts.
    //
    // The `...rest` matters and is easy to drop. @hono/node-server invokes this
    // as `fetch(request, env, ctx)`, where `env` carries the Node
    // `{ incoming, outgoing }` pair — and `incoming.socket.remoteAddress` is
    // the only source of the client address when no proxy is in front. A
    // wrapper that forwards only `request` leaves `c.env` undefined, so every
    // request is attributed to "unknown": rate-limit buckets collapse into one,
    // and the X-Forwarded-For sent upstream is a literal "unknown" that the
    // backend's own limiter rejects. Caught by the end-to-end test, not by any
    // unit test — the harness calls `app.fetch` directly and never has a
    // socket either.
    fetch: (request: Request, ...rest: unknown[]) =>
      (app.fetch as (r: Request, ...a: unknown[]) => Response | Promise<Response>)(
        normalizePath(request),
        ...rest,
      ),
    port: config.MCP_PORT,
    hostname: config.MCP_HOST,
  });

  log().info({
    evt: 'started',
    version: VERSION,
    port: config.MCP_PORT,
    base_url: config.baseUrl,
    upstream: config.N8N_MCP_URL,
    store: config.storeKind,
    environment: config.ENVIRONMENT,
  });

  // ── Shutdown ───────────────────────────────────────────────────────────────
  let shuttingDown = false;
  const shutdown = (signal: string): void => {
    // A second Ctrl-C should exit now, not queue another graceful shutdown.
    if (shuttingDown) {
      log().warn({ evt: 'shutdown_forced', signal });
      process.exit(1);
    }
    shuttingDown = true;
    log().info({ evt: 'shutdown', signal });

    // Long-lived SSE streams will not end on their own, so the close callback
    // may never fire. Bound the wait rather than hanging until the
    // orchestrator's SIGKILL, which would look like a crash in the logs.
    const forceExit = setTimeout(() => {
      log().warn({ evt: 'shutdown_timeout', ms: SHUTDOWN_TIMEOUT_MS });
      process.exit(0);
    }, SHUTDOWN_TIMEOUT_MS);
    forceExit.unref();

    server.close(() => {
      void store.close().finally(() => process.exit(0));
    });
  };

  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT', () => shutdown('SIGINT'));

  // A rejection nobody handled is a bug, and a bug in an auth path is not
  // something to keep serving through. Log it with full context, then let the
  // orchestrator restart a known-good process.
  process.on('unhandledRejection', (reason) => {
    log().fatal({
      evt: 'unhandled_rejection',
      detail: reason instanceof Error ? reason.stack : String(reason),
    });
    process.exit(1);
  });
  process.on('uncaughtException', (error) => {
    log().fatal({ evt: 'uncaught_exception', detail: error.stack ?? String(error) });
    process.exit(1);
  });
}

await main();

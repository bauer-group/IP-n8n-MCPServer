/**
 * Structured logging.
 *
 * One rule governs this file: **an n8n API key must never reach a log line.**
 * Everything else is convenience. The redaction list below is belt-and-braces —
 * call sites are expected not to pass secrets at all, and the paths here catch
 * the case where someone logs a whole request or grant object by accident.
 *
 * Events are named rather than free-form (`evt: 'consent_granted'`), so an
 * operator can grep and alert on them without parsing prose. docs/operations.md
 * lists the full vocabulary.
 */

import { type Logger, pino } from 'pino';
import type { Config } from './config.js';

/**
 * Keys whose values are removed wherever they appear, at any depth.
 *
 * `[*]` wildcards cost a little at serialisation time and are worth it: the
 * alternative is enumerating every shape a grant or a header bag can take, and
 * the one that gets missed is the one that leaks.
 */
const REDACT_PATHS = [
  'apiKey',
  'api_key',
  'sealedKey',
  'password',
  'authorization',
  'access_token',
  'refresh_token',
  'client_secret',
  'code_verifier',
  '*.apiKey',
  '*.api_key',
  '*.sealedKey',
  '*.authorization',
  'req.headers.authorization',
  'req.headers["x-n8n-key"]',
  'headers.authorization',
  'headers["x-n8n-key"]',
];

let root: Logger | null = null;

/** Build the process logger. Called once from main.ts. */
export function initLogger(config: Config): Logger {
  root = pino({
    level: config.LOG_LEVEL,
    redact: { paths: REDACT_PATHS, censor: '[redacted]' },
    base: { service: 'bg-n8n-mcp', env: config.ENVIRONMENT },
    // ISO timestamps rather than epoch millis: these logs are read by humans
    // during an incident at least as often as they are shipped to a collector.
    timestamp: pino.stdTimeFunctions.isoTime,
    formatters: {
      // Emit `level: "info"` instead of `level: 30`. Costs nothing and removes
      // a lookup table from every `docker compose logs | jq` session.
      level: (label) => ({ level: label }),
    },
    ...(config.LOG_FORMAT === 'console'
      ? {
          transport: {
            target: 'pino-pretty',
            options: {
              colorize: true,
              translateTime: 'HH:MM:ss.l',
              ignore: 'pid,hostname,service',
            },
          },
        }
      : {}),
  });
  return root;
}

/**
 * The process logger.
 *
 * Throws rather than lazily constructing a default: a module that logs before
 * initLogger() has run would silently use a different level and format than the
 * one the operator configured, and that divergence is invisible in production.
 */
export function log(): Logger {
  if (!root) throw new Error('logger used before initLogger()');
  return root;
}

/** Test seam — install a logger without going through config parsing. */
export function setLogger(logger: Logger): void {
  root = logger;
}

/**
 * Truncate an identifier for logging. Enough to correlate two lines, not enough
 * to replay. Used for client ids, session ids and n8n user ids — never for
 * anything that is itself a credential, which is redacted outright.
 */
export function short(value: string | undefined | null, keep = 8): string | undefined {
  if (!value) return undefined;
  return value.length <= keep ? value : `${value.slice(0, keep)}…`;
}

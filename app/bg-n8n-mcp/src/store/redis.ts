/**
 * Redis backend — the production store.
 *
 * Written against node-redis v6, which changed enough from v4/v5 to be worth
 * naming: RESP3 is the default protocol, replies are plain objects rather than
 * null-prototype ones, and `commandOptions.timeout` now defaults to 5s where it
 * used to be unbounded. The SET option shape moved from `{ EX: n }` to
 * `{ expiration: { type: 'EX', value: n } }`; the old form still works but is
 * deprecated and will go.
 */

import { createClient, type RedisClientType } from 'redis';
import { log } from '../logger.js';
import type { StoreBackend, WindowKind } from './backend.js';

/**
 * The subset of the node-redis client this backend uses.
 *
 * Declared explicitly so the mapping below can be tested against a fake without
 * a live Redis. That matters more than it looks: node-redis has changed the SET
 * option shape and the `multi().exec()` reply shape across majors, and those
 * are exactly the details a type-only dependency would let drift silently.
 */
export interface RedisSetOptions {
  expiration: { type: 'EX'; value: number };
  /** `NX` = only if the key does not already exist. */
  condition?: 'NX';
}

/** The chainable MULTI surface, declared as chainable so either order works. */
export interface RedisMultiLike {
  set(key: string, value: string, options: RedisSetOptions): RedisMultiLike;
  incr(key: string): RedisMultiLike;
  expire(key: string, seconds: number): RedisMultiLike;
  exec(): Promise<unknown[]>;
}

export interface RedisLike {
  get(key: string): Promise<string | null>;
  set(key: string, value: string, options: RedisSetOptions): Promise<unknown>;
  getDel(key: string): Promise<string | null>;
  del(key: string): Promise<unknown>;
  ping(): Promise<string>;
  close(): Promise<void>;
  multi(): RedisMultiLike;
}

export class RedisBackend implements StoreBackend {
  readonly #client: RedisLike;

  private constructor(client: RedisLike) {
    this.#client = client;
  }

  /** Test seam: wrap an already-built (or faked) client. */
  static fromClient(client: RedisLike): RedisBackend {
    return new RedisBackend(client);
  }

  static async connect(url: string): Promise<RedisBackend> {
    const client: RedisClientType = createClient({
      url,
      socket: {
        // Exponential-ish backoff with a 2s ceiling. Redis being briefly away
        // must not turn into a reconnect storm, and it must not give up
        // either — every grant lives here, so "no Redis" means "nobody can
        // use the server".
        reconnectStrategy: (retries) => Math.min(50 * 2 ** Math.min(retries, 6), 2_000),
        connectTimeout: 5_000,
      },
    });

    // The error listener is not optional: node-redis emits 'error' on the
    // client, and an EventEmitter 'error' with no listener crashes the process.
    // A Redis blip must degrade this service, not kill it.
    client.on('error', (error: unknown) => {
      log().error({ evt: 'redis_error', detail: String(error) });
    });
    client.on('reconnecting', () => log().warn({ evt: 'redis_reconnecting' }));
    client.on('ready', () => log().info({ evt: 'redis_ready' }));

    await client.connect();
    return new RedisBackend(client as unknown as RedisLike);
  }

  async get(key: string): Promise<string | null> {
    return await this.#client.get(key);
  }

  async set(key: string, value: string, ttlSeconds: number): Promise<void> {
    await this.#client.set(key, value, { expiration: { type: 'EX', value: ttlSeconds } });
  }

  async take(key: string): Promise<string | null> {
    // GETDEL (Redis >= 6.2) is a single atomic command. The older MULTI/GET/DEL
    // idiom is atomic too, but costs a round trip and returns a reply array
    // whose shape changed between node-redis majors — a needless place to be
    // subtly wrong about single-use authorization codes.
    return await this.#client.getDel(key);
  }

  async incr(key: string, ttlSeconds: number, window: WindowKind): Promise<number> {
    const toCount = (reply: unknown): number => {
      const count = Number(reply);
      return Number.isFinite(count) ? count : 0;
    };

    if (window === 'sliding') {
      // INCR then EXPIRE in one transaction. Re-arming the TTL on every
      // increment is what makes the window slide — each new attempt extends
      // the lockout, which is what a brute-force counter wants.
      const replies = await this.#client.multi().incr(key).expire(key, ttlSeconds).exec();
      return toCount(replies[0]);
    }

    // Fixed window: create the counter carrying its TTL, but only if it is not
    // already there, then increment. The TTL is therefore anchored to the
    // window's first request and never moves.
    //
    // `SET … EX … NX` + `INCR` rather than the shorter `EXPIRE … NX`: that mode
    // needs Redis >= 7.0, and while the compose files pin redis:8, AUTH_REDIS_URL
    // can point at a managed instance nobody here chose. On an older server
    // `EXPIRE … NX` errors, the counter is left with no TTL at all, and the
    // bucket becomes a permanent lockout — a worse failure than the one being
    // fixed. `SET … NX` has worked since 2.6.12.
    const replies = await this.#client
      .multi()
      .set(key, '0', { expiration: { type: 'EX', value: ttlSeconds }, condition: 'NX' })
      .incr(key)
      .exec();
    return toCount(replies[1]);
  }

  async del(key: string): Promise<void> {
    await this.#client.del(key);
  }

  async ping(): Promise<boolean> {
    try {
      return (await this.#client.ping()) === 'PONG';
    } catch {
      return false;
    }
  }

  async close(): Promise<void> {
    // `close()` waits for in-flight commands; `destroy()` would drop them. At
    // shutdown we may be mid-write on a freshly issued token.
    await this.#client.close();
  }
}

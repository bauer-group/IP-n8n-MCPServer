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
import type { StoreBackend } from './backend.js';

/**
 * The subset of the node-redis client this backend uses.
 *
 * Declared explicitly so the mapping below can be tested against a fake without
 * a live Redis. That matters more than it looks: node-redis has changed the SET
 * option shape and the `multi().exec()` reply shape across majors, and those
 * are exactly the details a type-only dependency would let drift silently.
 */
export interface RedisLike {
  get(key: string): Promise<string | null>;
  set(
    key: string,
    value: string,
    options: { expiration: { type: 'EX'; value: number } },
  ): Promise<unknown>;
  getDel(key: string): Promise<string | null>;
  del(key: string): Promise<unknown>;
  ping(): Promise<string>;
  close(): Promise<void>;
  multi(): {
    incr(key: string): { expire(key: string, seconds: number): { exec(): Promise<unknown[]> } };
  };
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

  async incr(key: string, ttlSeconds: number): Promise<number> {
    // INCR then EXPIRE in one transaction. Setting the TTL unconditionally
    // makes this a sliding window: each new attempt extends the lockout, which
    // is the behaviour you want from a brute-force counter.
    const replies = await this.#client.multi().incr(key).expire(key, ttlSeconds).exec();
    const count = Number(replies[0]);
    return Number.isFinite(count) ? count : 0;
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

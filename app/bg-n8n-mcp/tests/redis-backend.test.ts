/**
 * The Redis backend, against a fake client.
 *
 * These tests are not about Redis working — they are about *our mapping onto
 * the node-redis v6 API* being right. node-redis changed the SET option shape
 * (`{ EX: n }` → `{ expiration: { type: 'EX', value: n } }`) and the
 * `multi().exec()` reply shape across majors, and a type-only dependency on
 * those would let a wrong call sit undetected until production.
 */

import { describe, expect, it } from 'vitest';
import {
  RedisBackend,
  type RedisLike,
  type RedisMultiLike,
  type RedisSetOptions,
} from '../src/store/redis.js';
import { silentLogger } from './helpers.js';

silentLogger();

interface Recorded {
  op: string;
  args: unknown[];
}

function fakeClient(overrides: Partial<RedisLike> = {}) {
  const data = new Map<string, string>();
  const log: Recorded[] = [];

  const client: RedisLike = {
    async get(key) {
      log.push({ op: 'get', args: [key] });
      return data.get(key) ?? null;
    },
    async set(key, value, options) {
      log.push({ op: 'set', args: [key, value, options] });
      data.set(key, value);
      return 'OK';
    },
    async getDel(key) {
      log.push({ op: 'getDel', args: [key] });
      const value = data.get(key) ?? null;
      data.delete(key);
      return value;
    },
    async del(key) {
      log.push({ op: 'del', args: [key] });
      data.delete(key);
      return 1;
    },
    async ping() {
      log.push({ op: 'ping', args: [] });
      return 'PONG';
    },
    async close() {
      log.push({ op: 'close', args: [] });
    },
    multi() {
      const queued: Recorded[] = [];
      const replies: unknown[] = [];
      const chain: RedisMultiLike = {
        set(key: string, value: string, options: RedisSetOptions) {
          queued.push({ op: 'set', args: [key, value, options] });
          // The real server applies NX: an existing key is left alone, TTL and
          // all. Modelling that is the whole point of this fake -- a fixed
          // window is exactly "the second SET did nothing".
          if (options.condition === 'NX' && data.has(key)) {
            replies.push(null);
          } else {
            data.set(key, value);
            replies.push('OK');
          }
          return chain;
        },
        incr(key: string) {
          queued.push({ op: 'incr', args: [key] });
          const next = Number(data.get(key) ?? 0) + 1;
          data.set(key, String(next));
          replies.push(next);
          return chain;
        },
        expire(key: string, seconds: number) {
          queued.push({ op: 'expire', args: [key, seconds] });
          replies.push(1);
          return chain;
        },
        async exec() {
          log.push(...queued);
          return replies;
        },
      };
      return chain;
    },
    ...overrides,
  };

  return { client, data, log };
}

describe('RedisBackend', () => {
  it('sets a TTL using the v6 expiration option shape', async () => {
    const { client, log } = fakeClient();
    await RedisBackend.fromClient(client).set('k', 'v', 42);
    expect(log[0]).toEqual({
      op: 'set',
      args: ['k', 'v', { expiration: { type: 'EX', value: 42 } }],
    });
  });

  it('reads a value back', async () => {
    const { client } = fakeClient();
    const backend = RedisBackend.fromClient(client);
    await backend.set('k', 'v', 60);
    expect(await backend.get('k')).toBe('v');
    expect(await backend.get('missing')).toBeNull();
  });

  it('uses GETDEL for the single-use take', async () => {
    // One atomic command. The older MULTI/GET/DEL idiom is also atomic but
    // costs a round trip and returns a reply array whose shape has moved
    // between majors — a needless place to be subtly wrong about single-use
    // authorization codes.
    const { client, log } = fakeClient();
    const backend = RedisBackend.fromClient(client);
    await backend.set('code', 'value', 60);
    expect(await backend.take('code')).toBe('value');
    expect(await backend.take('code')).toBeNull();
    expect(log.some((entry) => entry.op === 'getDel')).toBe(true);
  });

  it('re-arms the window on every increment when it slides', async () => {
    const { client, log } = fakeClient();
    const backend = RedisBackend.fromClient(client);
    expect(await backend.incr('c', 900, 'sliding')).toBe(1);
    expect(await backend.incr('c', 900, 'sliding')).toBe(2);
    // Setting the TTL on every increment is what makes this a sliding window.
    expect(log.filter((entry) => entry.op === 'expire')).toHaveLength(2);
    expect(log.find((entry) => entry.op === 'expire')?.args).toEqual(['c', 900]);
  });

  it('anchors the window to the first request when it is fixed', async () => {
    // The bug this pins: under a sliding window every increment re-armed the
    // TTL, and since throughput buckets also count the requests they REJECT, a
    // client retrying on 429 renewed its own lockout with each retry. At the
    // one-hour register/cimd window that is a permanent block on the very path
    // a user takes to reconnect.
    const { client, log } = fakeClient();
    const backend = RedisBackend.fromClient(client);
    expect(await backend.incr('c', 900, 'fixed')).toBe(1);
    expect(await backend.incr('c', 900, 'fixed')).toBe(2);
    expect(await backend.incr('c', 900, 'fixed')).toBe(3);

    // EXPIRE is never used; the TTL rides on a conditional SET instead.
    expect(log.filter((entry) => entry.op === 'expire')).toHaveLength(0);
    const sets = log.filter((entry) => entry.op === 'set');
    expect(sets).toHaveLength(3);
    // Every one of them is NX-guarded, so only the first can have taken effect.
    for (const attempt of sets) {
      expect(attempt.args[2]).toEqual({
        expiration: { type: 'EX', value: 900 },
        condition: 'NX',
      });
    }
  });

  it('returns 0 rather than NaN if the reply is not a number', async () => {
    const nonsense = (replies: unknown[]) => {
      const chain = {
        set: () => chain,
        incr: () => chain,
        expire: () => chain,
        exec: async () => replies,
      };
      return chain as unknown as RedisMultiLike;
    };
    // Both shapes: sliding reads reply[0], fixed reads reply[1].
    const sliding = fakeClient({ multi: () => nonsense(['not-a-number', 1]) });
    expect(await RedisBackend.fromClient(sliding.client).incr('c', 60, 'sliding')).toBe(0);
    const fixed = fakeClient({ multi: () => nonsense(['OK', 'not-a-number']) });
    expect(await RedisBackend.fromClient(fixed.client).incr('c', 60, 'fixed')).toBe(0);
  });

  it('deletes a key', async () => {
    const { client, data } = fakeClient();
    const backend = RedisBackend.fromClient(client);
    await backend.set('k', 'v', 60);
    await backend.del('k');
    expect(data.has('k')).toBe(false);
  });

  it('reports health from PING', async () => {
    expect(await RedisBackend.fromClient(fakeClient().client).ping()).toBe(true);
  });

  it('reports unhealthy instead of throwing when PING fails', async () => {
    // A Redis blip must degrade /readyz, not crash the request.
    const { client } = fakeClient({
      ping: async () => {
        throw new Error('connection lost');
      },
    });
    expect(await RedisBackend.fromClient(client).ping()).toBe(false);
  });

  it('reports unhealthy on an unexpected PING reply', async () => {
    const { client } = fakeClient({ ping: async () => 'something else' });
    expect(await RedisBackend.fromClient(client).ping()).toBe(false);
  });

  it('closes gracefully rather than destroying in-flight commands', async () => {
    const { client, log } = fakeClient();
    await RedisBackend.fromClient(client).close();
    expect(log.at(-1)?.op).toBe('close');
  });
});

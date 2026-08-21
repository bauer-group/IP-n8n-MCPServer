/**
 * The typed store, with the in-memory backend.
 *
 * The property that matters most here is the grant indirection: revoking a
 * grant must invalidate every token that points at it, immediately.
 */

import { describe, expect, it } from 'vitest';
import { randomToken } from '../src/lib/crypto.js';
import type { StoreBackend } from '../src/store/backend.js';
import { Store } from '../src/store/index.js';
import { MemoryBackend } from '../src/store/memory.js';
import { silentLogger, testConfig } from './helpers.js';

silentLogger();

function newStore(overrides: Record<string, string> = {}) {
  const config = testConfig(overrides);
  return new Store(new MemoryBackend(0), config);
}

const grantInput = {
  hostname: 'flow.acme.example',
  sealedKey: 'v1.aa.bb.cc',
  clientId: 'c_1',
  resource: 'https://mcp.test.example/i/flow.acme.example/mcp',
  username: 'kb@example.com',
  n8nUserId: 'user-1',
};

/**
 * A backend that records the TTL every write was given.
 *
 * MemoryBackend keeps an absolute `expiresAt` and exposes no way to read it
 * back, and asserting on a TTL by waiting for expiry would make the suite slow
 * and flaky. What matters here is only which number was *passed*.
 */
function recordingBackend() {
  const writes: Array<{ key: string; value: string; ttlSeconds: number }> = [];
  const inner = new MemoryBackend(0);
  const backend: StoreBackend = {
    get: (key) => inner.get(key),
    set: (key, value, ttlSeconds) => {
      writes.push({ key, value, ttlSeconds });
      return inner.set(key, value, ttlSeconds);
    },
    take: (key) => inner.take(key),
    incr: (key, ttlSeconds, window) => inner.incr(key, ttlSeconds, window),
    del: (key) => inner.del(key),
    ping: () => inner.ping(),
    close: () => inner.close(),
  };
  return { backend, writes };
}

describe('client records', () => {
  const base = {
    redirectUris: ['https://claude.ai/api/mcp/auth_callback'],
    clientName: 'Claude',
    applicationType: 'web' as const,
    createdAt: Date.now(),
  };

  it('gives a DCR registration the long TTL and a CIMD cache the short one', async () => {
    // One knob used to serve both, and the two fail in opposite directions:
    // losing a registration costs a re-registration, while KEEPING a cached
    // document too long rejects a client that rotated its redirect URIs for
    // exactly that long, with nothing revalidating it.
    const config = testConfig();
    const { backend, writes } = recordingBackend();
    const store = new Store(backend, config);

    await store.putClient({ ...base, clientId: 'c_dcr', source: 'dcr' });
    await store.putClient({ ...base, clientId: 'https://claude.ai/meta', source: 'cimd' });

    expect(writes.map((w) => w.ttlSeconds)).toEqual([
      config.AUTH_CLIENT_TTL,
      config.AUTH_CIMD_CACHE_TTL,
    ]);
    expect(config.AUTH_CIMD_CACHE_TTL).toBeLessThan(config.AUTH_CLIENT_TTL);
  });

  it('reads either kind back unchanged', async () => {
    const store = newStore();
    const client = { ...base, clientId: 'c_dcr', source: 'dcr' as const };
    await store.putClient(client);
    expect(await store.getClient('c_dcr')).toMatchObject(client);
    expect(await store.getClient('')).toBeNull();
  });
});

describe('grants', () => {
  it('creates and reads back a grant', async () => {
    const store = newStore();
    const grant = await store.createGrant(grantInput);
    expect(grant.grantId).toBeTruthy();
    expect(await store.getGrant(grant.grantId)).toMatchObject(grantInput);
  });

  it('returns null for an unknown grant id', async () => {
    expect(await newStore().getGrant('nope')).toBeNull();
    expect(await newStore().getGrant('')).toBeNull();
  });
});

describe('tokens and the grant indirection', () => {
  it('resolves a token together with its grant', async () => {
    const store = newStore();
    const grant = await store.createGrant(grantInput);
    const token = randomToken();
    await store.putToken(
      token,
      {
        grantId: grant.grantId,
        kind: 'access',
        clientId: 'c_1',
        resource: grantInput.resource,
        issuedAt: Date.now(),
      },
      3600,
    );
    const resolved = await store.resolveToken(token);
    expect(resolved?.grant.grantId).toBe(grant.grantId);
    expect(resolved?.token.kind).toBe('access');
  });

  it('invalidates EVERY token of a grant the moment the grant is revoked', async () => {
    // This is the whole point of holding the credential once and pointing
    // tokens at it: revoking one user is a single delete, not a master-key
    // rotation that disconnects everybody.
    const store = newStore();
    const grant = await store.createGrant(grantInput);
    const access = randomToken();
    const refresh = randomToken();
    const base = {
      grantId: grant.grantId,
      clientId: 'c_1',
      resource: grantInput.resource,
      issuedAt: Date.now(),
    };
    await store.putToken(access, { ...base, kind: 'access' }, 3600);
    await store.putToken(refresh, { ...base, kind: 'refresh' }, 7200);

    await store.revokeGrant(grant.grantId);

    expect(await store.resolveToken(access)).toBeNull();
    expect(await store.takeToken(refresh)).toBeNull();
  });

  it('consumes a token with takeToken, so a refresh cannot be replayed', async () => {
    const store = newStore();
    const grant = await store.createGrant(grantInput);
    const token = randomToken();
    await store.putToken(
      token,
      {
        grantId: grant.grantId,
        kind: 'refresh',
        clientId: 'c_1',
        resource: grantInput.resource,
        issuedAt: Date.now(),
      },
      3600,
    );
    expect(await store.takeToken(token)).not.toBeNull();
    expect(await store.takeToken(token)).toBeNull();
  });

  it('never stores the token value itself', async () => {
    // A store dump must not hand an attacker a set of working bearer tokens.
    const backend = new MemoryBackend(0);
    const store = new Store(backend, testConfig());
    const grant = await store.createGrant(grantInput);
    const token = 'a-very-recognisable-token-value';
    await store.putToken(
      token,
      {
        grantId: grant.grantId,
        kind: 'access',
        clientId: 'c_1',
        resource: grantInput.resource,
        issuedAt: Date.now(),
      },
      3600,
    );
    // The key is an HMAC of the token, so a direct lookup by the raw value
    // finds nothing.
    expect(await backend.get(`tok:${token}`)).toBeNull();
  });
});

describe('authorization codes', () => {
  it('is single-use', async () => {
    const store = newStore();
    const code = randomToken();
    await store.putCode(code, {
      grantId: 'g1',
      clientId: 'c_1',
      redirectUri: 'https://claude.ai/cb',
      codeChallenge: 'chal',
      resource: grantInput.resource,
    });
    expect(await store.takeCode(code)).not.toBeNull();
    expect(await store.takeCode(code)).toBeNull();
  });

  it('returns null for an empty code without hitting the backend', async () => {
    expect(await newStore().takeCode('')).toBeNull();
  });
});

describe('pending authorizations', () => {
  it('reads without consuming, so a mistyped key can retry', async () => {
    const store = newStore();
    const requestId = await store.createPendingAuth({
      clientId: 'c_1',
      redirectUri: 'https://claude.ai/cb',
      state: 'st',
      codeChallenge: 'chal',
      hostname: 'flow.acme.example',
      resource: grantInput.resource,
      createdAt: Date.now(),
    });
    expect(await store.getPendingAuth(requestId)).not.toBeNull();
    expect(await store.getPendingAuth(requestId)).not.toBeNull();
    await store.consumePendingAuth(requestId);
    expect(await store.getPendingAuth(requestId)).toBeNull();
  });
});

describe('rate-limit counters', () => {
  it('counts, reads and clears', async () => {
    const store = newStore();
    expect(await store.attemptCount('login', '1.2.3.4')).toBe(0);
    expect(await store.countAttempt('login', '1.2.3.4', 60)).toBe(1);
    expect(await store.countAttempt('login', '1.2.3.4', 60)).toBe(2);
    expect(await store.attemptCount('login', '1.2.3.4')).toBe(2);
    await store.clearAttempts('login', '1.2.3.4');
    expect(await store.attemptCount('login', '1.2.3.4')).toBe(0);
  });

  it('keeps buckets and identities separate', async () => {
    const store = newStore();
    await store.countAttempt('login', 'a', 60);
    expect(await store.attemptCount('login', 'b')).toBe(0);
    expect(await store.attemptCount('token', 'a')).toBe(0);
  });

  it('does not put the identity in the key in the clear', async () => {
    const backend = new MemoryBackend(0);
    const store = new Store(backend, testConfig());
    await store.countAttempt('login', 'kb@example.com', 60);
    expect(await backend.get('rl:login:kb@example.com')).toBeNull();
  });
});

describe('MemoryBackend', () => {
  it('expires entries on read', async () => {
    const backend = new MemoryBackend(0);
    await backend.set('k', 'v', 0);
    // A zero TTL is already in the past by the time it is read back.
    expect(await backend.get('k')).toBeNull();
  });

  it('take is atomic read-and-delete', async () => {
    const backend = new MemoryBackend(0);
    await backend.set('k', 'v', 60);
    expect(await backend.take('k')).toBe('v');
    expect(await backend.take('k')).toBeNull();
  });

  it('incr starts at one and refreshes the window when it slides', async () => {
    const backend = new MemoryBackend(0);
    expect(await backend.incr('c', 60, 'sliding')).toBe(1);
    expect(await backend.incr('c', 60, 'sliding')).toBe(2);
  });

  // Both window tests use a 2s TTL and 1.2s sleeps rather than the tightest
  // numbers that would work. The margin is the point: a CI runner that stalls
  // an extra 300ms must not flip a correctness assertion into a failure.
  const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

  it('a fixed window expires on schedule however hard it is hit', async () => {
    const backend = new MemoryBackend(0);
    expect(await backend.incr('c', 2, 'fixed')).toBe(1);
    // Two more inside the window: the count climbs, the deadline does not move.
    await sleep(1_200);
    expect(await backend.incr('c', 2, 'fixed')).toBe(2);
    await sleep(1_200);
    // 2.4s after the first: a sliding window would have been pushed out twice
    // and still be counting. A fixed one has drained and starts over.
    expect(await backend.incr('c', 2, 'fixed')).toBe(1);
  });

  it('a sliding window is pushed out by every increment', async () => {
    // The counterpart, so the difference is pinned from both sides: identical
    // timings, opposite outcome.
    const backend = new MemoryBackend(0);
    expect(await backend.incr('s', 2, 'sliding')).toBe(1);
    await sleep(1_200);
    expect(await backend.incr('s', 2, 'sliding')).toBe(2);
    await sleep(1_200);
    expect(await backend.incr('s', 2, 'sliding')).toBe(3);
  });

  it('reports healthy and clears on close', async () => {
    const backend = new MemoryBackend(0);
    await backend.set('k', 'v', 60);
    expect(await backend.ping()).toBe(true);
    await backend.close();
    expect(backend.size).toBe(0);
  });
});

describe('refresh-token rotation grace', () => {
  const response = {
    access_token: 'at_secret_value_0001',
    refresh_token: 'rt_secret_value_0002',
    token_type: 'Bearer',
    expires_in: 3600,
  };
  const issued = { grantId: 'g_1', response };

  it('returns the remembered pair for the token that produced it', async () => {
    const { backend } = recordingBackend();
    const store = new Store(backend, testConfig());
    await store.putRotation('rt_consumed', issued, 30);
    expect(await store.getRotation('rt_consumed')).toEqual(issued);
    expect(await store.getRotation('rt_something_else')).toBeNull();
    expect(await store.getRotation('')).toBeNull();
  });

  it('names the grant, so a replay can be checked against a revocation', async () => {
    // Without the grant id the refresh path can only ask "is the window open?",
    // and would answer 200 with a pair that died when the grant was revoked.
    const { backend } = recordingBackend();
    const store = new Store(backend, testConfig());
    await store.putRotation('rt_consumed', issued, 30);
    expect((await store.getRotation('rt_consumed'))?.grantId).toBe('g_1');
  });

  it('seals the pair, so a store dump yields no working token', async () => {
    // Every other record here is deliberately worthless to whoever reads it:
    // tokens live under hashes with no secret in the value, and the one
    // credential there is is AES-256-GCM sealed. This record is different in
    // kind — its value IS a live access and refresh token — so it has to carry
    // the same protection or it becomes the one thing a Redis dump hands over.
    const { backend, writes } = recordingBackend();
    const store = new Store(backend, testConfig());
    await store.putRotation('rt_consumed', issued, 30);

    const written = writes.find((entry) => entry.key.startsWith('rot:'));
    expect(written).toBeDefined();
    expect(written?.ttlSeconds).toBe(30);
    // Neither the token that was consumed nor either token it produced.
    expect(written?.key).not.toContain('rt_consumed');
    expect(written?.value).not.toContain('rt_consumed');
    expect(written?.value).not.toContain(response.access_token);
    expect(written?.value).not.toContain(response.refresh_token);
  });

  it('treats an unreadable record as no grace rather than an error', async () => {
    // Rotating AUTH_STORAGE_ENCRYPTION_KEY is the documented revoke-everything
    // lever; it must not start throwing on the refresh path.
    const { backend } = recordingBackend();
    const store = new Store(backend, testConfig());
    await store.putRotation('rt_consumed', issued, 30);

    const underNewKey = new Store(
      backend,
      testConfig({ AUTH_STORAGE_ENCRYPTION_KEY: Buffer.alloc(32, 9).toString('base64') }),
    );
    expect(await underNewKey.getRotation('rt_consumed')).toBeNull();
  });
});

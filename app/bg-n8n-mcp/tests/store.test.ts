/**
 * The typed store, with the in-memory backend.
 *
 * The property that matters most here is the grant indirection: revoking a
 * grant must invalidate every token that points at it, immediately.
 */

import { describe, expect, it } from 'vitest';
import { randomToken } from '../src/lib/crypto.js';
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

  it('incr starts at one and refreshes the window', async () => {
    const backend = new MemoryBackend(0);
    expect(await backend.incr('c', 60)).toBe(1);
    expect(await backend.incr('c', 60)).toBe(2);
  });

  it('reports healthy and clears on close', async () => {
    const backend = new MemoryBackend(0);
    await backend.set('k', 'v', 60);
    expect(await backend.ping()).toBe(true);
    await backend.close();
    expect(backend.size).toBe(0);
  });
});

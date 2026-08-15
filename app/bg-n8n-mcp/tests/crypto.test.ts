/**
 * Sealing, hashing and constant-time comparison.
 */

import { describe, expect, it } from 'vitest';
import { deriveKeyring, hashKey, randomToken, safeEqual, seal, unseal } from '../src/lib/crypto.js';

const rootA = Buffer.alloc(32, 1);
const rootB = Buffer.alloc(32, 2);

describe('deriveKeyring', () => {
  it('derives two independent keys from one root', () => {
    const keyring = deriveKeyring(rootA);
    expect(keyring.encryption).toHaveLength(32);
    expect(keyring.hashing).toHaveLength(32);
    // Reusing one key for both encryption and MAC is the shortcut this avoids.
    expect(keyring.encryption.equals(keyring.hashing)).toBe(false);
  });

  it('is deterministic, so a restart can still read what it wrote', () => {
    expect(deriveKeyring(rootA).encryption.equals(deriveKeyring(rootA).encryption)).toBe(true);
  });

  it('produces different keys for different roots', () => {
    expect(deriveKeyring(rootA).encryption.equals(deriveKeyring(rootB).encryption)).toBe(false);
  });
});

describe('seal / unseal', () => {
  const keyring = deriveKeyring(rootA);

  it('round-trips a value', () => {
    const secret = 'n8n_api_key_value';
    expect(unseal(keyring, seal(keyring, secret))).toBe(secret);
  });

  it('never produces the same ciphertext twice', () => {
    // A deterministic sealing would let anyone with store access tell that two
    // users configured the same API key.
    expect(seal(keyring, 'same')).not.toBe(seal(keyring, 'same'));
  });

  it('does not contain the plaintext', () => {
    expect(seal(keyring, 'SUPERSECRET')).not.toContain('SUPERSECRET');
  });

  it('carries a version prefix', () => {
    expect(seal(keyring, 'x').startsWith('v1.')).toBe(true);
  });

  it.each([
    ['a different key', () => unseal(deriveKeyring(rootB), seal(keyring, 'x'))],
    ['a truncated value', () => unseal(keyring, seal(keyring, 'x').slice(0, -6))],
    ['a wrong shape', () => unseal(keyring, 'not.a.sealed.value.at.all')],
    ['an empty string', () => unseal(keyring, '')],
    [
      'a downgraded version prefix',
      () => unseal(keyring, seal(keyring, 'x').replace('v1.', 'v0.')),
    ],
  ])('returns null rather than throwing for %s', (_label, act) => {
    expect(act()).toBeNull();
  });

  it('detects a tampered ciphertext through the auth tag', () => {
    const sealed = seal(keyring, 'value');
    const parts = sealed.split('.');
    const data = Buffer.from(parts[3] as string, 'base64url');
    data[0] = (data[0] ?? 0) ^ 0xff;
    parts[3] = data.toString('base64url');
    expect(unseal(keyring, parts.join('.'))).toBeNull();
  });

  it('round-trips unicode and long values', () => {
    const value = `${'ä'.repeat(500)}🔑`;
    expect(unseal(keyring, seal(keyring, value))).toBe(value);
  });
});

describe('hashKey', () => {
  const keyring = deriveKeyring(rootA);

  it('is stable for the same input and key', () => {
    expect(hashKey(keyring, 'token')).toBe(hashKey(keyring, 'token'));
  });

  it('is peppered — a different root gives a different digest', () => {
    // Without the pepper, anyone who can read the store can confirm a guessed
    // token offline with a plain SHA-256.
    expect(hashKey(keyring, 'token')).not.toBe(hashKey(deriveKeyring(rootB), 'token'));
  });

  it('does not contain the input', () => {
    expect(hashKey(keyring, 'plaintext-token')).not.toContain('plaintext-token');
  });
});

describe('randomToken', () => {
  it('produces url-safe values of stable length', () => {
    const token = randomToken();
    expect(token).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(token.length).toBeGreaterThanOrEqual(42);
  });

  it('does not repeat', () => {
    const seen = new Set(Array.from({ length: 500 }, () => randomToken()));
    expect(seen.size).toBe(500);
  });
});

describe('safeEqual', () => {
  it('compares equal strings as equal', () => {
    expect(safeEqual('abc', 'abc')).toBe(true);
  });

  it('rejects different strings', () => {
    expect(safeEqual('abc', 'abd')).toBe(false);
  });

  it('handles different lengths without throwing', () => {
    // timingSafeEqual throws on a length mismatch, which would leak the length
    // through an exception if the raw strings were compared directly.
    expect(safeEqual('short', 'much longer value')).toBe(false);
    expect(safeEqual('', 'x')).toBe(false);
  });
});

/**
 * The DNS half of the tenant check: the deadline and the result cache.
 *
 * Kept apart from tenant.test.ts because it needs `node:dns/promises` mocked,
 * and that mock is module-wide. What is being pinned here is not "does DNS
 * work" but two properties that are invisible in a happy-path test:
 *
 *   - the wait is bounded, so a hung resolver cannot hold a login open
 *     indefinitely (`dns.lookup` takes no signal and no timeout of its own)
 *   - a failure is remembered briefly, so a resolver having a bad minute is
 *     not re-asked on every retry — and the login path deliberately does not
 *     count an unresolvable host toward the lockout, so those retries are
 *     unthrottled by design
 */

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const lookup = vi.hoisted(() => vi.fn());
vi.mock('node:dns/promises', () => ({ lookup }));

const { clearTenantCache, resolveTenant } = await import('../src/n8n/tenant.js');
const { TENANT, testConfig } = await import('./helpers.js');

/** The address check only runs when private addresses are NOT allowed. */
const config = testConfig({ N8N_ALLOW_PRIVATE_ADDRESSES: 'false' });

beforeEach(() => {
  clearTenantCache();
  lookup.mockReset();
});

afterEach(() => {
  vi.useRealTimers();
});

describe('resolution deadline', () => {
  it('gives up waiting when the resolver never answers', async () => {
    vi.useFakeTimers();
    // A resolver that accepts the query and then goes quiet. Without a
    // deadline this promise never settles and the consent request hangs for
    // as long as the client is willing to wait.
    lookup.mockReturnValue(new Promise(() => {}));

    const pending = resolveTenant(config, TENANT);
    await vi.advanceTimersByTimeAsync(3_000);

    expect(await pending).toEqual({ ok: false, reason: 'unresolvable' });
  });

  it('still answers normally when the resolver is merely slow', async () => {
    vi.useFakeTimers();
    lookup.mockReturnValue(
      new Promise((resolve) => setTimeout(() => resolve([{ address: '93.184.216.34' }]), 500)),
    );

    const pending = resolveTenant(config, TENANT);
    await vi.advanceTimersByTimeAsync(500);

    expect(await pending).toEqual({
      ok: true,
      hostname: TENANT,
      origin: `https://${TENANT}`,
    });
  });
});

describe('resolution cache', () => {
  it('caches a failure so a resolver blip is not re-paid on every attempt', async () => {
    lookup.mockRejectedValue(new Error('SERVFAIL'));

    expect(await resolveTenant(config, TENANT)).toEqual({ ok: false, reason: 'unresolvable' });
    expect(await resolveTenant(config, TENANT)).toEqual({ ok: false, reason: 'unresolvable' });

    expect(lookup).toHaveBeenCalledTimes(1);
  });

  it('lets a cached failure expire, so a host coming back is not held down', async () => {
    vi.useFakeTimers();
    lookup.mockRejectedValue(new Error('SERVFAIL'));
    await resolveTenant(config, TENANT);

    // Just past RESOLUTION_FAILURE_TTL_MS. Deliberately much shorter than the
    // success TTL: a wrong "it is down" must not outlive the outage by long.
    await vi.advanceTimersByTimeAsync(10_001);
    lookup.mockResolvedValue([{ address: '93.184.216.34' }]);

    expect(await resolveTenant(config, TENANT)).toEqual({
      ok: true,
      hostname: TENANT,
      origin: `https://${TENANT}`,
    });
    expect(lookup).toHaveBeenCalledTimes(2);
  });

  it('caches a success too, so a busy session does not query per request', async () => {
    lookup.mockResolvedValue([{ address: '93.184.216.34' }]);

    await resolveTenant(config, TENANT);
    await resolveTenant(config, TENANT);

    expect(lookup).toHaveBeenCalledTimes(1);
  });

  it('rejects a name that mixes public and private records', async () => {
    // The classic DNS-rebinding shape. Accepting it because the first record
    // looked fine is exactly how that attack succeeds.
    lookup.mockResolvedValue([{ address: '93.184.216.34' }, { address: '169.254.169.254' }]);

    expect(await resolveTenant(config, TENANT)).toEqual({ ok: false, reason: 'private_address' });
  });

  it('treats an empty answer as unresolvable rather than as public', async () => {
    lookup.mockResolvedValue([]);

    expect(await resolveTenant(config, TENANT)).toEqual({ ok: false, reason: 'unresolvable' });
  });
});

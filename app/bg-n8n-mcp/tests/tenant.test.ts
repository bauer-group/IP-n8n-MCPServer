/**
 * The tenant allowlist and the address-space classifier.
 *
 * This is the file to read first if you are auditing the security of this
 * gateway: every case here is a way a naive implementation lets a caller reach
 * a host it should not.
 */

import { describe, expect, it } from 'vitest';
import { compileHostMatcher } from '../src/config.js';
import {
  checkTenant,
  isPublicIPv4,
  isPublicIPv6,
  parseHostname,
  resolveTenant,
} from '../src/n8n/tenant.js';
import { testConfig } from './helpers.js';

describe('parseHostname', () => {
  it('accepts a plain hostname and lowercases it', () => {
    expect(parseHostname('Flow.Acme.Example')).toBe('flow.acme.example');
  });

  it('strips a trailing root dot', () => {
    // `flow.acme.example.` is the same name to a resolver but would not match
    // an allowlist entry written without the dot.
    expect(parseHostname('flow.acme.example.')).toBe('flow.acme.example');
  });

  it.each([
    ['userinfo smuggling', 'flow.acme.example@evil.tld'],
    ['a path', 'flow.acme.example/../evil'],
    ['a backslash path', 'flow.acme.example\\evil'],
    ['an explicit port', 'flow.acme.example:8080'],
    ['a query string', 'flow.acme.example?x=1'],
    ['a fragment', 'flow.acme.example#x'],
    ['a scheme', 'https://flow.acme.example'],
    ['a unicode homoglyph', 'flow.äcme.example'],
    ['an empty string', ''],
    ['a doubled dot', 'flow..acme.example'],
    ['an over-long name', `${'a'.repeat(250)}.example`],
  ])('rejects %s', (_label, input) => {
    expect(parseHostname(input)).toBeNull();
  });
});

describe('compileHostMatcher', () => {
  it('matches an exact entry, case-insensitively', () => {
    const match = compileHostMatcher(['flow.acme.example'], '');
    expect(match('flow.acme.example')).toBe(true);
    expect(match('FLOW.ACME.EXAMPLE')).toBe(true);
    expect(match('other.acme.example')).toBe(false);
  });

  it('matches a wildcard subdomain but NOT the apex', () => {
    // `*.example.com` granting `example.com` is how a tenant allowlist quietly
    // grows to include the operator's own instance.
    const match = compileHostMatcher(['*.wild.example'], '');
    expect(match('a.wild.example')).toBe(true);
    expect(match('a.b.wild.example')).toBe(true);
    expect(match('wild.example')).toBe(false);
  });

  it('does not let a wildcard match a suffix-alike domain', () => {
    const match = compileHostMatcher(['*.wild.example'], '');
    expect(match('evilwild.example')).toBe(false);
  });

  it('anchors a regex pattern even when the operator forgot to', () => {
    // Without forced anchoring this pattern would match
    // `evil.com/?x=flow.acme.example` shaped inputs via substring search.
    const match = compileHostMatcher([], 'flow\\.[a-z0-9-]+\\.example');
    expect(match('flow.acme.example')).toBe(true);
    expect(match('flow.acme.example.evil.tld')).toBe(false);
    expect(match('prefix-flow.acme.example')).toBe(false);
  });

  it('throws on an invalid regex rather than silently matching nothing', () => {
    expect(() => compileHostMatcher([], '(unclosed')).toThrow(/not a valid regular expression/);
  });

  it('combines list and pattern', () => {
    const match = compileHostMatcher(['exact.example'], 'flow\\..*\\.example');
    expect(match('exact.example')).toBe(true);
    expect(match('flow.a.example')).toBe(true);
    expect(match('nope.example')).toBe(false);
  });
});

describe('isPublicIPv4', () => {
  it.each([
    ['loopback', '127.0.0.1'],
    ['RFC 1918 /8', '10.1.2.3'],
    ['RFC 1918 /12', '172.16.5.4'],
    ['RFC 1918 /12 upper', '172.31.255.255'],
    ['RFC 1918 /16', '192.168.1.1'],
    ['cloud metadata', '169.254.169.254'],
    ['CGNAT', '100.64.0.1'],
    ['this network', '0.0.0.0'],
    ['multicast', '224.0.0.1'],
    ['broadcast', '255.255.255.255'],
    ['TEST-NET-1', '192.0.2.1'],
    ['benchmarking', '198.18.0.1'],
  ])('rejects %s', (_label, address) => {
    expect(isPublicIPv4(address)).toBe(false);
  });

  it.each([['8.8.8.8'], ['1.1.1.1'], ['172.32.0.1'], ['100.63.255.255'], ['93.184.216.34']])(
    'accepts the public address %s',
    (address) => {
      expect(isPublicIPv4(address)).toBe(true);
    },
  );

  it('rejects malformed input rather than defaulting to public', () => {
    expect(isPublicIPv4('999.1.1.1')).toBe(false);
    expect(isPublicIPv4('1.2.3')).toBe(false);
    expect(isPublicIPv4('not-an-ip')).toBe(false);
  });
});

describe('isPublicIPv6', () => {
  it.each([
    ['loopback', '::1'],
    ['unspecified', '::'],
    ['unique local', 'fd00::1'],
    ['unique local fc', 'fc00::1'],
    ['link local', 'fe80::1'],
    ['multicast', 'ff02::1'],
    ['documentation', '2001:db8::1'],
  ])('rejects %s', (_label, address) => {
    expect(isPublicIPv6(address)).toBe(false);
  });

  it('judges an IPv4-mapped address by its IPv4 half', () => {
    // ::ffff:10.0.0.1 is an IPv4 destination wearing an IPv6 costume. Treating
    // it as "some IPv6 address, looks fine" is a complete bypass.
    expect(isPublicIPv6('::ffff:10.0.0.1')).toBe(false);
    expect(isPublicIPv6('::ffff:169.254.169.254')).toBe(false);
    expect(isPublicIPv6('::ffff:8.8.8.8')).toBe(true);
  });

  it('accepts a normal global address', () => {
    expect(isPublicIPv6('2606:4700:4700::1111')).toBe(true);
  });
});

describe('checkTenant', () => {
  const config = testConfig();

  it('accepts an allowlisted host and returns a canonical origin', () => {
    const result = checkTenant(config, 'flow.acme.example');
    expect(result).toEqual({
      ok: true,
      hostname: 'flow.acme.example',
      origin: 'https://flow.acme.example',
    });
  });

  it('rejects a host outside the allowlist', () => {
    expect(checkTenant(config, 'evil.example')).toEqual({ ok: false, reason: 'not_allowlisted' });
  });

  it('rejects a malformed host before consulting the allowlist', () => {
    expect(checkTenant(config, 'flow.acme.example@evil.tld')).toEqual({
      ok: false,
      reason: 'malformed',
    });
  });

  it('does not perform DNS resolution', async () => {
    // checkTenant is used to publish metadata; a resolver dependency there
    // would let a DNS blip take a working connector offline for the length of
    // a client's discovery cache.
    const result = checkTenant(config, 'host-that-does-not-exist.wild.example');
    expect(result.ok).toBe(true);
  });
});

describe('resolveTenant', () => {
  it('rejects a literal private IP even when the allowlist would permit it', async () => {
    const config = testConfig({
      N8N_ALLOWED_HOSTS: '10.0.0.5',
      N8N_ALLOW_PRIVATE_ADDRESSES: 'false',
    });
    expect(await resolveTenant(config, '10.0.0.5')).toEqual({
      ok: false,
      reason: 'private_address',
    });
  });

  it('honours the escape hatch when an operator opts in', async () => {
    const config = testConfig({
      N8N_ALLOWED_HOSTS: '10.0.0.5',
      N8N_ALLOW_PRIVATE_ADDRESSES: 'true',
    });
    const result = await resolveTenant(config, '10.0.0.5');
    expect(result.ok).toBe(true);
  });

  it('reports an unresolvable name distinctly from a disallowed one', async () => {
    const config = testConfig({
      N8N_ALLOWED_HOSTS: '*.invalid',
      N8N_ALLOW_PRIVATE_ADDRESSES: 'false',
    });
    // `.invalid` is reserved by RFC 2606 and never resolves.
    const result = await resolveTenant(config, 'nothing.here.invalid');
    expect(result).toEqual({ ok: false, reason: 'unresolvable' });
  });
});

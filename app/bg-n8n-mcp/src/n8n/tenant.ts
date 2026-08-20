/**
 * Tenant resolution — deciding which n8n instance a request is allowed to reach.
 *
 * This is the security boundary of the whole gateway. Everything downstream
 * trusts that the origin handed to it has already been through `resolveTenant`.
 *
 * Two independent checks, in this order:
 *
 *  1. **Syntactic + allowlist.** The candidate is parsed as a URL first and
 *     matched second. A regex applied to a raw string is bypassable through
 *     userinfo (`flow.ok.example.com@evil.tld`), an explicit port, a path, a
 *     trailing dot, or a unicode homoglyph that punycode later folds. Parsing
 *     first collapses all of those into a hostname there is only one way to
 *     read.
 *
 *  2. **Address check.** Even an allowlisted name is rejected when it resolves
 *     into private, loopback, link-local, CGNAT or multicast space. Without
 *     this, an operator who writes `*.internal.example.com` and a DNS record
 *     pointing at 169.254.169.254 has turned the gateway into a cloud-metadata
 *     reader — the shape of GHSA-4ggg-h7ph-26qr, the SSRF advisory against
 *     n8n-mcp itself.
 */

import { lookup } from 'node:dns/promises';
import { isIP } from 'node:net';
import type { Config } from '../config.js';

export type TenantRejection = 'malformed' | 'not_allowlisted' | 'unresolvable' | 'private_address';

export type TenantResult =
  | { ok: true; hostname: string; origin: string }
  | { ok: false; reason: TenantRejection };

/**
 * Normalise a candidate host string to a bare hostname, or null if it is not
 * one. Rejects everything that is not purely a host: credentials, ports,
 * paths, queries, fragments, non-ASCII.
 */
export function parseHostname(raw: string): string | null {
  if (!raw) return null;
  // 253 is the maximum length of a fully-qualified domain name.
  if (raw.length > 253) return null;
  // Anything outside printable ASCII is refused before URL parsing rather than
  // after: `flow.ä.example.com` and `flow.xn--4ca.example.com` are the same
  // name to a resolver but different strings to an allowlist.
  if (!/^[\x21-\x7e]+$/.test(raw)) return null;
  // `@` and `/` cannot appear in a hostname; their presence means the caller is
  // trying to smuggle a different authority past us.
  if (raw.includes('@') || raw.includes('/') || raw.includes('\\')) return null;

  let url: URL;
  try {
    url = new URL(`https://${raw.toLowerCase()}`);
  } catch {
    return null;
  }

  if (url.username || url.password) return null;
  // No port: this gateway speaks to n8n over standard HTTPS only. Allowing a
  // port would let one allowlisted name address every service on that host.
  if (url.port) return null;
  if (url.pathname !== '/' || url.search || url.hash) return null;

  // A trailing dot is a valid absolute FQDN to a resolver but would not match
  // an allowlist entry written without it.
  const hostname = url.hostname.replace(/\.$/, '');
  if (!hostname || hostname.includes('..')) return null;

  return hostname;
}

// ─── Address-space checks ────────────────────────────────────────────────────

const IPV4_BLOCKED: ReadonlyArray<readonly [string, number]> = [
  ['0.0.0.0', 8], // "this network"
  ['10.0.0.0', 8], // RFC 1918 private
  ['100.64.0.0', 10], // RFC 6598 carrier-grade NAT
  ['127.0.0.0', 8], // loopback
  ['169.254.0.0', 16], // link-local — includes 169.254.169.254 cloud metadata
  ['172.16.0.0', 12], // RFC 1918 private
  ['192.0.0.0', 24], // IETF protocol assignments
  ['192.0.2.0', 24], // TEST-NET-1
  ['192.88.99.0', 24], // 6to4 relay anycast (deprecated)
  ['192.168.0.0', 16], // RFC 1918 private
  ['198.18.0.0', 15], // benchmarking
  ['198.51.100.0', 24], // TEST-NET-2
  ['203.0.113.0', 24], // TEST-NET-3
  ['224.0.0.0', 4], // multicast
  ['240.0.0.0', 4], // reserved, includes 255.255.255.255
];

function ipv4ToInt(address: string): number | null {
  const octets = address.split('.');
  if (octets.length !== 4) return null;
  let value = 0;
  for (const octet of octets) {
    if (!/^\d{1,3}$/.test(octet)) return null;
    const n = Number(octet);
    if (n > 255) return null;
    value = (value << 8) | n;
  }
  return value >>> 0;
}

/** True when the IPv4 address is a normal, globally routable public address. */
export function isPublicIPv4(address: string): boolean {
  const value = ipv4ToInt(address);
  if (value === null) return false;
  for (const [network, bits] of IPV4_BLOCKED) {
    const base = ipv4ToInt(network);
    if (base === null) continue;
    // `<<< 32` is undefined in JS, so a /0 would wrap. No entry uses /0, and
    // the guard keeps that true if one is ever added.
    const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
    if ((value & mask) === (base & mask)) return false;
  }
  return true;
}

/** True when the IPv6 address is a normal, globally routable public address. */
export function isPublicIPv6(address: string): boolean {
  const lower = address.toLowerCase().split('%')[0] ?? '';

  // An IPv4-mapped address (::ffff:10.0.0.1) is an IPv4 destination wearing an
  // IPv6 costume; judge it by its IPv4 half or it walks straight through.
  const mapped = /^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/.exec(lower);
  if (mapped?.[1]) return isPublicIPv4(mapped[1]);

  if (lower === '::' || lower === '::1') return false; // unspecified, loopback
  if (/^f[cd]/.test(lower)) return false; // fc00::/7 unique local
  if (/^fe[89ab]/.test(lower)) return false; // fe80::/10 link-local
  if (lower.startsWith('ff')) return false; // ff00::/8 multicast
  if (lower.startsWith('2001:db8:')) return false; // documentation
  if (lower.startsWith('64:ff9b:')) return false; // NAT64
  if (lower.startsWith('100:') && lower.split(':')[1] === '') return false; // 100::/64 discard

  return true;
}

/** Dispatch on address family. Unknown input is treated as not public. */
export function isPublicAddress(address: string): boolean {
  const family = isIP(address);
  if (family === 4) return isPublicIPv4(address);
  if (family === 6) return isPublicIPv6(address);
  return false;
}

// ─── Resolution ──────────────────────────────────────────────────────────────

/**
 * Result cache for the DNS half of the check.
 *
 * Bounded and short-lived. The point is not speed — it is to stop a busy MCP
 * session from issuing a resolver query per request, which turns the gateway
 * into an amplifier the moment a client loops.
 */
const RESOLUTION_TTL_MS = 60_000;
/**
 * Failures are cached too, but briefly.
 *
 * Not caching them at all is the worse bug it looks like a safe choice: a
 * resolver having a bad minute is then re-asked on every single attempt, and
 * an unresolvable host is the one case the login path does NOT count toward
 * the lockout — so the retries are unthrottled by design. Ten seconds is long
 * enough to collapse a burst onto one query and short enough that a host
 * coming back is not held down for a noticeable time.
 */
const RESOLUTION_FAILURE_TTL_MS = 10_000;
/**
 * How long we WAIT for the resolver. Not how long it takes.
 *
 * `dns.lookup` is getaddrinfo on a libuv thread and takes no signal, so this
 * deadline abandons the wait, not the work: the thread stays occupied until
 * the C call returns. That matters because the pool is small (4 by default),
 * which is why the volume gate on POST /authorize exists — bounding the wait
 * without bounding the callers would just move the queue.
 *
 * A healthy lookup is single-digit milliseconds; 3s is ~100x that and still
 * leaves the 8s probe budget room inside a wait a human will sit through.
 */
const RESOLUTION_TIMEOUT_MS = 3_000;
const RESOLUTION_CACHE_MAX = 512;
/** `null` = could not resolve. Distinct from `false` = resolved, not public. */
const resolutionCache = new Map<string, { until: number; result: boolean | null }>();

/** Drop cached DNS verdicts. Test seam; also useful from a future admin route. */
export function clearTenantCache(): void {
  resolutionCache.clear();
}

/** Resolve, or give up waiting. Null on failure, empty result, or deadline. */
async function lookupWithDeadline(hostname: string): Promise<Array<{ address: string }> | null> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    const records = await Promise.race([
      lookup(hostname, { all: true, verbatim: true }).catch(() => null),
      new Promise<null>((resolve) => {
        timer = setTimeout(() => resolve(null), RESOLUTION_TIMEOUT_MS);
        // Never hold the process open for a lookup nobody is waiting on.
        timer.unref?.();
      }),
    ]);
    return records?.length ? records : null;
  } finally {
    if (timer) clearTimeout(timer);
  }
}

function remember(hostname: string, result: boolean | null): void {
  if (resolutionCache.size >= RESOLUTION_CACHE_MAX) {
    // Cheap bound: drop the oldest insertion. This cache exists to damp query
    // volume, not to be an LRU, and a miss costs one resolver round trip.
    const oldest = resolutionCache.keys().next();
    if (!oldest.done) resolutionCache.delete(oldest.value);
  }
  const ttl = result === null ? RESOLUTION_FAILURE_TTL_MS : RESOLUTION_TTL_MS;
  resolutionCache.set(hostname, { until: Date.now() + ttl, result });
}

async function addressesArePublic(hostname: string): Promise<boolean | null> {
  const cached = resolutionCache.get(hostname);
  if (cached && cached.until > Date.now()) return cached.result;

  const records = await lookupWithDeadline(hostname);

  // EVERY address must be public. A name that publishes one public and one
  // private record is the classic DNS-rebinding setup, and accepting it
  // because the first record looked fine is how that attack succeeds.
  const result = records === null ? null : records.every((r) => isPublicAddress(r.address));

  remember(hostname, result);
  return result;
}

/**
 * Is this host — a literal address or a name — entirely in public address space?
 *
 * Three-valued on purpose: `null` means "could not resolve", which callers must
 * keep distinct from `false` ("resolved, and not public"). Collapsing the two
 * loses the difference between an outage and an attack.
 *
 * Exported because `oauth/clients.ts` needs exactly this check before fetching a
 * Client ID Metadata Document. That is the same primitive as the tenant path —
 * an unauthenticated caller naming a host this gateway will then connect to —
 * and it therefore needs the same deadline, the same cache and the same
 * every-record rule. It had its own `lookup()` with none of the three.
 */
export async function hostResolvesPublic(hostname: string): Promise<boolean | null> {
  if (isIP(hostname)) return isPublicAddress(hostname);
  return await addressesArePublic(hostname);
}

/**
 * Cheap tenant check: parse and allowlist only, no DNS.
 *
 * Used where the answer is "does this gateway serve that instance at all" and
 * no outbound connection follows — publishing protected-resource metadata, and
 * validating the `resource` parameter at /authorize.
 *
 * Deliberately excludes the address check. Discovery documents are cached by
 * clients for minutes at a time, so letting a transient resolver failure turn
 * metadata into a 404 would take a working connector down for far longer than
 * the DNS blip lasted — and buy nothing, because serving metadata makes no
 * outbound request. The address check happens on the paths that actually
 * connect: `resolveTenant`, below.
 */
export function checkTenant(config: Config, raw: string): TenantResult {
  const hostname = parseHostname(raw);
  if (!hostname) return { ok: false, reason: 'malformed' };
  if (!config.isAllowedHost(hostname)) return { ok: false, reason: 'not_allowlisted' };
  return { ok: true, hostname, origin: `https://${hostname}` };
}

/**
 * Full tenant check: parse, allowlist, then address space.
 *
 * On success returns the canonical `https://<hostname>` origin — the only
 * string any caller should go on to use. Callers must never rebuild an origin
 * from the raw path segment.
 *
 * **Known limitation, stated rather than hidden:** the address check is a
 * check-then-use, so a resolver that returns a public address here and a
 * private one microseconds later during `fetch` defeats it. Closing that
 * properly needs a pinned-IP HTTP agent. The residual risk is bounded by the
 * allowlist (an attacker must already control an allowlisted name) and by
 * n8n-mcp's own SSRF guard behind us, which re-checks at request time. See
 * docs/security.md.
 */
export async function resolveTenant(config: Config, raw: string): Promise<TenantResult> {
  const basic = checkTenant(config, raw);
  if (!basic.ok) return basic;
  const { hostname } = basic;

  if (!config.N8N_ALLOW_PRIVATE_ADDRESSES) {
    // A literal IP can never be allowlisted safely — it bypasses the name-based
    // allowlist's whole premise — but `hostResolvesPublic` checks it directly
    // rather than sending it to a resolver.
    const isPublic = await hostResolvesPublic(hostname);
    if (isPublic === null) return { ok: false, reason: 'unresolvable' };
    if (!isPublic) return { ok: false, reason: 'private_address' };
  }

  return { ok: true, hostname, origin: `https://${hostname}` };
}

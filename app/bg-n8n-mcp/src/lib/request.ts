/**
 * Request-shaped helpers that are easy to get subtly wrong.
 */

import type { Context } from 'hono';

/**
 * The client IP, read from `X-Forwarded-For` according to how many proxies are
 * actually in front of us.
 *
 * `X-Forwarded-For` is append-only and client-controlled at its **left** end: a
 * caller can send `X-Forwarded-For: 1.2.3.4` and every proxy will append to it,
 * so the leftmost entry is whatever the attacker wrote. The only trustworthy
 * entries are the rightmost `hops`, which our own infrastructure appended.
 *
 *     XFF:  <spoofed>, <spoofed>, <real client>, <traefik>
 *                                       ▲
 *                        hops = 1 ───────┘   (one proxy: Traefik)
 *
 * Taking the leftmost entry — the common shortcut — hands every rate limit in
 * this server to anyone willing to set a header.
 *
 * With `hops = 0` (no proxy) the header is ignored entirely and the socket
 * address is used.
 */
export function clientIp(c: Context, hops: number): string {
  if (hops > 0) {
    const forwarded = c.req.header('x-forwarded-for');
    if (forwarded) {
      const chain = forwarded
        .split(',')
        .map((part) => part.trim())
        .filter(Boolean);
      // hops=1 → last entry; hops=2 → second to last; and so on.
      const candidate = chain[chain.length - hops];
      if (candidate) return candidate;
      // Fewer entries than configured hops means the request did not arrive
      // through the expected chain. Fall through to the socket address rather
      // than trusting a short chain an attacker could have constructed.
    }
  }

  const socketAddress = c.env as { incoming?: { socket?: { remoteAddress?: string } } } | undefined;
  return socketAddress?.incoming?.socket?.remoteAddress ?? 'unknown';
}

/** Cap on a form body. Every field we read is a token, a code or a short string. */
const MAX_FORM_BYTES = 64 * 1024;

/**
 * Read an `application/x-www-form-urlencoded` body as a flat string map.
 *
 * `/token` and `/revoke` are form-encoded per RFC 6749 §4.1.3 and RFC 7009
 * §2.1, while `/register` is JSON per RFC 7591 §3.1. A gateway that registers
 * only one body parser returns 415 on the other, which is one of the most
 * common ways a hand-rolled OAuth server fails against a real client.
 *
 * Parsed here rather than through the framework's generic body parser for one
 * specific reason: **a repeated parameter must resolve deterministically, and
 * we want to be the ones who chose how.** Hono's `parseBody` keeps the LAST
 * occurrence; we keep the FIRST. Neither is a vulnerability at this endpoint —
 * the client composes the whole body — but "the framework happened to pick one"
 * is not an answer to give about `code=a&code=b` reaching a token endpoint.
 */
export async function formBody(c: Context): Promise<Record<string, string>> {
  let text: string;
  try {
    text = await c.req.text();
  } catch {
    return {};
  }
  if (text.length > MAX_FORM_BYTES) return {};

  const out: Record<string, string> = {};
  for (const [key, value] of new URLSearchParams(text)) {
    // First occurrence wins; later ones are ignored rather than overwriting.
    if (!Object.hasOwn(out, key)) out[key] = value;
  }
  return out;
}

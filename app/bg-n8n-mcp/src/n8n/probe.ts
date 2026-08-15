/**
 * Validating a user's n8n API key against their instance.
 *
 * Runs once before any token is issued, and again (cheaply) on refresh. The
 * point is not just "is this key good" — it is to tell the failure modes apart,
 * because they need different answers from the login form:
 *
 *   wrong key        → make a new one in n8n
 *   edge wants auth  → exempt /api/v1/ from the proxy's own login
 *   public API off   → ask your instance admin to enable it
 *   host unreachable → is the instance up, and public over HTTPS?
 *   not n8n at all   → wrong address
 *
 * The draft this replaces collapsed the last three into "instance unreachable",
 * which is the single most common support question for a setup like this.
 */

export type ProbeFailure =
  | 'bad_key'
  | 'insufficient_permissions'
  | 'proxy_auth'
  | 'api_disabled'
  | 'rate_limited'
  | 'unreachable'
  | 'not_n8n';

export type ProbeResult = { ok: true } | { ok: false; code: ProbeFailure; detail: string };

/**
 * Cap on how much of the response body we read before deciding it is not n8n.
 * A misconfigured address could point at something that streams megabytes; the
 * shape check only needs the first few hundred bytes.
 */
const MAX_PROBE_BODY_BYTES = 64 * 1024;

interface ProbeOptions {
  readonly timeoutMs: number;
  /** Injectable for tests. Defaults to the global fetch. */
  readonly fetchImpl?: typeof fetch;
}

/**
 * The scheme of an HTTP authentication challenge on the response, or null.
 *
 * This is the one signal that separates "n8n rejected the key" from "the key
 * never reached n8n". n8n's public API answers a bad key with a bare JSON body
 * and **no** challenge header — technically a violation of RFC 9110 §15.5.2,
 * which requires one on a 401, but a consistent violation, and the discriminator
 * we get for free because of it. A challenge therefore comes from something in
 * front of n8n: a Basic-Auth'd nginx, an OAuth2 proxy, a WAF.
 */
function authChallengeScheme(response: Response): string | null {
  const raw =
    response.headers.get('www-authenticate') ?? response.headers.get('proxy-authenticate');
  if (!raw) return null;
  // Only the scheme is taken. The rest of a challenge is attacker-influenced
  // free text of unbounded length, and it goes into an operator's log line.
  return (raw.trim().split(/[\s,]/)[0] || 'unknown').slice(0, 32);
}

async function readBounded(response: Response, limit: number): Promise<string | null> {
  const reader = response.body?.getReader();
  if (!reader) return null;
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      if (value) {
        chunks.push(value);
        total += value.byteLength;
        if (total > limit) break;
      }
    }
  } finally {
    // Releasing the lock lets the connection be reused or torn down; without
    // it a body we stopped reading early keeps a socket pinned.
    reader.releaseLock();
    await response.body?.cancel().catch(() => undefined);
  }
  return Buffer.concat(chunks.map((c) => Buffer.from(c))).toString('utf8');
}

/**
 * Read-only probe against n8n's public API.
 *
 * `GET /api/v1/workflows?limit=1` is chosen deliberately: it is available to
 * every role that could usefully drive this MCP server, it is cheap, it never
 * mutates anything, and its response shape (`{ data: [...] }`) is distinctive
 * enough to tell a real n8n from a login page that happens to answer 200.
 */
export async function probeApiKey(
  origin: string,
  apiKey: string,
  options: ProbeOptions,
): Promise<ProbeResult> {
  const doFetch = options.fetchImpl ?? fetch;

  let response: Response;
  try {
    response = await doFetch(`${origin}/api/v1/workflows?limit=1`, {
      method: 'GET',
      headers: {
        'X-N8N-API-KEY': apiKey,
        accept: 'application/json',
        // Named so an n8n operator seeing this in their access log knows who
        // is asking and can correlate it with a user connecting a connector.
        'user-agent': 'bg-n8n-mcp/1 (+https://github.com/bauer-group/IP-n8n-MCPServer)',
      },
      // A redirect is never a valid answer from a REST API. Following one would
      // also re-send the API key to whatever host the redirect names, which is
      // a credential-leak primitive rather than a convenience.
      redirect: 'manual',
      signal: AbortSignal.timeout(options.timeoutMs),
    });
  } catch (error) {
    const detail = error instanceof Error ? error.name : String(error);
    return { ok: false, code: 'unreachable', detail };
  }

  // 3xx: see above. Treated as "there is no API here", not as a retry.
  if (response.status >= 300 && response.status < 400) {
    await response.body?.cancel().catch(() => undefined);
    return {
      ok: false,
      code: 'not_n8n',
      detail: `redirect (${response.status}) instead of an API response`,
    };
  }

  // A 401 has two possible authors, and telling them apart is the difference
  // between "create a new key" and "fix your reverse proxy". An edge that fronts
  // n8n with its own login (Basic auth, an OAuth2 proxy) answers `/api/v1/*`
  // before n8n does, and the key is never seen by n8n at all. Reading that as
  // `bad_key` sends the user to mint key after key into a loop no key can leave
  // — while the lockout counter, which `bad_key` feeds, runs down.
  //
  // 407 is the same situation stated explicitly, challenge header or not.
  const challenge = authChallengeScheme(response);
  if (response.status === 407 || (response.status === 401 && challenge)) {
    await response.body?.cancel().catch(() => undefined);
    return {
      ok: false,
      code: 'proxy_auth',
      detail:
        `an HTTP layer in front of n8n demanded its own credentials ` +
        `(${response.status}, ${challenge ?? 'no challenge header'}); the API key never reached n8n`,
    };
  }

  if (response.status === 401) {
    await response.body?.cancel().catch(() => undefined);
    return { ok: false, code: 'bad_key', detail: 'n8n rejected the key (401)' };
  }

  // 403 means the key is real but the account cannot list workflows. Separating
  // it from 401 matters: telling that user to "create a new key" sends them
  // round a loop that cannot succeed — they need a role change.
  if (response.status === 403) {
    await response.body?.cancel().catch(() => undefined);
    return {
      ok: false,
      code: 'insufficient_permissions',
      detail: 'n8n accepted the key but denied access to workflows (403)',
    };
  }

  // n8n answers 404 across /api/v1/* when the public API is switched off — but
  // so does a reverse proxy with no route for this host, which is what a
  // stopped or undeployed container looks like from out here. The two are not
  // distinguishable from the status alone, and guessing wrong sends the user
  // to an administrator with the wrong request, so the message names both.
  if (response.status === 404) {
    await response.body?.cancel().catch(() => undefined);
    return {
      ok: false,
      code: 'api_disabled',
      detail: 'no API at /api/v1 (public API switched off, or nothing routed for this host)',
    };
  }

  if (response.status === 429) {
    await response.body?.cancel().catch(() => undefined);
    return { ok: false, code: 'rate_limited', detail: 'n8n rate-limited the probe (429)' };
  }

  if (!response.ok) {
    await response.body?.cancel().catch(() => undefined);
    return { ok: false, code: 'unreachable', detail: `n8n returned HTTP ${response.status}` };
  }

  const body = await readBounded(response, MAX_PROBE_BODY_BYTES);
  if (body === null) return { ok: false, code: 'not_n8n', detail: 'empty response body' };

  let parsed: unknown;
  try {
    parsed = JSON.parse(body);
  } catch {
    return { ok: false, code: 'not_n8n', detail: 'response was not JSON' };
  }

  if (
    !parsed ||
    typeof parsed !== 'object' ||
    !Array.isArray((parsed as { data?: unknown }).data)
  ) {
    return { ok: false, code: 'not_n8n', detail: 'response did not look like an n8n API payload' };
  }

  return { ok: true };
}

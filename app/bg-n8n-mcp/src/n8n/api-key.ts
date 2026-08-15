/**
 * Inspecting an n8n API key.
 *
 * n8n issues public-API keys as JWTs signed with the instance's own secret —
 * `{ "iss": "n8n", "aud": "public-api", "sub": "<user-uuid>", "iat": …, "exp": … }`.
 * We cannot verify the signature (only the instance holds the key), and we do
 * not try to. What we *can* do without any network round trip is read the
 * claims, which buys three real things:
 *
 *  - **Expiry is caught at the login form.** n8n keys can be issued with a
 *    lifetime. Without this check the user gets a working connector that dies
 *    silently weeks later with an opaque tool error.
 *  - **The grant gets a stable identity.** `sub` is the n8n user id. That is
 *    the authoritative "who" for audit logging, and unlike the typed username
 *    it cannot be made up.
 *  - **An obvious paste error is named.** Someone pasting a webhook URL, a
 *    session cookie or an n8n *license* key gets told what is wrong instead of
 *    "instance rejected the key".
 *
 * Deliberate design choice: **unparseable is not invalid.** If the value is not
 * a JWT we return `{ kind: 'opaque' }` and let the live probe decide. Some
 * deployments front n8n with a gateway that issues its own key format, and
 * refusing those on syntax grounds would be us inventing a rule n8n does not
 * have. We fail closed only on positive evidence: a well-formed n8n key that
 * has expired, or one that names a different audience.
 */

export interface N8nApiKeyClaims {
  /** n8n user id (the JWT `sub` claim). */
  readonly subject: string;
  readonly issuer: string | undefined;
  readonly audience: string | undefined;
  /** Seconds since the epoch, or undefined for a non-expiring key. */
  readonly expiresAt: number | undefined;
  readonly issuedAt: number | undefined;
}

export type ApiKeyInspection =
  | { kind: 'n8n'; claims: N8nApiKeyClaims }
  | { kind: 'opaque' }
  | { kind: 'invalid'; reason: 'expired' | 'wrong_audience' | 'empty' };

/** The `aud` value n8n stamps on public-API keys. */
const EXPECTED_AUDIENCE = 'public-api';
const EXPECTED_ISSUER = 'n8n';

/**
 * Clock skew tolerance when checking `exp`. Small on purpose: this is not a
 * signature verification where skew matters across hosts, just a courtesy so a
 * key expiring in the next few seconds is not rejected mid-form-submit.
 */
const CLOCK_SKEW_SECONDS = 30;

function decodeSegment(segment: string): unknown {
  try {
    const json = Buffer.from(segment, 'base64url').toString('utf8');
    return JSON.parse(json);
  } catch {
    return null;
  }
}

function readString(source: Record<string, unknown>, key: string): string | undefined {
  const value = source[key];
  return typeof value === 'string' && value ? value : undefined;
}

function readNumber(source: Record<string, unknown>, key: string): number | undefined {
  const value = source[key];
  return typeof value === 'number' && Number.isFinite(value) ? value : undefined;
}

/**
 * Read what can be read from an API key, without any network access.
 *
 * `now` is injectable so the expiry branch is testable without freezing the
 * system clock.
 */
export function inspectApiKey(raw: string, now: number = Date.now()): ApiKeyInspection {
  const key = raw.trim();
  if (!key) return { kind: 'invalid', reason: 'empty' };

  const parts = key.split('.');
  if (parts.length !== 3) return { kind: 'opaque' };

  const payload = decodeSegment(parts[1] ?? '');
  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) return { kind: 'opaque' };

  const body = payload as Record<string, unknown>;
  const subject = readString(body, 'sub');
  const issuer = readString(body, 'iss');
  const audience = readString(body, 'aud');

  // No subject means this is some other JWT — a session token, an OIDC id
  // token someone copied by mistake. Nothing here to bind a grant to, so hand
  // it to the probe rather than guessing.
  if (!subject) return { kind: 'opaque' };

  // A JWT that positively identifies itself as n8n's but for a different
  // audience is the "I pasted the wrong n8n token" case, and saying so is far
  // more useful than a 401 from the instance.
  if (issuer === EXPECTED_ISSUER && audience && audience !== EXPECTED_AUDIENCE) {
    return { kind: 'invalid', reason: 'wrong_audience' };
  }

  const expiresAt = readNumber(body, 'exp');
  if (expiresAt !== undefined && expiresAt + CLOCK_SKEW_SECONDS < Math.floor(now / 1000)) {
    return { kind: 'invalid', reason: 'expired' };
  }

  return {
    kind: 'n8n',
    claims: {
      subject,
      issuer,
      audience,
      expiresAt,
      issuedAt: readNumber(body, 'iat'),
    },
  };
}

/**
 * Whether a sealed grant should be treated as expired without asking n8n.
 *
 * Called on the refresh path: a key whose `exp` has passed cannot come back,
 * so there is no point spending a network round trip — and no reason to let a
 * momentarily unreachable instance keep it alive either.
 */
export function isExpiredKey(raw: string, now: number = Date.now()): boolean {
  const inspection = inspectApiKey(raw, now);
  return inspection.kind === 'invalid' && inspection.reason === 'expired';
}

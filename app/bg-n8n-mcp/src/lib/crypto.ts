/**
 * Cryptographic primitives.
 *
 * Three jobs, deliberately kept in one small file so the whole trust story fits
 * on a screen:
 *
 *  1. **Seal / unseal** the user's n8n API key with AES-256-GCM, so a Redis dump
 *     (or a stolen RDB file) yields ciphertext rather than working credentials.
 *  2. **Peppered hashing** of the bearer tokens and authorization codes we use
 *     as store keys, so the store never holds a value that is itself usable.
 *  3. **Constant-time comparison** for anything an attacker can guess against.
 *
 * The two derived keys come from one configured secret via HKDF, with distinct
 * `info` labels. Reusing a single key for both encryption and hashing is the
 * kind of shortcut that is fine until the day one of the two primitives leaks
 * something about the key.
 */

import {
  createCipheriv,
  createDecipheriv,
  createHmac,
  hkdfSync,
  randomBytes,
  timingSafeEqual,
} from 'node:crypto';

/** Version tag on every sealed value, so a future format change is detectable. */
const SEAL_VERSION = 'v1';
/** AES-GCM nonce length, in bytes. 96 bits is the size GCM is defined for. */
const IV_BYTES = 12;

export interface Keyring {
  /** AES-256-GCM key for sealing API keys. */
  readonly encryption: Buffer;
  /** HMAC-SHA-256 key used as the pepper when hashing store keys. */
  readonly hashing: Buffer;
}

/**
 * Derive the two working keys from the configured 32-byte root.
 *
 * HKDF with distinct `info` strings gives independent keys from one secret, so
 * rotating AUTH_STORAGE_ENCRYPTION_KEY rotates both at once — which is what
 * makes "rotate the key and restart" a complete revocation of every grant.
 */
export function deriveKeyring(root: Buffer): Keyring {
  const derive = (info: string): Buffer =>
    Buffer.from(hkdfSync('sha256', root, Buffer.alloc(0), `bg-n8n-mcp:${info}`, 32));
  return { encryption: derive('encryption'), hashing: derive('hashing') };
}

/**
 * Encrypt a secret for storage.
 *
 * Format: `v1.<iv>.<authTag>.<ciphertext>`, each part base64url. The version
 * prefix is authenticated as GCM additional data, so an attacker cannot
 * downgrade a value to a future weaker format by rewriting the prefix.
 */
export function seal(keyring: Keyring, plaintext: string): string {
  const iv = randomBytes(IV_BYTES);
  const cipher = createCipheriv('aes-256-gcm', keyring.encryption, iv);
  cipher.setAAD(Buffer.from(SEAL_VERSION, 'utf8'));
  const ciphertext = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  return [
    SEAL_VERSION,
    iv.toString('base64url'),
    cipher.getAuthTag().toString('base64url'),
    ciphertext.toString('base64url'),
  ].join('.');
}

/**
 * Decrypt a sealed secret.
 *
 * Returns `null` instead of throwing on any failure — wrong version, truncated
 * value, failed authentication tag, or a value written under a previous
 * AUTH_STORAGE_ENCRYPTION_KEY. All four mean the same thing operationally
 * ("this grant is no longer usable, re-authorize"), and a null keeps that on
 * the normal control-flow path rather than in an exception handler that might
 * log the ciphertext.
 */
export function unseal(keyring: Keyring, sealed: string): string | null {
  const parts = sealed.split('.');
  if (parts.length !== 4) return null;
  const [version, ivB64, tagB64, dataB64] = parts as [string, string, string, string];
  if (version !== SEAL_VERSION) return null;

  try {
    const decipher = createDecipheriv(
      'aes-256-gcm',
      keyring.encryption,
      Buffer.from(ivB64, 'base64url'),
    );
    decipher.setAAD(Buffer.from(SEAL_VERSION, 'utf8'));
    decipher.setAuthTag(Buffer.from(tagB64, 'base64url'));
    return Buffer.concat([
      decipher.update(Buffer.from(dataB64, 'base64url')),
      decipher.final(),
    ]).toString('utf8');
  } catch {
    return null;
  }
}

/**
 * Peppered hash, used to derive store keys from bearer tokens and codes.
 *
 * HMAC rather than a bare SHA-256: without the pepper, anyone who can read the
 * store can confirm a guessed token by hashing it offline. With it, they also
 * need AUTH_STORAGE_ENCRYPTION_KEY, which lives only in the process
 * environment.
 */
export function hashKey(keyring: Keyring, value: string): string {
  return createHmac('sha256', keyring.hashing).update(value).digest('base64url');
}

/**
 * 256 bits of entropy, base64url-encoded — the shape of every token,
 * authorization code and client id this server issues.
 */
export function randomToken(): string {
  return randomBytes(32).toString('base64url');
}

/**
 * Compare two strings without leaking their contents through timing.
 *
 * Both sides are hashed to a fixed 32 bytes first. `timingSafeEqual` throws on
 * a length mismatch, so comparing raw strings would leak the length through the
 * exception — and length alone is enough to distinguish a PKCE verifier from a
 * malformed one.
 */
export function safeEqual(a: string, b: string): boolean {
  const ha = createHmac('sha256', 'compare').update(a).digest();
  const hb = createHmac('sha256', 'compare').update(b).digest();
  return timingSafeEqual(ha, hb);
}

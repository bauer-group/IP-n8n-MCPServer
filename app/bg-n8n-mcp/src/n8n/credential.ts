/**
 * "Is this API key usable against this instance, right now?"
 *
 * Extracted from the consent handler because it is a distinct decision with its
 * own rules, and because those rules include one that is easy to get backwards:
 * **which failures count toward the brute-force lockout.**
 *
 * Only a credential verdict does. Counting an unreachable instance would lock a
 * user out for an outage that is not theirs and that retrying cannot fix — and
 * it would hand anyone who can take an n8n instance offline a way to lock out
 * everyone who uses it.
 *
 * The checks run cheapest-first:
 *   1. read the key itself      — no network at all
 *   2. resolve the instance     — one DNS lookup, and the SSRF guard
 *   3. probe the public API     — one HTTP request
 */

import type { Config } from '../config.js';
import { inspectApiKey } from './api-key.js';
import { probeApiKey } from './probe.js';
import { resolveTenant } from './tenant.js';

export type CredentialResult =
  | {
      ok: true;
      /** n8n user id from the key's JWT `sub`, when it is one. */
      n8nUserId: string | null;
      /** Canonical `https://host` origin the key was validated against. */
      origin: string;
    }
  | {
      ok: false;
      /** A key into the i18n error table. */
      code: string;
      /** Whether this failure should count toward the login lockout. */
      countsAsFailure: boolean;
      /** Operator-facing detail. Never shown to the user. */
      detail: string;
    };

export async function validateCredential(
  config: Config,
  hostname: string,
  apiKey: string,
): Promise<CredentialResult> {
  // 1 — decidable from the key alone.
  const inspection = inspectApiKey(apiKey);
  if (inspection.kind === 'invalid') {
    return {
      ok: false,
      code: inspection.reason,
      // An expired or wrong-audience key is a real credential problem, so it
      // counts — but it is also self-evident, so the user gets a message that
      // tells them exactly what to do rather than "rejected".
      countsAsFailure: true,
      detail: `key rejected offline: ${inspection.reason}`,
    };
  }

  // 2 — the first point where an outbound connection happens on a user's
  // behalf, which is where the SSRF guard belongs.
  const tenant = await resolveTenant(config, hostname);
  if (!tenant.ok) {
    return {
      ok: false,
      code: tenant.reason === 'unresolvable' ? 'unreachable' : 'unknown_instance',
      countsAsFailure: false,
      detail: `tenant rejected: ${tenant.reason}`,
    };
  }

  // 3 — ask the instance.
  const probe = await probeApiKey(tenant.origin, apiKey, {
    timeoutMs: config.N8N_PROBE_TIMEOUT_MS,
  });
  if (!probe.ok) {
    return {
      ok: false,
      code: probe.code,
      // 403 is deliberately NOT counted: the key is real, the account just
      // lacks a permission. Locking that user out sends them round a loop
      // that cannot succeed.
      countsAsFailure: probe.code === 'bad_key',
      detail: probe.detail,
    };
  }

  return {
    ok: true,
    n8nUserId: inspection.kind === 'n8n' ? inspection.claims.subject : null,
    origin: tenant.origin,
  };
}

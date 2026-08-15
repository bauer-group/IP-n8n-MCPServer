#!/usr/bin/env node
/**
 * Provision the E2E n8n instance and mint a real API key.
 *
 * Runs INSIDE the compose network, in a throwaway container from the gateway
 * image — which is the only place that both resolves `n8n.local` and trusts the
 * throwaway CA (`NODE_EXTRA_CA_CERTS`, read at process start, so it cannot be
 * done from the host process).
 *
 * Prints a single JSON object on stdout. Everything else goes to stderr, so the
 * caller can parse the last line without filtering.
 *
 * The point of doing this at all: the key the gateway later seals and forwards
 * is one n8n itself issued and will itself accept. A fixture would prove that
 * our own code round-trips a string; this proves the chain works.
 */

const BASE = process.env.N8N_BASE ?? 'https://n8n.local';

const OWNER = {
  email: process.env.N8N_OWNER_EMAIL ?? 'e2e@example.com',
  firstName: 'E2E',
  lastName: 'Runner',
  password: process.env.N8N_OWNER_PASSWORD ?? 'E2e-Test-Passw0rd!',
};

const note = (...args) => process.stderr.write(`${args.join(' ')}\n`);

async function call(path, { method = 'GET', body, cookie } = {}) {
  const response = await fetch(`${BASE}${path}`, {
    method,
    headers: {
      accept: 'application/json',
      ...(body ? { 'content-type': 'application/json' } : {}),
      ...(cookie ? { cookie } : {}),
    },
    ...(body ? { body: JSON.stringify(body) } : {}),
  });
  const text = await response.text();
  let parsed = null;
  try {
    parsed = JSON.parse(text);
  } catch {
    /* left null; `text` is reported instead */
  }
  return {
    status: response.status,
    body: parsed,
    text,
    setCookie: response.headers.getSetCookie?.() ?? [],
  };
}

/** n8n takes a while to finish migrations after its port opens. */
async function waitForN8n() {
  for (let attempt = 0; attempt < 60; attempt += 1) {
    try {
      const health = await call('/healthz');
      if (health.status === 200) return true;
    } catch (error) {
      if (attempt === 0) note('waiting for n8n:', String(error).slice(0, 100));
    }
    await new Promise((r) => setTimeout(r, 2000));
  }
  return false;
}

async function main() {
  if (!(await waitForN8n())) throw new Error('n8n never became healthy');
  note('n8n is up');

  // ── Owner setup ───────────────────────────────────────────────────────────
  const setup = await call('/rest/owner/setup', { method: 'POST', body: OWNER });
  note(`owner setup → ${setup.status}`);
  // 400 means the owner already exists, which is fine on a re-run.
  if (![200, 201, 400].includes(setup.status)) {
    throw new Error(`owner setup failed: ${setup.status} ${setup.text.slice(0, 200)}`);
  }

  // ── Login ─────────────────────────────────────────────────────────────────
  // The login body field was renamed across n8n versions; try both rather than
  // pinning the test to one release.
  let cookie = null;
  for (const body of [
    { emailOrLdapLoginId: OWNER.email, password: OWNER.password },
    { email: OWNER.email, password: OWNER.password },
  ]) {
    const login = await call('/rest/login', { method: 'POST', body });
    note(`login (${Object.keys(body)[0]}) → ${login.status}`);
    if (login.status === 200) {
      cookie = login.setCookie.map((c) => c.split(';')[0]).join('; ');
      break;
    }
  }
  // The setup call itself may already have authenticated us.
  if (!cookie && setup.setCookie.length) {
    cookie = setup.setCookie.map((c) => c.split(';')[0]).join('; ');
    note('using the cookie from owner setup');
  }
  if (!cookie) throw new Error('could not authenticate against n8n');

  // ── API key ───────────────────────────────────────────────────────────────
  // Newer n8n requires an explicit scope list and publishes the valid values;
  // older versions reject the field entirely. Ask first, then try with and
  // without.
  let scopes = null;
  const scopeResponse = await call('/rest/api-keys/scopes', { cookie });
  if (scopeResponse.status === 200 && Array.isArray(scopeResponse.body?.data)) {
    scopes = scopeResponse.body.data;
    note(`instance publishes ${scopes.length} API-key scopes`);
  }

  // Endpoint and body shape have both moved across n8n releases. Try the
  // current one first, then the older ones, rather than pinning the test to a
  // single version.
  const attempts = [
    ...(scopes ? [{ path: '/rest/api-keys', body: { label: `e2e-${Date.now()}`, expiresAt: null, scopes } }] : []),
    { path: '/rest/api-keys', body: { label: `e2e-${Date.now()}`, expiresAt: null } },
    { path: '/rest/me/api-key', body: {} },
  ];

  let rawKey = null;
  for (const { path, body } of attempts) {
    const created = await call(path, { method: 'POST', body, cookie });
    note(`create api key ${path}${body.scopes ? ' (scoped)' : ''} → ${created.status}`);
    if (created.status !== 200 && created.status !== 201) {
      note(`  ${created.text.slice(0, 200)}`);
      continue;
    }
    const data = created.body?.data ?? created.body ?? {};
    // `rawApiKey` is the plaintext; `apiKey` is redacted on newer releases, so
    // only accept it when it actually looks like a JWT.
    const candidate =
      data.rawApiKey ??
      (typeof data.apiKey === 'string' && data.apiKey.split('.').length === 3
        ? data.apiKey
        : null);
    if (candidate) {
      rawKey = candidate;
      break;
    }
    note(`  response carried no plaintext key: ${created.text.slice(0, 200)}`);
  }

  if (!rawKey) throw new Error('n8n did not return a usable API key');

  const claims = JSON.parse(Buffer.from(rawKey.split('.')[1], 'base64url').toString());
  note(`key issued: iss=${claims.iss} aud=${claims.aud} sub=${String(claims.sub).slice(0, 8)}…`);

  // Prove the key actually works against the public API before handing it over,
  // so a failure later is unambiguously the gateway's and not n8n's.
  const probe = await fetch(`${BASE}/api/v1/workflows?limit=1`, {
    headers: { 'X-N8N-API-KEY': rawKey, accept: 'application/json' },
  });
  note(`public API probe → ${probe.status}`);

  process.stdout.write(
    `${JSON.stringify({ apiKey: rawKey, claims, publicApiStatus: probe.status })}\n`,
  );
}

try {
  await main();
} catch (error) {
  note(`PROVISION FAILED: ${error instanceof Error ? error.message : String(error)}`);
  process.stdout.write(`${JSON.stringify({ error: String(error) })}\n`);
  process.exit(1);
}

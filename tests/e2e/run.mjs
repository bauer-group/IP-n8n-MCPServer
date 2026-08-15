#!/usr/bin/env node
/**
 * End-to-end test.
 *
 * Brings up a real stack — genuine n8n, the genuine upstream n8n-mcp image,
 * Redis, TLS, and the gateway built from source — then plays the part of an MCP
 * client: it registers, runs the OAuth 2.1 flow, submits a REAL n8n API key it
 * just created through n8n's own REST API, and drives actual MCP tool calls
 * through the whole chain.
 *
 * Nothing is mocked. The unit suite already covers the branches; this answers
 * the different question of whether the pieces fit together — which is exactly
 * where a gateway like this fails in practice.
 *
 * Usage
 * -----
 *   node tests/e2e/run.mjs              # up, test, down
 *   node tests/e2e/run.mjs --keep       # leave the stack running afterwards
 *   node tests/e2e/run.mjs --no-build   # reuse the existing gateway image
 *   node tests/e2e/run.mjs --logs       # dump container logs at the end
 *
 * Exit code 0 = every check passed.
 */

import { execFileSync, spawnSync } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseArgs } from 'node:util';

const HERE = dirname(fileURLToPath(import.meta.url));
const CERTS = join(HERE, 'certs');
const COMPOSE = join(HERE, 'docker-compose.e2e.yml');

const { values: opts } = parseArgs({
  options: {
    keep: { type: 'boolean', default: false },
    'no-build': { type: 'boolean', default: false },
    logs: { type: 'boolean', default: false },
    port: { type: 'string', default: '18080' },
  },
});

const GATEWAY = `http://localhost:${opts.port}`;
const TENANT = 'n8n.local';
const RESOURCE = `${GATEWAY}/i/${TENANT}/mcp`;
const REDIRECT = 'https://claude.ai/api/mcp/auth_callback';

const N8N_OWNER = {
  email: 'e2e@example.com',
  firstName: 'E2E',
  lastName: 'Runner',
  password: 'E2e-Test-Passw0rd!',
};

const env = {
  ...process.env,
  E2E_UPSTREAM_TOKEN: randomBytes(32).toString('base64'),
  E2E_STORAGE_KEY: randomBytes(32).toString('base64'),
  E2E_GATEWAY_PORT: opts.port,
};

// ─── output ──────────────────────────────────────────────────────────────────

let step = 0;
let failures = 0;
const t0 = Date.now();

const since = () => `${((Date.now() - t0) / 1000).toFixed(1)}s`;
const heading = (text) => process.stdout.write(`\n\x1b[1m── ${text} ${'─'.repeat(Math.max(0, 60 - text.length))}\x1b[0m\n`);
const info = (text) => process.stdout.write(`   ${text}\n`);

function check(label, condition, detail = '') {
  step += 1;
  if (condition) {
    process.stdout.write(`  \x1b[32m✓\x1b[0m ${label}${detail ? `  \x1b[2m${detail}\x1b[0m` : ''}\n`);
  } else {
    failures += 1;
    process.stdout.write(`  \x1b[31m✗ ${label}\x1b[0m${detail ? `  ${detail}` : ''}\n`);
  }
}

// ─── shell helpers ───────────────────────────────────────────────────────────

function compose(args, { capture = false, allowFail = false } = {}) {
  const result = spawnSync('docker', ['compose', '-f', COMPOSE, ...args], {
    cwd: HERE,
    env,
    encoding: 'utf8',
    stdio: capture ? 'pipe' : 'inherit',
    maxBuffer: 64 * 1024 * 1024,
  });
  if (!allowFail && result.status !== 0) {
    throw new Error(`docker compose ${args.join(' ')} failed (${result.status})\n${result.stderr ?? ''}`);
  }
  return result.stdout ?? '';
}

const openssl = (args) => execFileSync('openssl', args, { cwd: CERTS, stdio: 'pipe' });

// ─── certificates ────────────────────────────────────────────────────────────

/**
 * A throwaway CA and a leaf for `n8n.local`.
 *
 * Regenerated on every run and gitignored. The gateway only ever speaks HTTPS
 * to an n8n instance, so a plain-HTTP shortcut here would test a code path
 * production never takes.
 */
function makeCerts() {
  rmSync(CERTS, { recursive: true, force: true });
  mkdirSync(CERTS, { recursive: true });

  openssl(['req', '-x509', '-newkey', 'rsa:2048', '-days', '2', '-nodes',
    '-keyout', 'ca.key', '-out', 'ca.crt', '-subj', '/CN=bg-n8n-mcp-e2e-ca']);

  openssl(['req', '-newkey', 'rsa:2048', '-nodes',
    '-keyout', 'server.key', '-out', 'server.csr', '-subj', '/CN=n8n.local']);

  writeFileSync(
    join(CERTS, 'ext.cnf'),
    'subjectAltName=DNS:n8n.local,DNS:localhost,IP:127.0.0.1\nextendedKeyUsage=serverAuth\n',
  );

  openssl(['x509', '-req', '-in', 'server.csr', '-CA', 'ca.crt', '-CAkey', 'ca.key',
    '-CAcreateserial', '-out', 'server.crt', '-days', '2', '-extfile', 'ext.cnf']);

  return readFileSync(join(CERTS, 'ca.crt'), 'utf8');
}

// ─── HTTP helpers ────────────────────────────────────────────────────────────

const form = (obj) => new URLSearchParams(obj);

async function json(response) {
  const text = await response.text();
  try {
    return JSON.parse(text);
  } catch {
    return { _raw: text.slice(0, 400) };
  }
}

// ─── n8n setup, through n8n's own REST API ───────────────────────────────────

/**
 * Create the owner account and mint a real API key.
 *
 * This is what makes the test end-to-end rather than end-to-almost-end: the key
 * the gateway seals and forwards is one n8n actually issued and will actually
 * accept, signed with the instance's own secret — not a fixture.
 */
async function provisionN8n() {
  // Runs inside the compose network, from the gateway image — the only place
  // that both resolves `n8n.local` and trusts the throwaway CA.
  // NODE_EXTRA_CA_CERTS is read at process start, so this cannot be done from
  // the host process.
  const result = spawnSync(
    'docker',
    ['compose', '-f', COMPOSE, 'run', '--rm', '--no-deps', '-T',
      '-e', `N8N_OWNER_EMAIL=${N8N_OWNER.email}`,
      '-e', `N8N_OWNER_PASSWORD=${N8N_OWNER.password}`,
      '--entrypoint', 'node', 'gateway', '/e2e/provision-n8n.mjs'],
    { cwd: HERE, env, encoding: 'utf8', maxBuffer: 32 * 1024 * 1024 },
  );

  const stdout = (result.stdout ?? '').trim();
  const diagnostics = (result.stderr ?? '').trim();
  const lastLine = stdout.split('\n').filter(Boolean).at(-1) ?? '';
  let payload = {};
  try {
    payload = JSON.parse(lastLine);
  } catch {
    payload = { error: `unparseable provisioning output: ${lastLine.slice(0, 200)}` };
  }
  return { payload, diagnostics };
}

// ─── main ────────────────────────────────────────────────────────────────────

async function main() {
  heading('Certificates');
  const caCert = makeCerts();
  check('throwaway CA and n8n.local leaf generated', caCert.includes('BEGIN CERTIFICATE'));

  heading('Stack');
  info('docker compose up — this builds the gateway and runs its test gate');
  compose(['down', '-v', '--remove-orphans'], { capture: true, allowFail: true });
  compose(['up', '-d', ...(opts['no-build'] ? [] : ['--build']), '--wait'].filter(Boolean));
  check('all services healthy', true, since());

  heading('Gateway is up');
  const health = await (await fetch(`${GATEWAY}/healthz`)).json();
  check('GET /healthz', health.status === 'ok', JSON.stringify(health));
  const ready = await (await fetch(`${GATEWAY}/readyz`)).json();
  check('GET /readyz reports the store up', ready.store === 'up', JSON.stringify(ready));

  heading('n8n provisioning (real API key)');
  const { payload, diagnostics } = await provisionN8n();
  const apiKey = payload.apiKey ?? null;
  if (!apiKey) info(diagnostics.split('\n').slice(-12).join('\n   '));
  check('n8n issued an API key', Boolean(apiKey),
    apiKey ? `${apiKey.slice(0, 24)}…` : (payload.error ?? '').slice(0, 200));
  if (!apiKey) throw new Error('cannot continue without a real API key');

  const claims = payload.claims ?? {};
  check('it is an n8n public-api JWT', claims.iss === 'n8n' && claims.aud === 'public-api',
    `iss=${claims.iss} aud=${claims.aud} sub=${String(claims.sub).slice(0, 8)}…`);
  check('the key works against n8n’s public API', payload.publicApiStatus === 200,
    `HTTP ${payload.publicApiStatus}`);

  // ── Discovery ─────────────────────────────────────────────────────────────
  heading('Discovery');
  const challengeResponse = await fetch(RESOURCE, { method: 'POST', body: '{}' });
  const wwwAuth = challengeResponse.headers.get('www-authenticate') ?? '';
  check('unauthenticated MCP call is 401', challengeResponse.status === 401);
  const prmUrl = /resource_metadata="([^"]+)"/.exec(wwwAuth)?.[1];
  check('challenge points at protected-resource metadata', Boolean(prmUrl), prmUrl);

  const prm = await (await fetch(prmUrl)).json();
  check('PRM resource is byte-identical to the connector URL', prm.resource === RESOURCE,
    `${prm.resource}`);
  check('PRM names exactly one authorization server', prm.authorization_servers?.length === 1);

  const asMeta = await (await fetch(`${GATEWAY}/.well-known/oauth-authorization-server`)).json();
  check('AS advertises S256', asMeta.code_challenge_methods_supported?.includes('S256'));
  check('AS advertises the iss parameter', asMeta.authorization_response_iss_parameter_supported === true);
  check('AS advertises CIMD support', asMeta.client_id_metadata_document_supported === true);

  // ── Registration ──────────────────────────────────────────────────────────
  heading('Client registration');
  const registration = await json(await fetch(`${GATEWAY}/register`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      client_name: 'Claude', redirect_uris: [REDIRECT], token_endpoint_auth_method: 'none',
    }),
  }));
  check('DCR returns a public client', Boolean(registration.client_id) && !registration.client_secret,
    registration.client_id?.slice(0, 20));

  // ── Authorize + consent ───────────────────────────────────────────────────
  heading('Authorization');
  const verifier = randomBytes(32).toString('base64url');
  const challenge = createHash('sha256').update(verifier).digest('base64url');
  const authorizeUrl = `${GATEWAY}/authorize?${new URLSearchParams({
    response_type: 'code',
    client_id: registration.client_id,
    redirect_uri: REDIRECT,
    state: 'e2e-state',
    code_challenge: challenge,
    code_challenge_method: 'S256',
    resource: RESOURCE,
  })}`;

  const consentHtml = await (await fetch(authorizeUrl)).text();
  const requestId = /name="request_id" value="([^"]+)"/.exec(consentHtml)?.[1];
  check('consent screen rendered', Boolean(requestId));
  check('consent screen names the target instance', consentHtml.includes(TENANT));
  check('consent screen asks for username and key',
    consentHtml.includes('name="username"') && consentHtml.includes('name="api_key"'));
  check('pending request is not round-tripped through the form', !consentHtml.includes(REDIRECT));

  // A wrong key first, to prove the probe is real.
  const wrongKey = await fetch(`${GATEWAY}/authorize`, {
    method: 'POST', redirect: 'manual',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: form({ request_id: requestId, username: 'e2e@example.com', api_key: 'definitely-not-valid' }),
  });
  check('a wrong API key is rejected by the real n8n', wrongKey.status === 400,
    `HTTP ${wrongKey.status}`);

  // Now the real one.
  const consent = await fetch(`${GATEWAY}/authorize`, {
    method: 'POST', redirect: 'manual',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: form({ request_id: requestId, username: 'e2e@example.com', api_key: apiKey }),
  });
  // 303 specifically: a 302 or 307 preserves POST, Claude's callback answers
  // 405, and the token exchange never happens.
  check('consent with the real key redirects 303 (not 302/307)', consent.status === 303,
    `HTTP ${consent.status}`);

  const back = new URL(consent.headers.get('location'));
  const code = back.searchParams.get('code');
  check('authorization code returned', Boolean(code));
  check('state is echoed', back.searchParams.get('state') === 'e2e-state');
  check('RFC 9207 iss is present', back.searchParams.get('iss') === GATEWAY);

  // ── Token ─────────────────────────────────────────────────────────────────
  heading('Token');
  const tokens = await json(await fetch(`${GATEWAY}/token`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: form({
      grant_type: 'authorization_code', code, code_verifier: verifier,
      client_id: registration.client_id, redirect_uri: REDIRECT,
    }),
  }));
  check('access + refresh token issued', Boolean(tokens.access_token && tokens.refresh_token),
    `expires_in=${tokens.expires_in}`);

  const replay = await fetch(`${GATEWAY}/token`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: form({
      grant_type: 'authorization_code', code, code_verifier: verifier,
      client_id: registration.client_id, redirect_uri: REDIRECT,
    }),
  });
  check('the code cannot be replayed', replay.status === 400);

  const auth = { authorization: `Bearer ${tokens.access_token}` };

  // ── MCP through the whole chain ───────────────────────────────────────────
  heading('MCP over the full chain');
  // Every MCP request carries BOTH content types in Accept. This is not
  // optional politeness: Streamable HTTP requires it, and a request that omits
  // it errors the server-side transport — which closes the session, so the
  // NEXT call fails with "Session not found or expired" and the real cause is
  // one request earlier. (Diagnosed with probe-backend.mjs, which talks to the
  // backend directly and got it right by accident.)
  const ACCEPT = 'application/json, text/event-stream';

  const rpc = async (method, params, extraHeaders = {}) => {
    const response = await fetch(RESOURCE, {
      method: 'POST',
      headers: {
        ...auth, ...extraHeaders,
        'content-type': 'application/json',
        accept: ACCEPT,
      },
      body: JSON.stringify({ jsonrpc: '2.0', id: Date.now(), method, params }),
    });
    const text = await response.text();
    // The backend answers initialize as SSE; unwrap a `data:` frame if present.
    const payload = text.startsWith('event:') || text.startsWith('data:')
      ? text.split('\n').filter((l) => l.startsWith('data:')).map((l) => l.slice(5).trim()).join('')
      : text;
    let parsed;
    try { parsed = JSON.parse(payload); } catch { parsed = { _raw: text.slice(0, 300) }; }
    return { response, body: parsed };
  };

  const init = await rpc('initialize', {
    protocolVersion: '2025-06-18',
    capabilities: {},
    clientInfo: { name: 'bg-n8n-mcp-e2e', version: '1' },
  });
  const sessionId = init.response.headers.get('mcp-session-id');
  check('initialize succeeded', init.response.ok && Boolean(init.body.result),
    `server=${init.body.result?.serverInfo?.name} v${init.body.result?.serverInfo?.version}`);
  check('Mcp-Session-Id came back through the proxy', Boolean(sessionId), sessionId?.slice(0, 24));

  const sess = sessionId ? { 'mcp-session-id': sessionId } : {};
  const initialized = await fetch(RESOURCE, {
    method: 'POST',
    headers: { ...auth, ...sess, 'content-type': 'application/json', accept: ACCEPT },
    body: JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' }),
  });
  await initialized.text();
  // An accepted notification is 202 with no body.
  check('notifications/initialized accepted', initialized.status === 202,
    `HTTP ${initialized.status}`);

  const tools = await rpc('tools/list', {}, sess);
  const toolNames = tools.body.result?.tools?.map((t) => t.name) ?? [];
  check('tools/list returned a tool surface', toolNames.length > 0, `${toolNames.length} tools`);
  check('n8n management tools are present (multi-tenant credentials reached the backend)',
    toolNames.some((n) => n.startsWith('n8n_')),
    toolNames.filter((n) => n.startsWith('n8n_')).slice(0, 3).join(', '));

  // The real prize: a tool call that makes the backend use the user's key
  // against the real n8n.
  const listWorkflows = await rpc('tools/call',
    { name: 'n8n_list_workflows', arguments: { limit: 5 } }, sess);
  const callResult = listWorkflows.body.result;
  const callText = JSON.stringify(callResult ?? listWorkflows.body).slice(0, 300);
  check('n8n_list_workflows executed against the real n8n',
    Boolean(callResult) && callResult.isError !== true, callText);

  const health2 = await rpc('tools/call', { name: 'n8n_health_check', arguments: {} }, sess);
  check('n8n_health_check reached the instance',
    Boolean(health2.body.result) && health2.body.result.isError !== true,
    JSON.stringify(health2.body.result ?? health2.body).slice(0, 200));

  // ── Security properties, live ─────────────────────────────────────────────
  heading('Security properties');

  const noToken = await fetch(RESOURCE, { method: 'POST', body: '{}' });
  check('no token → 401 with a challenge', noToken.status === 401 &&
    (noToken.headers.get('www-authenticate') ?? '').includes('resource_metadata'));

  const unknownTenant = await fetch(`${GATEWAY}/i/evil.example/mcp`, { method: 'POST', headers: auth, body: '{}' });
  check('a host outside the allowlist → 404', unknownTenant.status === 404);

  // The interesting outcome is not that this is refused — it is that it
  // SUCCEEDS, unchanged, because the smuggled headers were stripped and
  // replaced before the request ever left the gateway. Had they survived, the
  // backend would have been pointed at evil.example with an attacker key and
  // answered an error instead.
  const smuggle = await rpc('tools/list', {}, {
    ...sess,
    'x-n8n-url': 'https://evil.example',
    'x-n8n-key': 'attacker-key',
    'x-instance-id': 'spoofed',
  });
  check('smuggled x-n8n-* headers are stripped, request still serves the right tenant',
    smuggle.response.status === 200 && Array.isArray(smuggle.body.result?.tools),
    `HTTP ${smuggle.response.status}, ${smuggle.body.result?.tools?.length ?? 0} tools`);

  const caseMutated = await fetch(`${GATEWAY}/I/${TENANT.toUpperCase()}/MCP`, {
    method: 'POST', headers: { ...auth, 'content-type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'ping', params: {} }),
  });
  check('a title-cased path still routes', caseMutated.status !== 404, `HTTP ${caseMutated.status}`);

  // ── Refresh + revocation ──────────────────────────────────────────────────
  heading('Refresh and revocation');
  const refreshed = await json(await fetch(`${GATEWAY}/token`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: form({ grant_type: 'refresh_token', refresh_token: tokens.refresh_token }),
  }));
  check('refresh re-validated the key against the real n8n and rotated',
    Boolean(refreshed.access_token) && refreshed.refresh_token !== tokens.refresh_token);

  const oldRefresh = await fetch(`${GATEWAY}/token`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: form({ grant_type: 'refresh_token', refresh_token: tokens.refresh_token }),
  });
  check('the rotated-out refresh token is dead', oldRefresh.status === 400);

  const revoke = await fetch(`${GATEWAY}/revoke`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: form({ token: refreshed.access_token }),
  });
  check('revocation returns 200', revoke.status === 200);

  const afterRevoke = await fetch(RESOURCE, {
    method: 'POST',
    headers: { authorization: `Bearer ${refreshed.access_token}`, 'content-type': 'application/json' },
    body: '{}',
  });
  check('the whole grant is gone — every token for it stops working',
    afterRevoke.status === 401, `HTTP ${afterRevoke.status}`);

  const alsoDead = await fetch(RESOURCE, { method: 'POST', headers: auth, body: '{}' });
  check('the ORIGINAL access token died with the grant too', alsoDead.status === 401,
    `HTTP ${alsoDead.status}`);
}

// ─── run ─────────────────────────────────────────────────────────────────────

let exitCode = 0;
try {
  await main();
} catch (error) {
  failures += 1;
  process.stdout.write(`\n\x1b[31mFATAL: ${error instanceof Error ? error.message : String(error)}\x1b[0m\n`);
} finally {
  if (opts.logs || failures) {
    heading('Container logs (tail)');
    process.stdout.write(compose(['logs', '--tail', '60'], { capture: true, allowFail: true }));
  }
  if (!opts.keep) {
    heading('Teardown');
    compose(['down', '-v', '--remove-orphans'], { capture: true, allowFail: true });
    if (existsSync(CERTS)) rmSync(CERTS, { recursive: true, force: true });
    info('stack removed');
  } else {
    info(`stack left running — ${GATEWAY}`);
  }

  heading('Result');
  exitCode = failures ? 1 : 0;
  const summary = failures
    ? `\x1b[31m${failures} of ${step} checks FAILED\x1b[0m`
    : `\x1b[32mall ${step} checks passed\x1b[0m`;
  process.stdout.write(`  ${summary}  (${since()})\n\n`);
}

process.exit(exitCode);

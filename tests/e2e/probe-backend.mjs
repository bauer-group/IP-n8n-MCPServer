#!/usr/bin/env node
/**
 * Diagnostic: talk to n8n-mcp DIRECTLY, bypassing the gateway.
 *
 * Answers one question — when an MCP session does not survive from
 * `initialize` to `tools/list`, is that the gateway's doing or the backend's?
 * Run it against the same backend the E2E stack uses, with the same tenant
 * headers the gateway would inject.
 *
 *   docker compose -f tests/e2e/docker-compose.e2e.yml run --rm --no-deps -T \
 *     -e UPSTREAM=... -e APIKEY=... --entrypoint node gateway /e2e/probe-backend.mjs
 */

const BACKEND = process.env.BACKEND ?? 'http://n8n-mcp-backend:3000/mcp';
const UPSTREAM = process.env.UPSTREAM ?? '';
const APIKEY = process.env.APIKEY ?? '';
const INSTANCE = process.env.INSTANCE ?? 'probe-instance-id';
const N8N_URL = process.env.N8N_URL ?? 'https://n8n.local';

const base = {
  authorization: `Bearer ${UPSTREAM}`,
  'content-type': 'application/json',
  accept: 'application/json, text/event-stream',
  'x-n8n-url': N8N_URL,
  'x-n8n-key': APIKEY,
  'x-instance-id': INSTANCE,
};

function unwrap(text) {
  if (!text.startsWith('event:') && !text.startsWith('data:')) return text;
  return text
    .split('\n')
    .filter((l) => l.startsWith('data:'))
    .map((l) => l.slice(5).trim())
    .join('');
}

async function rpc(label, body, extra = {}) {
  const response = await fetch(BACKEND, {
    method: 'POST',
    headers: { ...base, ...extra },
    body: JSON.stringify(body),
  });
  const text = await response.text();
  const payload = unwrap(text);
  console.log(
    `${label}: HTTP ${response.status}  session=${response.headers.get('mcp-session-id') ?? '-'}`,
  );
  console.log(`   ${payload.slice(0, 260)}`);
  return { response, payload };
}

const init = await rpc('initialize            ', {
  jsonrpc: '2.0',
  id: 1,
  method: 'initialize',
  params: {
    protocolVersion: '2025-06-18',
    capabilities: {},
    clientInfo: { name: 'probe', version: '1' },
  },
});

const sid = init.response.headers.get('mcp-session-id');
const sess = sid ? { 'mcp-session-id': sid } : {};

// Variant A: tools/list immediately, no initialized notification.
await rpc('tools/list (no notify)', { jsonrpc: '2.0', id: 2, method: 'tools/list', params: {} }, sess);

// Variant B: send notifications/initialized first, then tools/list.
const notify = await fetch(BACKEND, {
  method: 'POST',
  headers: { ...base, ...sess },
  body: JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' }),
});
console.log(`notifications/initialized: HTTP ${notify.status}`);
await notify.text();

await rpc('tools/list (after notify)', { jsonrpc: '2.0', id: 3, method: 'tools/list', params: {} }, sess);

// Variant C: a fresh initialize, then immediately tools/list on the SAME
// connection semantics — to see whether the first session was evicted.
const init2 = await rpc('initialize #2         ', {
  jsonrpc: '2.0',
  id: 4,
  method: 'initialize',
  params: {
    protocolVersion: '2025-06-18',
    capabilities: {},
    clientInfo: { name: 'probe', version: '1' },
  },
});
const sid2 = init2.response.headers.get('mcp-session-id');
console.log(`same session id as first? ${sid === sid2}`);
await rpc(
  'tools/list (session #2)',
  { jsonrpc: '2.0', id: 5, method: 'tools/list', params: {} },
  sid2 ? { 'mcp-session-id': sid2 } : {},
);

// Variant D: does the FIRST session still work after the second initialize?
await rpc('tools/list (session #1 again)', { jsonrpc: '2.0', id: 6, method: 'tools/list', params: {} }, sess);

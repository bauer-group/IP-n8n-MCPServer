/**
 * Guards on the consent POST that are invisible in a happy-path flow.
 *
 * Two distinct properties, both regression tests for real defects:
 *
 *   1. One consent yields at most one grant. Validating a key takes seconds
 *      against a remote instance, and the form ships no script to disable its
 *      own submit button (the page runs under `script-src 'none'`), so a
 *      double click during that window used to mint two long-lived grants —
 *      two sealed copies of the same API key, of which the user ever learns
 *      about one.
 *
 *   2. Submissions are bounded per address. The brute-force lockout counts
 *      only verdicts on a key, deliberately, so that an outage never locks out
 *      the people depending on it. Every other outcome went uncounted, and
 *      each one still buys the caller an outbound probe.
 */

import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import {
  BASE_URL,
  createHarness,
  type FetchStub,
  type Harness,
  makeN8nKey,
  n8nWorkflowsOk,
  pkcePair,
  stubFetch,
  TENANT,
} from './helpers.js';

const RESOURCE = `${BASE_URL}/i/${TENANT}/mcp`;
const REDIRECT = 'https://claude.ai/api/mcp/auth_callback';

let harness: Harness;
let fetchStub: FetchStub;

afterEach(() => {
  fetchStub.restore();
});

async function registerClaude(): Promise<string> {
  const response = await harness.fetch('/register', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      client_name: 'Claude',
      redirect_uris: [REDIRECT],
      token_endpoint_auth_method: 'none',
      grant_types: ['authorization_code', 'refresh_token'],
      response_types: ['code'],
    }),
  });
  expect(response.status).toBe(201);
  return ((await response.json()) as { client_id: string }).client_id;
}

/** Walk /authorize up to the rendered form and hand back its request_id. */
async function openConsentForm(): Promise<string> {
  const clientId = await registerClaude();
  const { challenge } = await pkcePair();
  const page = await harness.fetch(
    `/authorize?response_type=code&client_id=${clientId}&redirect_uri=${encodeURIComponent(REDIRECT)}` +
      `&code_challenge=${challenge}&code_challenge_method=S256&resource=${encodeURIComponent(RESOURCE)}`,
  );
  return /name="request_id" value="([^"]+)"/.exec(await page.text())?.[1] as string;
}

function submit(requestId: string, apiKey: string, username = 'kb'): Promise<Response> {
  return harness.fetch('/authorize', {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ request_id: requestId, username, api_key: apiKey }),
  });
}

describe('one consent, one grant', () => {
  beforeEach(() => {
    harness = createHarness();
  });

  it('lets only one of two concurrent submissions through', async () => {
    // A probe slow enough that the second submission arrives while the first
    // is still waiting on n8n — the exact window a double click lands in.
    fetchStub = stubFetch(async () => {
      await new Promise((resolve) => setTimeout(resolve, 25));
      return n8nWorkflowsOk();
    });

    const requestId = await openConsentForm();
    const key = makeN8nKey();

    const [first, second] = await Promise.all([submit(requestId, key), submit(requestId, key)]);

    const statuses = [first.status, second.status].sort();
    expect(statuses).toEqual([303, 400]);

    // The decisive assertion: the loser never reached the probe, so it never
    // reached createGrant either. One consent produced one sealed key.
    expect(fetchStub.calls).toHaveLength(1);

    const loser = first.status === 400 ? first : second;
    // The error page, not the form: there is nothing left to retry against.
    const body = await loser.text();
    expect(body).toMatch(/zu lange gedauert|took too long/i);
    expect(body).not.toContain('name="request_id"');
  });

  it('still lets a user retry after getting the key wrong', async () => {
    // The claim is put back on every failed attempt — without that, the fix
    // for the double submit would turn every typo into a dead end.
    fetchStub = stubFetch(async (request) =>
      request.headers.get('x-n8n-api-key') === 'wrong'
        ? new Response('', { status: 401 })
        : n8nWorkflowsOk(),
    );

    const requestId = await openConsentForm();

    const rejected = await submit(requestId, 'wrong');
    expect(rejected.status).toBe(400);
    expect(await rejected.text()).toContain('name="request_id"');

    const accepted = await submit(requestId, makeN8nKey());
    expect(accepted.status).toBe(303);
  });

  it('does not resurrect a request that was already spent', async () => {
    fetchStub = stubFetch(async () => n8nWorkflowsOk());

    const requestId = await openConsentForm();
    expect((await submit(requestId, makeN8nKey())).status).toBe(303);

    // Re-posting a consumed request_id — a back button, a replayed form — must
    // not produce a second grant for the same consent.
    const replay = await submit(requestId, makeN8nKey());
    expect(await replay.text()).not.toContain('name="request_id"');
  });

  it('tells a resubmitted success apart from an expired request', async () => {
    // Exactly the production sequence that sent everyone hunting for a failure
    // that had not happened: a 303, then eleven seconds later a second submit
    // of the same form. Reporting that as "sign-in took too long, reconnect in
    // your AI client" is false — the user is already connected.
    fetchStub = stubFetch(async () => n8nWorkflowsOk());

    const requestId = await openConsentForm();
    expect((await submit(requestId, makeN8nKey())).status).toBe(303);

    const again = await submit(requestId, makeN8nKey());
    const body = await again.text();
    expect(body).toMatch(/bereits abgeschlossen|already complete/i);
    expect(body).not.toMatch(/zu lange gedauert|took too long/i);
    // Not an error: nothing went wrong, so this must not read as a failure.
    expect(again.status).toBe(200);
  });

  it('still reports a genuinely unknown request as expired', async () => {
    fetchStub = stubFetch(async () => n8nWorkflowsOk());
    await openConsentForm();

    const unknown = await submit('never-issued-handle', makeN8nKey());
    expect(unknown.status).toBe(400);
    expect(await unknown.text()).toMatch(/zu lange gedauert|took too long/i);
  });
});

describe('an unexpected failure does not eat the request', () => {
  beforeEach(() => {
    harness = createHarness();
    fetchStub = stubFetch(async () => n8nWorkflowsOk());
  });

  it('puts the claim back when the handler throws, so the user can retry', async () => {
    // Before the consent request was claimed rather than read, a throw left
    // the record in place and the user simply tried again. The claim removed
    // that property unless something restores it, and the cost of losing it
    // is the whole flow: the form's handle no longer resolves, so every later
    // submit reports an expired session and the only way out is to start over
    // in the AI client.
    const store = harness.store as unknown as { createGrant: unknown };
    const realCreateGrant = store.createGrant;
    store.createGrant = () => {
      throw new Error('redis went away mid-consent');
    };

    const requestId = await openConsentForm();
    const failed = await submit(requestId, makeN8nKey());
    expect(failed.status).toBe(500);

    store.createGrant = realCreateGrant;

    // The decisive part: the same handle still works.
    const retried = await submit(requestId, makeN8nKey());
    expect(retried.status).toBe(303);
  });

  it('keeps a spent request spent when the failure comes after the grant', async () => {
    // The mirror image, and the reason `spent` flips at createGrant rather
    // than at the redirect. Restoring here would let the user consent twice
    // and mint a second grant holding a second sealed copy of one API key.
    const store = harness.store as unknown as { putCode: unknown };
    store.putCode = () => {
      throw new Error('failed after the grant existed');
    };

    const requestId = await openConsentForm();
    expect((await submit(requestId, makeN8nKey())).status).toBe(500);

    const replay = await submit(requestId, makeN8nKey());
    expect(replay.status).toBe(400);
    expect(await replay.text()).toMatch(/zu lange gedauert|took too long/i);
  });
});

describe('submission volume gate', () => {
  beforeEach(() => {
    // LOGIN_MAX 1 puts the submission ceiling at 1 * 6 = 6.
    harness = createHarness({ RATE_LIMITER_LOGIN_MAX: '1' });
    fetchStub = stubFetch(async () => n8nWorkflowsOk());
  });

  it('stops a caller who never produces a verdict from probing forever', async () => {
    const requestId = await openConsentForm();

    // An empty key never reaches n8n and never counts toward the lockout, so
    // before the volume gate existed this loop was free and unbounded.
    for (let i = 0; i < 6; i += 1) {
      const response = await submit(requestId, '');
      expect(response.status).toBe(400);
    }

    const blocked = await submit(requestId, '');
    expect(blocked.status).toBe(429);

    // Nothing ever left the process on any of these attempts.
    expect(fetchStub.calls).toHaveLength(0);
  });

  it('leaves a normal login well clear of the ceiling', async () => {
    const requestId = await openConsentForm();
    expect((await submit(requestId, makeN8nKey())).status).toBe(303);
  });
});

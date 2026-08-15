# End-to-end test

```bash
node tests/e2e/run.mjs
```

Brings up a real stack, drives the complete flow an AI client performs, and
tears it down. Exit code 0 means every check passed.

```text
run.mjs ──OAuth 2.1 + PKCE──▶ gateway ──x-n8n-url/x-n8n-key──▶ n8n-mcp ──▶ n8n
                                 │                                          ▲
                                 └────── probes the API key ────────────────┘
                                              (both over TLS)
```

## What makes it end-to-end

Nothing is mocked. In particular:

- **The API key is real.** `run.mjs` completes n8n's owner setup and mints a key
  through n8n's own REST API. The gateway then seals *that* key and forwards it,
  and n8n accepts it because n8n signed it. A fixture would prove much less.
- **The backend is the published upstream image**, unmodified, in the same
  multi-tenant configuration production uses — including the deliberate absence
  of `N8N_API_URL` / `N8N_API_KEY`.
- **TLS is real.** The gateway only ever produces `https://` origins for n8n
  instances; that is a production constraint, not something to work around. So
  caddy terminates TLS for `n8n.local` using a throwaway CA that both Node
  processes trust via `NODE_EXTRA_CA_CERTS`. A harness that let the gateway talk
  plain HTTP would be exercising a code path production never takes.
- **The gateway is built from source** by the same Dockerfile CI uses, so its
  lint / typecheck / test gate runs as part of the E2E.

## What it checks

| Phase | Checks |
| --- | --- |
| Stack | every service healthy; `/healthz`; `/readyz` reports the store up |
| n8n | a real API key is issued, and it is an `iss=n8n, aud=public-api` JWT |
| Discovery | 401 + `resource_metadata` pointer; PRM `resource` byte-identical to the connector URL; AS advertises S256, `iss`, CIMD |
| Registration | DCR returns a public client with no secret |
| Consent | screen renders; names the instance; asks for username + key; does **not** round-trip the pending request; a wrong key is rejected by the real n8n; the right one redirects **303** with `code`, `state` and `iss` |
| Token | access + refresh issued; the code cannot be replayed |
| MCP | `initialize` through the chain; `Mcp-Session-Id` survives the proxy; `tools/list` returns the surface; **`n8n_list_workflows` and `n8n_health_check` execute against the real n8n** |
| Security | no token → 401 + challenge; non-allowlisted host → 404; smuggled `x-n8n-*` headers do not redirect the tenant; a title-cased path still routes |
| Lifecycle | refresh re-validates the key and rotates; the rotated-out token is dead; revocation kills **the whole grant**, including a token issued before it |

The tool call is the one that matters most: it only succeeds if the gateway
resolved the tenant, unsealed the right key, injected both tenant headers, the
backend accepted them, and n8n accepted the key — the entire chain in one
assertion.

## Flags

| Flag | Effect |
| --- | --- |
| `--keep` | leave the stack running afterwards (inspect it at `http://localhost:18080`) |
| `--no-build` | reuse the existing `bg-n8n-mcp:e2e` image |
| `--logs` | dump container logs at the end (automatic on failure) |
| `--port <n>` | host port for the gateway (default 18080) |

## Diagnosing a failure

`probe-backend.mjs` talks to n8n-mcp **directly**, bypassing the gateway, with
the same tenant headers the gateway would inject. It answers the one question
that matters when an MCP call fails: *is this the gateway's doing or the
backend's?*

```bash
node tests/e2e/run.mjs --keep                    # leave the stack up

cd tests/e2e
export MSYS_NO_PATHCONV=1                        # Git Bash only, see below
docker compose -f docker-compose.e2e.yml run --rm --no-deps -T \
  -e UPSTREAM="$(docker inspect bg-n8n-mcp-e2e-n8n-mcp-backend-1 \
       --format '{{range .Config.Env}}{{println .}}{{end}}' | grep ^AUTH_TOKEN= | cut -d= -f2-)" \
  -e APIKEY="<a key from provision-n8n.mjs>" \
  --entrypoint node gateway /e2e/probe-backend.mjs
```

It runs `initialize`, then `tools/list` with and without the `initialized`
notification, then a second session, then re-checks the first — which
distinguishes "the session was never created", "the session was evicted" and
"the transport errored and closed it".

That last case is how the harness's own first failure was found: a request that
omits `Accept: application/json, text/event-stream` errors the server-side
transport and closes the session, so the *next* call reports "Session not found
or expired" and the real cause is one request earlier.

> **Git Bash on Windows:** `MSYS_NO_PATHCONV=1` is needed for manual
> `docker … /e2e/…` invocations, or the path is rewritten to
> `C:/Program Files/Git/e2e/…`. `run.mjs` is unaffected — it spawns `docker`
> directly rather than through a shell.

## Requirements

Docker with Compose v2, `openssl` on `PATH`, and outbound access to pull `n8n`,
`caddy`, `redis` and `ghcr.io/czlonkowski/n8n-mcp`. First run takes a few
minutes; most of it is pulling n8n.

## Relationship to the unit suite

They answer different questions and neither replaces the other.

`app/bg-n8n-mcp/tests/` covers the branches — every rejection path, every
malformed input, every fail-closed invariant — quickly and without Docker. This
covers whether the pieces fit together against real components, which is exactly
where a gateway fails in practice: a header name, a redirect status, a
certificate, a session id.

CI runs the unit suite on every push. Run this before a release, and after any
change to the proxy, the tenant headers or the compose files.

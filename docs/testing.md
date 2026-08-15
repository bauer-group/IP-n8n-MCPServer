# Testing

Two suites, answering two different questions.

| | Question | Cost |
| --- | --- | --- |
| **Unit** (`app/bg-n8n-mcp/tests/`) | Does each decision branch behave? | seconds, no Docker |
| **End-to-end** (`tests/e2e/`) | Do the real pieces fit together? | minutes, needs Docker |

Neither replaces the other. The unit suite can be exhaustive about rejection
paths precisely because it mocks the network; the E2E can prove a header name,
a redirect status and a certificate are right precisely because it does not.

```bash
cd app/bg-n8n-mcp && pnpm check   # unit gate: biome + tsc --noEmit + vitest --coverage
node tests/e2e/run.mjs            # end-to-end against real n8n + real n8n-mcp
```

---

## Unit suite

```bash
cd app/bg-n8n-mcp
pnpm install
pnpm check          # biome + tsc --noEmit + vitest --coverage
```

`pnpm check` is exactly what CI runs and exactly what the Docker test stage
runs. A green local run means a green build; there is no fourth set of
commands.

Individually:

```bash
pnpm lint           # biome check src tests
pnpm lint:fix       # biome check --write
pnpm typecheck      # tsc -p tsconfig.json --noEmit
pnpm test           # vitest run
pnpm test:watch     # vitest
pnpm test:coverage  # vitest run --coverage (enforces the thresholds)
```

---

## What the suite covers

303 tests across 11 files. The split is deliberate: the pure security
primitives are unit-tested exhaustively, and everything above them is driven
through the **real Hono app** over `app.fetch`, with only the store backend
(in-memory) and `fetch` faked.

| File | What it holds you to |
| --- | --- |
| `tenant.test.ts` | The allowlist and the address classifier. **Read this first when auditing.** Every case is a way a naive implementation lets a caller reach a host it should not. |
| `crypto.test.ts` | Sealing round-trips, non-determinism, tamper detection, key separation, constant-time comparison. |
| `config.test.ts` | Every fail-closed invariant. Each `toThrow` is a deployment that would otherwise have started with a security property quietly missing. |
| `n8n.test.ts` | API-key claim reading and the seven probe outcomes. |
| `clients.test.ts` | Redirect-URI rules (including RFC 8252 loopback port-agnostic matching), registration, CIMD fetch and validation. |
| `store.test.ts` | Grant indirection, single-use codes, refresh consumption, that raw tokens are never stored. |
| `redis-backend.test.ts` | Our mapping onto the node-redis v6 API, against a fake client. |
| `oauth-flow.test.ts` | The complete flow end to end: challenge → discovery → register → authorize → consent → token → refresh → revoke. |
| `proxy.test.ts` | What actually reaches the backend — token replacement, header stripping, audience binding, streaming headers. |
| `http.test.ts` | Client-IP extraction, path normalisation, HTML escaping, CSP, CORS. |
| `misc.test.ts` | Logger construction, the challenge builder, resource parsing, form parsing, error handling. |

### Coverage

| Metric | Achieved | Gate |
| --- | --- | --- |
| Lines | ~94% | 90% |
| Statements | ~90% | 88% |
| Functions | ~89% | 85% |
| Branches | ~84% | 80% |

Branches is the lowest of the four, and the reason is worth stating rather than
leaving to look like slack. The v8 provider counts every `?.`, `??` and `catch`
as a branch, and a large share here are defensive paths unreachable without
breaking an invariant the type system already enforces. The one genuine gap is
`RedisBackend.connect`, which needs a live Redis; its command *mapping* is
covered against a fake, and the connection itself is exercised by the compose
stack's healthcheck.

The gates sit slightly under what the suite achieves so an unrelated change does
not turn CI red on a rounding difference.

---

## Conventions

**Nothing reaches the network.** `stubFetch` in `tests/helpers.ts` replaces the
global `fetch` and records every call, which is also how the proxy tests assert
on the headers that actually went upstream — the whole point of the tenant
injection and stripping.

**Integration tests use the real app.** `createHarness()` builds the production
Hono app with the production middleware and drives it through `normalizePath`,
exactly as `main.ts` does. Routing, CSP, CORS, OAuth logic and the proxy are all
production code under test.

**DNS is not a dependency.** The integration harness sets
`N8N_ALLOW_PRIVATE_ADDRESSES=true` so no test needs a resolver; the address
check is covered directly against the pure classifier functions in
`tenant.test.ts`, plus two `resolveTenant` cases using RFC 2606 reserved names.

**Comments say why the case exists.** A test named "rejects userinfo smuggling"
is more useful with the sentence explaining what would happen without it. That
is the difference between a suite that documents the threat model and one that
merely passes.

---

## Adding a test

1. Put it in the file that matches the unit, not a new file per feature.
2. If it is a security property, add it to `tenant.test.ts`, `config.test.ts` or
   `proxy.test.ts` — those three are where a reviewer looks first.
3. Prefer driving the real app over mocking a handler. A mocked handler tests
   the mock.
4. Say why in a comment when the case is not self-evident. "Rejects a 302"
   deserves "following it would re-send the API key to whatever host the
   redirect names".
5. Run `pnpm check` before committing.

---

---

## End-to-end suite

```bash
node tests/e2e/run.mjs            # up, test, down
node tests/e2e/run.mjs --keep     # leave the stack running to poke at
```

Brings up a real n8n, the published upstream `n8n-mcp` image, Redis, a TLS
terminator and the gateway built from source; mints a **real API key through
n8n's own REST API**; then runs the complete OAuth 2.1 flow and drives actual
MCP tool calls through the whole chain.

The decisive assertion is `n8n_list_workflows`: it only succeeds if the gateway
resolved the tenant, unsealed the right key, injected both tenant headers, the
backend accepted them, and n8n accepted the key — the entire chain in one check.

Full detail, including why TLS is part of the harness rather than mocked away,
is in [tests/e2e/README.md](../tests/e2e/README.md).

Run it before a release, and after any change to the proxy, the tenant headers,
the Dockerfile or the compose files.

---

## Manual poking

```bash
docker compose -f docker-compose.development.yml up -d --build

# The Inspector performs full OAuth discovery and shows exactly which step fails.
npx @modelcontextprotocol/inspector
# Transport: Streamable HTTP
# URL:       http://localhost:8000/i/<your-n8n-host>/mcp
```

Note that **claude.ai cannot reach a local stack** — connectors are brokered from
Anthropic's infrastructure. Use the Traefik stack on a public hostname for any
test involving a real AI client.

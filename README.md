# bg-n8n-mcp — BAUER GROUP n8n MCP Server

> **OAuth 2.1 MCP server for n8n** — it fronts
> [n8n-mcp](https://github.com/czlonkowski/n8n-mcp) as a **remote connector**,
> usable directly from Claude Web, Claude Desktop, Claude Code, Microsoft 365
> Copilot, Cursor and Continue, with **every user connecting under their own n8n
> API key**.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Docker Image](https://img.shields.io/badge/ghcr.io-bg--n8n--mcp-blue?logo=docker)](https://github.com/bauer-group/IP-n8n-MCPServer/pkgs/container/ip-n8n-mcpserver%2Fbg-n8n-mcp)
[![Node 26](https://img.shields.io/badge/Node-26-green?logo=nodedotjs)](https://nodejs.org)
[![Built with Hono](https://img.shields.io/badge/built%20with-Hono-orange)](https://hono.dev)

---

## The problem this solves

`n8n-mcp` is an excellent MCP server for n8n, but it authenticates with a single
shared `AUTH_TOKEN` and — in multi-tenant mode — expects the *caller* to supply
`x-n8n-url` and `x-n8n-key` headers. That is fine for a local `mcp-remote` bridge
on one developer's machine. It is not something you can hand to claude.ai:

- remote connectors speak **OAuth 2.1**, not bearer tokens you paste into a config
- a shared token means Claude acts as one identity for everybody
- anyone holding that token can point the tenant headers at **any** n8n instance

This gateway sits in front and fixes all three. It is a full OAuth 2.1
authorization server and protected resource; at consent time each user supplies
their own n8n API key, which is sealed at rest and injected server-side on every
request. **The AI client never sees an n8n credential**, and n8n's own role
system remains the authorization boundary — Claude sees exactly what that person
is allowed to see.

---

## Highlights

| Feature | What it means |
| --- | --- |
| **Per-user credentials** | Each user authenticates with their personal n8n API key. n8n's RBAC does the real authorization; there is no shared service identity. |
| **Many instances, one deployment** | `…/i/<n8n-host>/mcp`. Add a connector per instance; nothing to deploy per tenant. Tokens are audience-bound, so a token for instance A is rejected on instance B's path. |
| **Standards-complete OAuth 2.1** | RFC 8414 + RFC 9728 discovery with correct path insertion, PKCE S256, RFC 8707 resource indicators, RFC 9207 `iss`, RFC 7591 registration, RFC 7009 revocation, rotating refresh tokens. |
| **Client ID Metadata Documents** | The successor to dynamic registration, which MCP has deprecated. Avoids the client-record explosion DCR causes on a busy deployment. Claude Code already uses it. |
| **Real revocation** | Every token points at one grant record. Deleting it invalidates all of that user's tokens at once — no master-key rotation, no collateral. |
| **Sealed at rest** | API keys are AES-256-GCM sealed; token and code store keys are peppered HMACs. A Redis dump yields neither working tokens nor usable credentials. |
| **SSRF-hardened** | Parse-then-match host allowlist, plus an address-space check that rejects private, loopback, link-local and CGNAT targets — including IPv4-mapped IPv6. |
| **Streaming passthrough** | SSE flows through unbuffered, with `Mcp-Session-Id` and future protocol headers forwarded verbatim. |
| **Node 26 · pnpm 11 · TypeScript 7** | Current toolchain, strict everywhere, 300+ tests and a test-gated image build. |
| **Three deploy flavours** | Local development, self-hosted Traefik, Coolify — same image, same source. |

---

## Architecture

```text
                              AI Clients
                ┌────────────┬───────────────┬────────────┐
                │ Claude Web │ Claude Desktop│ Claude Code│ …
                └─────┬──────┴───────┬───────┴──────┬─────┘
                      └──────────────┼──────────────┘
                                     │ HTTPS · OAuth 2.1 + PKCE
                                     │ Streamable HTTP  /i/<host>/mcp
                                     ▼
                         ┌───────────────────────┐
                         │   Traefik / Coolify   │
                         └──────────┬────────────┘
                                    ▼
   ┌────────────────────────────────────────────────────────────────┐
   │  bg-n8n-mcp  (this project, Hono on Node 26)                   │
   │  ┌──────────────────────────────────────────────────────────┐  │
   │  │ Authorization server: /authorize /token /register /revoke│  │
   │  │ Protected resource:   RFC 9728 metadata per tenant path  │  │
   │  └──────────────────────────────────────────────────────────┘  │
   │  ┌──────────────────────────────────────────────────────────┐  │
   │  │ Consent screen: instance (from path) + username + API key│  │
   │  └──────────────────────────────────────────────────────────┘  │
   │  ┌──────────────────────────────────────────────────────────┐  │
   │  │ Tenant guard: allowlist → address space → audience bind  │  │
   │  └──────────────────────────────────────────────────────────┘  │
   └───────────────────────────┬────────────────────────────────────┘
                               │ x-n8n-url / x-n8n-key / x-instance-id
                               ▼                       ┌───────────┐
   ┌────────────────────────────────────────────┐      │   Redis   │
   │  n8n-mcp  (ghcr.io/czlonkowski/n8n-mcp)    │      │  grants,  │
   │  ENABLE_MULTI_TENANT=true, no ambient creds│      │  sealed   │
   └───────────────────────────┬────────────────┘      └───────────┘
                               │ HTTPS  X-N8N-API-KEY
                               ▼
                   each user's own n8n instance
```

The AI client's OAuth token stops at the gateway and is never forwarded — MCP
forbids token passthrough, and doing it is the confused-deputy vulnerability the
spec names by name. What goes upstream is the internal shared secret plus that
user's own sealed n8n key.

---

## Quick start

### 1 · Generate the environment file

```bash
node scripts/generate-env.mjs
```

This fills in both secrets. Then edit `.env` and set:

- `N8N_MCP_HOSTNAME` — the gateway's own public hostname
- `N8N_ALLOWED_HOSTS` — which n8n instances may be addressed, e.g.
  `*.app.bauer-group.com` or an explicit comma-separated list

### 2 · Pick a deployment flavour

```bash
# Self-hosted Traefik (HTTPS, Let's Encrypt)
docker compose -f docker-compose.traefik.yml up -d

# Coolify — paste env into the dashboard, deploy from this compose file
docker compose -f docker-compose.coolify.yml up -d

# Local development (builds from source, publishes the port directly)
docker compose -f docker-compose.development.yml up -d --build
```

### 3 · Add a connector

One connector **per n8n instance**:

```text
https://<your-gateway-host>/i/<n8n-host>/mcp

# e.g.
https://n8n-mcp.bauer-group.com/i/flow.kunde-a.app.bauer-group.com/mcp
```

| Client | Where |
| --- | --- |
| Claude Web / Desktop | Settings → Connectors → Add custom connector |
| Claude Code | `claude mcp add --transport http n8n <url>` |
| Microsoft 365 Copilot Studio | Custom connector → MCP |
| Cursor / Continue | `mcp.json`, same URL |

On **Connect**, the user lands on the gateway's consent screen, which shows the
target instance and asks for a username and their n8n API key (n8n → Settings →
n8n API → Create an API key). On a Team or Enterprise plan an owner adds the
connector once and each member then connects with their own key.

Full walkthrough: [docs/client-setup.md](docs/client-setup.md).

---

## The credential model

Three inputs, and it is worth being precise about what each one is:

| Input | Source | Is it a credential? |
| --- | --- | --- |
| **Instance** | the connector URL path | No — it selects which n8n is being addressed, and must be on the allowlist. |
| **Username** | typed on the consent screen | **No.** It is a self-asserted label used for the audit log, the lockout bucket and the consent display. |
| **API key** | typed on the consent screen | **Yes.** This is the only thing that authenticates the user, and it is verified against the instance before any token is issued. |

The authoritative identity is neither the path nor the typed username: it is the
`sub` claim inside the API key. n8n issues public-API keys as JWTs, so the
gateway reads (but cannot verify — only the instance holds the signing key) the
claims to reject an expired or wrong-audience key **at the form**, and to bind
the grant to a stable n8n user id.

The key is then validated live against `GET /api/v1/workflows?limit=1`, sealed
with AES-256-GCM and stored. Failures are named rather than lumped together:

| Response from n8n | What the user is told |
| --- | --- |
| 401 | The key was rejected — create a new one |
| 403 | The key is valid but the account may not read workflows — ask an admin |
| 404 | The public API is not enabled on this instance |
| 429 | The instance rate-limited us — try again shortly |
| timeout / refused | The instance is unreachable — is it public over HTTPS? |
| 200, wrong shape | There is no n8n API at this address |

Only the 401 case counts toward the lockout. An instance being down must not
lock out the people who use it.

---

## Adding an instance

Nothing to deploy. If the hostname matches `N8N_ALLOWED_HOSTS` (or
`N8N_ALLOWED_HOST_PATTERN`), the path works — add the connector and go. No
instance registry, no key inventory, no per-tenant container.

Worth checking once: **who can create DNS records under your wildcard domain.**
With `*.app.bauer-group.com` on the allowlist, anyone who can add
`flow.whatever.app.bauer-group.com` has added themselves to it.

---

## Documentation

| Document | Contents |
| --- | --- |
| [docs/installation.md](docs/installation.md) | Prerequisites, the three deploy flavours, first-run verification |
| [docs/authentication.md](docs/authentication.md) | The full OAuth flow, discovery documents, what each RFC contributes |
| [docs/client-setup.md](docs/client-setup.md) | Per-client instructions and their quirks |
| [docs/security.md](docs/security.md) | Trust model, the guards and what each one stops, known trade-offs |
| [docs/operations.md](docs/operations.md) | Log vocabulary, revocation, key rotation, scaling, backups |
| [docs/troubleshooting.md](docs/troubleshooting.md) | Symptom → cause, including the ones with no useful error message |
| [docs/testing.md](docs/testing.md) | The unit gate and the end-to-end suite, and what each is for |
| [tests/e2e/README.md](tests/e2e/README.md) | The end-to-end harness: real n8n, real n8n-mcp, real TLS, real API key |
| [docs/adr/](docs/adr/) | Architecture decision records |
| [CONTRIBUTING.md](CONTRIBUTING.md) | The gate, and the conventions worth knowing |
| [SECURITY.md](SECURITY.md) | Reporting a vulnerability; what this server is trusted with |

---

## Configuration

Everything is environment-driven; [.env.example](.env.example) documents every
variable with its reasoning. The ones that decide whether the deployment is
correct:

| Variable | Purpose |
| --- | --- |
| `PUBLIC_BASE_URL` | The gateway's public origin. Baked into every OAuth document; must match what the user typed exactly. |
| `N8N_ALLOWED_HOSTS` | Which n8n instances may be addressed. **The security boundary.** The server refuses to start without this or the pattern form. |
| `N8N_MCP_AUTH_TOKEN` | Shared with the n8n-mcp backend; the gateway is its only client. |
| `AUTH_STORAGE_ENCRYPTION_KEY` | 32 bytes, base64. Seals every stored API key. Rotating it revokes every grant. |
| `AUTH_REDIS_URL` | Where grants live. Required outside development. |
| `RATE_LIMITER_TRUSTED_PROXY_HOPS` | How many proxies are in front. Wrong value ⇒ spoofable rate limits. |

The process exits **78 (`EX_CONFIG`)** with a precise message when any of this is
wrong. It never starts half-configured.

---

## Upstream version requirement

This gateway targets `ghcr.io/czlonkowski/n8n-mcp` and pins **2.69.2**.

Do not pin below **2.51.2**. Earlier versions silently fall back to the
operator's own process-level n8n credentials when the tenant headers are absent
([GHSA-jxx9-px88-pj69](https://github.com/czlonkowski/n8n-mcp/security/advisories/GHSA-jxx9-px88-pj69),
CVSS 8.1), and below **2.47.4** the tenant URL is a straightforward SSRF
primitive
([GHSA-4ggg-h7ph-26qr](https://github.com/czlonkowski/n8n-mcp/security/advisories/GHSA-4ggg-h7ph-26qr)).
The compose files set `ENABLE_MULTI_TENANT=true` and deliberately leave
`N8N_API_URL` / `N8N_API_KEY` unset, so there is nothing to fall back to even if
the guard were absent.

---

## Development

```bash
cd app/bg-n8n-mcp
pnpm install
pnpm check          # biome + tsc --noEmit + vitest with coverage thresholds
pnpm dev            # runs src/main.ts directly via Node's type stripping
```

`pnpm check` is exactly what CI runs and exactly what the Docker test stage
runs, so a green local run means a green build. See
[CONTRIBUTING.md](CONTRIBUTING.md).

---

## Licence

MIT — see [LICENSE](LICENSE).

`n8n-mcp` is a separate project by [czlonkowski](https://github.com/czlonkowski/n8n-mcp),
consumed here as an unmodified container image.

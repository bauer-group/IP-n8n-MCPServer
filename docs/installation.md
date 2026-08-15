# Installation

## Prerequisites

| Requirement | Why |
| --- | --- |
| A public hostname with an **A record** | Remote connectors are brokered from Anthropic's infrastructure, not from the user's machine. An AAAA-only host is unreachable for them, and split-horizon DNS or a private address fails before any HTTP request is made — with nothing in your logs. |
| TLS in front of the container | OAuth over plain HTTP leaks the authorization code and every token. The gateway refuses to start on `http://` outside `ENVIRONMENT=development`. |
| Docker + Compose v2 | All three deploy flavours are compose stacks. |
| An **x86-64 (amd64)** host | The published image is amd64-only. ARM hosts — Graviton, Ampere, a Raspberry Pi — cannot pull it. See below. |
| n8n instances reachable over **public HTTPS** | With `WEBHOOK_SECURITY_MODE=strict` (the default, and the one to keep) the backend refuses private and loopback targets. |
| A personal n8n API key per user | n8n → Settings → n8n API → Create an API key. Not an admin key, not a shared one. |

No IdP registration, no OAuth application to create anywhere. The gateway *is*
the authorization server.

### Architecture support

The published image is **`linux/amd64` only**:

```bash
docker buildx imagetools inspect ghcr.io/bauer-group/ip-n8n-mcpserver/bg-n8n-mcp:latest
# → application/vnd.oci.image.manifest.v1+json  (a single image, not a manifest list)
```

ARM hosts fail at `docker pull` with a "no matching manifest" error. That is a
limitation of the shared build pipeline rather than of this application —
nothing in the dependency tree is architecture-specific, so a local build works
fine on ARM:

```bash
docker build -t bg-n8n-mcp:local ./app/bg-n8n-mcp
```

Then point `N8N_MCP_IMAGE`/`N8N_MCP_VERSION` at that tag, or use
`docker-compose.development.yml`, which builds from source anyway.

---

## 1 · Configure

```bash
git clone https://github.com/bauer-group/IP-n8n-MCPServer.git
cd IP-n8n-MCPServer
node scripts/generate-env.mjs
```

That writes `.env` with both secrets generated:

- `N8N_MCP_AUTH_TOKEN` — shared between the gateway and the backend
- `AUTH_STORAGE_ENCRYPTION_KEY` — 32 bytes, base64; seals every stored API key

Then fill in by hand:

```env
N8N_MCP_HOSTNAME=n8n-mcp.example.com
PUBLIC_BASE_URL=https://n8n-mcp.example.com

# Which n8n instances may be addressed. At least one form is required —
# the gateway refuses to start with neither.
N8N_ALLOWED_HOSTS=*.app.bauer-group.com
```

`.env.example` documents every remaining variable with its reasoning.

> **On the hostname.** Give the gateway its own name rather than a path on an
> existing host. It is an OAuth authorization server; sharing an origin with an
> n8n instance puts two different OAuth roles behind one certificate and one
> cookie scope. The pairing we run:
>
> | n8n | `flow.kunde-a.app.bauer-group.com` |
> | --- | --- |
> | **MCP gateway** | `n8n-mcp.bauer-group.com` |

---

## 2 · Deploy

### Self-hosted Traefik

```bash
docker compose -f docker-compose.traefik.yml up -d
docker compose -f docker-compose.traefik.yml logs -f n8n-mcp-gateway
```

Requires an existing Traefik on the network named in `PROXY_NETWORK` (default
`EDGEPROXY`) with a working cert resolver. The compose file adds two things
worth knowing about:

- a middleware that **strips inbound tenant headers** one hop before the
  gateway does
- `responseForwarding.flushInterval=1ms`, so Traefik does not buffer SSE. Without
  it the first frame of a streaming response arrives only when the stream ends,
  which reads to the user as a hung tool call.

### Coolify

Deploy `docker-compose.coolify.yml` from the Coolify UI.

1. Set the domain in the application's **Domains** field —
   `SERVICE_FQDN_N8NMCP` is populated and Traefik is wired automatically.
2. Set `N8N_ALLOWED_HOSTS` in **Environment Variables**.
3. Set `AUTH_STORAGE_ENCRYPTION_KEY` **by hand**. Coolify's secret generator does
   not produce 32-bytes-base64, and the gateway rejects anything else:
   ```bash
   openssl rand -base64 32
   ```
4. Deploy.

There is deliberately no `networks:` block in that file — Coolify attaches
services to its own UUID-named network, and adding one causes Traefik routing
ambiguity (504).

### Local development

```bash
docker compose -f docker-compose.development.yml up -d --build
```

Builds from source, publishes port 8000, logs in console format at debug level,
and permits private-address targets so you can point at an n8n on the same
Docker network.

**claude.ai cannot reach this stack** — connectors are brokered server-side and
`localhost` is not routable from Anthropic's infrastructure. Use the MCP
Inspector or `curl` here, and the Traefik stack for anything involving a real
AI client.

---

## 3 · Verify

```bash
GW=https://n8n-mcp.example.com
N8N=flow.kunde-a.app.bauer-group.com

# Liveness and readiness (readiness additionally requires Redis)
curl -s $GW/healthz  | jq
curl -s $GW/readyz   | jq

# Authorization server metadata
curl -s $GW/.well-known/oauth-authorization-server | jq

# Protected resource metadata for one tenant.
# `resource` must come back byte-identical to the URL you will paste into Claude.
curl -s "$GW/.well-known/oauth-protected-resource/i/$N8N/mcp" | jq

# The challenge. Must be 401 — not 403, not 200 — and must carry
# resource_metadata as an absolute https URL.
curl -si -X POST "$GW/i/$N8N/mcp" -d '{}' | grep -i '^HTTP\|^www-authenticate'

# A host that is not allowlisted must 404, not 401.
curl -s -o /dev/null -w '%{http_code}\n' -X POST "$GW/i/evil.example/mcp" -d '{}'
```

Expected:

```text
HTTP/1.1 401 Unauthorized
www-authenticate: Bearer error="invalid_token", error_description="missing bearer token", scope="n8n", resource_metadata="https://n8n-mcp.example.com/.well-known/oauth-protected-resource/i/flow.kunde-a.app.bauer-group.com/mcp"
404
```

Open `https://n8n-mcp.example.com/` in a browser for a status page showing the
connector URL pattern.

---

## 4 · Add a connector

See [client-setup.md](client-setup.md).

---

## Upgrading

```bash
docker compose -f docker-compose.traefik.yml pull
docker compose -f docker-compose.traefik.yml up -d
```

Grants survive — they live in Redis, and the volume is named after
`STACK_NAME`. The one change that does **not** survive is rotating
`AUTH_STORAGE_ENCRYPTION_KEY`; that invalidates every grant by design, and every
user reconnects.

The backend image (`ghcr.io/czlonkowski/n8n-mcp`) is pinned to an exact version
and bumped deliberately via a Dependabot PR rather than auto-merged — it is a
third-party image whose changes are worth reading. Never pin it below **2.51.2**;
see the README for the two advisories that matter.

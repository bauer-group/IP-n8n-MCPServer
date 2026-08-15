# Troubleshooting

Ordered by how often each one actually happens. Several of these produce **no
useful error anywhere**, which is why they are written down.

---

## Connecting

### "Couldn't reach the MCP server" and nothing in your logs

Almost always DNS or address family, because remote connectors are brokered from
Anthropic's infrastructure rather than from the user's machine. Claude rejects
the connection **before any HTTP request** if the hostname:

- resolves to a non-globally-routable address (RFC 1918, CGNAT, loopback)
- resolves to a *mix* of public and non-public addresses
- publishes only AAAA records — connectors are IPv4-only
- is not HTTPS

```bash
dig +short A  n8n-mcp.example.com     # must return a public address
dig +short AAAA n8n-mcp.example.com   # fine to have, not sufficient alone
```

"It works in `curl` and in Claude Code but not claude.ai" is this, every time.

### "Authorization with the MCP server failed" after the browser flow completed

**A cross-host redirect.** If your registered URL 301/302s to a different host
(apex → www, a vanity domain → a CDN), the `Authorization` header is dropped on
the cross-host hop per standard HTTP client behaviour. The target sees an
unauthenticated request and answers 401.

```bash
curl -sI https://n8n-mcp.example.com/i/HOST/mcp | head -3
```

Register the URL your server actually listens on.

### The consent screen appears, you submit, and nothing happens

Check the redirect status:

```bash
# Should be 303. A 302 or 307 preserves POST, Claude's callback answers 405,
# and the token exchange never runs.
```

This gateway returns 303. If you have put something in front that rewrites
redirects, that is the thing to look at.

### Requests arriving at `/authorize`, `/token`, `/register` on the origin root

You never advertised those paths at the root — but if metadata discovery does
not fully resolve, claude.ai falls back to **synthesising** default endpoints at
the origin. Seeing them means discovery failed upstream of that. Fix discovery;
do not add the routes.

```bash
curl -s https://GW/.well-known/oauth-protected-resource/i/HOST/mcp | jq
curl -s https://GW/.well-known/oauth-authorization-server | jq
```

### 403 / 429 in your edge logs for requests your app never saw

Anthropic's OAuth broker sends `User-Agent: python-httpx/<version>` and, on some
paths, a `Claude-User` header. Cloudflare bot management, AWS WAF, mod_security
and several hosters flag both.

Allowlist **all** of these, not just the MCP path:

```text
/.well-known/oauth-*
/i/*/mcp
/authorize
/token
/register
/revoke
```

Allowlisting only the MCP path leaves registration blocked, which fails later
and looks unrelated.

### A metadata change has not taken effect

Discovery documents are cached **globally, keyed by URL**, for roughly five
minutes, shared across all users, with lazy best-effort refresh. Budget that
window when iterating on `scopes_supported` or the issuer, and do not chase
"it didn't pick up my change" inside it.

---

## The consent screen

### "Dieser API-Key wird von der Instanz abgelehnt" / "rejected"

n8n answered 401. The key is wrong, deleted or from a different instance. Create
a new one: n8n → Settings → n8n API.

### "Der Key ist gültig, das Konto darf aber keine Workflows lesen" / 403

The key authenticates but the account cannot list workflows. This is a role
problem in n8n, not a key problem — creating another key will not help. Note
that this does **not** count toward the lockout, precisely because retrying
cannot succeed.

### "Public API ist nicht aktiviert" / "public API is not enabled"

n8n answers 404 across `/api/v1/*` when the public API is switched off. An
instance administrator must enable it; there is no workaround from here.

### "Die Instanz ist nicht erreichbar" / "not reachable"

From the *gateway's* network, not yours:

```bash
docker compose exec n8n-mcp-gateway \
  curl -sS -o /dev/null -w '%{http_code}\n' \
  https://flow.kunde-a.app.bauer-group.com/api/v1/workflows?limit=1
```

If that works and the form still says unreachable, check the DNS address check —
see `tenant_unusable` in the logs.

### "Dieser API-Key ist abgelaufen" / "expired"

Read from the key's own `exp` claim, without contacting n8n. Create a new key.

### "Unter dieser Adresse antwortet keine n8n-API"

Something answered 200 but not with an n8n payload — usually a login page, a
catch-all reverse proxy, or the wrong hostname.

### The form says too many attempts

Ten failed key submissions per IP or per username in 15 minutes. Wait, or clear
it:

```bash
docker compose exec redis redis-cli --scan --pattern 'rl:login:*' | \
  xargs -r docker compose exec -T redis redis-cli DEL
```

---

## The gateway itself

### The container exits immediately with code 78

`78` is `EX_CONFIG` — the configuration is wrong, and the process refused to
start rather than serve traffic with a security property missing. The message
names every problem at once:

```bash
docker compose logs n8n-mcp-gateway | tail -20
```

Common ones:

| Message | Fix |
| --- | --- |
| `PUBLIC_BASE_URL must use https://` | Use HTTPS, or set `ENVIRONMENT=development` |
| `Set N8N_ALLOWED_HOSTS … or N8N_ALLOWED_HOST_PATTERN` | An empty allowlist is refused, not treated as "allow all" |
| `AUTH_REDIS_URL is required outside development` | The in-memory store loses every grant on restart |
| `must be exactly 32 bytes when base64-decoded` | `openssl rand -base64 32` |
| `must be at least 32 characters` | Same, for `N8N_MCP_AUTH_TOKEN` |

### `/i/<host>/mcp` returns 404 for a host you believe is allowed

The allowlist is matched against a **parsed** hostname. Check for a typo, a
port, a scheme, or a wildcard that does not cover what you think:
`*.app.example.com` matches `flow.app.example.com` but **not**
`app.example.com`.

### 502 with "the n8n instance could not be resolved"

Allowlisted, but DNS failed — or it resolved into private space and
`N8N_ALLOW_PRIVATE_ADDRESSES` is false (as it should be in production). Look for
`tenant_unusable` in the logs; `reason` distinguishes the two.

### 401 with "the MCP backend rejected the stored credentials"

`N8N_MCP_AUTH_TOKEN` differs between the gateway and the backend. Both read the
same variable, so this means one container was restarted without the other after
a change:

```bash
docker compose -f docker-compose.traefik.yml up -d n8n-mcp-backend n8n-mcp-gateway
```

### `Multi-tenant headers required` from the backend

The backend rejected a request with no tenant headers. Either the gateway did
not set them — check `upstream_rejected` and the request path — or something is
reaching the backend directly, which should be impossible: it has no Traefik
route and no published port.

### Tool calls hang, then time out

SSE is being buffered somewhere. The gateway sets `X-Accel-Buffering: no` and
`Cache-Control: no-transform` on streaming responses, and the Traefik compose
file sets `responseForwarding.flushInterval=1ms`. If you have added nginx or
another proxy in front, it needs `proxy_buffering off` too.

### Users get "Session not found or expired" after a colleague connects

`x-instance-id` collision. The gateway sends a **per-grant** value precisely to
avoid this; if you have overridden `MULTI_TENANT_SESSION_STRATEGY` or are
running more than one backend replica without sticky sessions, that guarantee is
gone. See [operations.md](operations.md#scaling).

### 429 from the gateway

A grant exceeded `RATE_LIMITER_MCP_MAX` per `RATE_LIMITER_MCP_WINDOW` (600/60 s
by default). Usually an agent loop. Raise it if the workload is legitimate.

### 429 that mentions "authentication attempts"

That one is the **backend's** limiter, which counts failed requests per client
IP. If it fires under normal use, `TRUST_PROXY` is not taking effect and it is
counting the gateway's single IP for everyone. Check that
`RATE_LIMITER_TRUSTED_PROXY_HOPS` matches the real topology so the gateway
forwards a correct `X-Forwarded-For`.

---

## Getting a clean trace

```bash
# Every request for one user, in order.
docker compose logs n8n-mcp-gateway | jq -c 'select(.username == "kb@example.com")'

# Everything about one request.
docker compose logs n8n-mcp-gateway | jq -c 'select(.req_id == "…")'

# Just the security-relevant events.
docker compose logs n8n-mcp-gateway | \
  jq -c 'select(.evt | test("audience_mismatch|grant_revoked|credential_rejected|rate_limited"))'
```

The `req_id` is returned to the caller as `X-Request-Id`, so a user can hand you
one directly.

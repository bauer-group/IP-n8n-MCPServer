# Operations

## Log vocabulary

Logs are one JSON object per line. Every entry carries `evt`, and every
request-scoped entry carries `req_id`, which is echoed to the caller as
`X-Request-Id` — so a user reporting "it failed at 14:02" can paste one string
and land on the exact line.

```bash
docker compose -f docker-compose.traefik.yml logs -f n8n-mcp-gateway | jq
```

| `evt` | Level | Meaning |
| --- | --- | --- |
| `started` | info | Boot complete; carries version, base URL, store kind |
| `request` | debug/info/warn/error | One per request. Proxy calls are debug so the hot path does not drown the rest. |
| `client_registered` | info | A client registered (`source`: `dcr` or `cimd`) |
| `authorize_unknown_client` | warn | `/authorize` with an unregistered `client_id` |
| `authorize_bad_redirect` | warn | `redirect_uri` did not match the registration |
| `authorize_tenant_rejected` | warn | `resource` named a host outside the allowlist |
| `credential_rejected` | warn | Consent failed. `code` says which of the seven reasons. |
| `login_rate_limited` | warn | Lockout tripped |
| `consent_granted` | **info** | A grant was created. Carries `username`, `host`, `n8n_user`, `grant_id`. |
| `token_issued` | info | `grant: code` or `grant: refresh` |
| `pkce_failed` | warn | Verifier did not match the challenge |
| `grant_revoked` | warn | Carries `reason`: `client_request`, `bad_key`, `insufficient_permissions` |
| `grant_undecryptable` | warn | The storage key was rotated under a live grant |
| `audience_mismatch` | **warn** | A token for one tenant was presented on another's path |
| `tenant_unusable` | warn | Allowlisted, but DNS failed or it resolved into private space |
| `mcp_rate_limited` | warn | A grant exceeded its per-window budget |
| `upstream_rejected` | warn | The backend answered 401/403 |
| `upstream_unreachable` | error | The backend could not be reached |
| `redis_error` / `redis_reconnecting` / `redis_ready` | error/warn/info | Store connectivity |
| `unhandled_error` | error | A bug. Carries a stack trace against `req_id`. |

**Never logged:** API keys, access or refresh tokens, authorization codes,
client secrets, PKCE verifiers, the `Authorization` header. The logger redacts
these by path as a backstop; call sites do not pass them at all.

### Worth alerting on

| Signal | Why |
| --- | --- |
| `audience_mismatch` | Either a client bug or someone probing tenant isolation. Should be zero. |
| `grant_undecryptable` | The storage key changed under live grants. Expected exactly once after a deliberate rotation, never otherwise. |
| `upstream_unreachable` sustained | The backend is down; every user is offline. |
| `unhandled_error` | Always a bug. |
| `login_rate_limited` clustering on one host | Someone is guessing keys against one instance. |

---

## Revoking access

### One user

Preferred, immediate:

```bash
# grant_id is in the consent_granted log line (truncated) — match on username.
docker compose exec redis redis-cli DEL "grant:<grant_id>"
```

Every access and refresh token pointing at that grant stops working on its next
request, because token lookup dereferences the grant and finds nothing.

Alternatives:

- **The user removes the connector in Claude** — the client calls `/revoke`,
  which drops the grant.
- **Delete the API key in n8n** — access ends at the next refresh, at the latest
  after `AUTH_ACCESS_TOKEN_TTL`. The refresh path re-probes the key and revokes
  the grant on a hard rejection.

### Everyone

Rotate `AUTH_STORAGE_ENCRYPTION_KEY` and restart:

```bash
openssl rand -base64 32   # → .env
docker compose -f docker-compose.traefik.yml up -d
```

Every sealed key becomes undecryptable, every grant is dropped on first use
(logged as `grant_undecryptable`), and every user reconnects. This is the
break-glass lever — it is not reversible and there is no partial rotation.

### Finding a user's grant

```bash
# List grants (keys only — the values are sealed).
docker compose exec redis redis-cli --scan --pattern 'grant:*'

# Inspect one. sealedKey is ciphertext; username and hostname are readable.
docker compose exec redis redis-cli GET "grant:<id>" | jq
```

---

## Rotating the upstream token

`N8N_MCP_AUTH_TOKEN` is shared between the gateway and the backend, so both must
change together. There is a brief window where in-flight requests fail with
`upstream_rejected`:

```bash
openssl rand -base64 32   # → .env, N8N_MCP_AUTH_TOKEN
docker compose -f docker-compose.traefik.yml up -d n8n-mcp-backend n8n-mcp-gateway
```

No grant is affected — user credentials are unrelated to this token.

---

## Health and readiness

| Endpoint | Answers |
| --- | --- |
| `GET /healthz` | 200 as long as the process can serve a request. This is what the container `HEALTHCHECK` polls. |
| `GET /readyz` | 200 only when the grant store is reachable; 503 otherwise. |

The split is deliberate. Tying liveness to Redis would let a brief Redis blip
make an orchestrator kill a process that was about to recover. Use `/readyz` for
load-balancer membership and `/healthz` for restart decisions.

---

## Scaling

The gateway itself is stateless — all state is in Redis — so several replicas
work.

**But the backend is not.** n8n-mcp holds MCP sessions in process memory, keyed
by `Mcp-Session-Id`. With more than one backend replica you need **sticky
sessions** on that header, or a client's second request lands on a replica that
has never heard of its session. Until you need that, run one backend and scale
the gateway.

`N8N_MCP_MAX_SESSIONS` (default 200 here) caps concurrent backend sessions
across all tenants. Each connected client holds one.

---

## Backups

Everything that matters is in the Redis volume (`${STACK_NAME}-redis`):

```bash
docker compose exec redis redis-cli BGSAVE
docker run --rm -v bg-n8n-mcp-redis:/data -v "$PWD:/backup" alpine \
  tar czf /backup/redis-$(date +%F).tar.gz -C /data .
```

That dump contains **sealed** API keys — useless without
`AUTH_STORAGE_ENCRYPTION_KEY`, which is in `.env` and must be backed up
separately and stored differently. Losing the key while keeping the dump means
every user reconnects; losing both means the same thing, so the practical
guidance is simply: do not put them in the same place.

Redis runs with `--maxmemory-policy noeviction` on purpose. Evicting a key here
would silently log a user out; running out of memory should be an alert, not a
mysterious disconnection.

---

## Tightening the tool surface

The backend accepts guardrails that apply to every tenant:

```env
# Read-only deployment
DISABLED_TOOLS=n8n_delete_workflow,n8n_delete_execution
DISABLED_TOOL_OPERATIONS=n8n_update_partial_workflow:*
```

These are coarse. Fine-grained authorization is n8n's own role system, which is
already in force because every call runs under the user's own key — the gateway
deliberately does not attempt to mirror it.

---

## Common operational answers

**"A user says their connector stopped working."**
Grep for their username in `consent_granted`, then for `grant_revoked` with the
same `host`. The usual cause is that they deleted or rotated their API key in
n8n. They reconnect and enter the new one.

**"Can I see who is connected?"**
`redis-cli --scan --pattern 'grant:*'`, then `GET` each — `username` and
`hostname` are readable, the key is not.

**"Do I have to restart after changing .env?"**
Yes. Configuration is parsed once at boot, deliberately: a process that
re-reads config at runtime can drift into a state no config file describes.

**"A user connected twice and the first session died."**
Expected with `MULTI_TENANT_ALLOW_CONCURRENT_SESSIONS=false`. One grant means
one live backend session, and reconnecting cleans up the previous one. Set it to
`true` if a single connector genuinely needs several concurrent sessions.

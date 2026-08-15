# Authentication

This server plays **three** roles at once, and most confusion about it comes
from conflating them:

```text
  AI client                    gateway                        n8n
      │                           │                            │
      │──(1) OAuth 2.1 + PKCE────▶│  authorization server      │
      │                           │                            │
      │──(2) Bearer <our token>──▶│  protected resource        │
      │                           │                            │
      │                           │──(3) X-N8N-API-KEY────────▶│
      │                           │       the user's own key   │
```

1. **Authorization server** — issues the tokens the AI client uses. Ours; opaque.
2. **Protected resource** — the MCP endpoint that validates them.
3. **OAuth client of nothing.** There is no upstream IdP. The credential that
   proves who the user is, is their **n8n API key**, presented once on the
   consent screen.

That third point is the design's whole premise, and it is why this server needs
no Entra/Keycloak/Google registration: n8n already issued every user a
credential, and n8n already knows what each of them may do.

---

## The flow, end to end

```text
 1. POST /i/<host>/mcp                        → 401 + WWW-Authenticate
                                                  resource_metadata="…"
 2. GET  /.well-known/oauth-protected-resource/i/<host>/mcp   → 200
 3. GET  /.well-known/oauth-authorization-server               → 200
 4. POST /register            (or a Client ID Metadata Document)
 5. GET  /authorize?…&resource=https://gw/i/<host>/mcp
                                              → consent screen
 6. POST /authorize           username + n8n API key
                                              → 303 to the client callback
                                                 ?code=…&state=…&iss=…
 7. POST /token               code + code_verifier
                                              → access + refresh token
 8. POST /i/<host>/mcp        Bearer <access> → proxied to n8n-mcp
```

Steps 2 and 3 are only reached if the client did not use the pointer from step
1. Claude prefers the pointer; the well-known probe is its fallback.

---

## Discovery, and the one rule everyone gets wrong

The MCP endpoint lives at a **path**, `/i/<n8n-host>/mcp`. RFC 9728 §3 says the
well-known segment is **inserted between the host and the path**, not appended:

```text
resource     https://mcp.example.com/i/flow.acme.com/mcp
metadata at  https://mcp.example.com/.well-known/oauth-protected-resource/i/flow.acme.com/mcp
                                     └──────────── inserted here ─────────┘

NOT          https://mcp.example.com/i/flow.acme.com/.well-known/oauth-protected-resource
```

The second form is the OIDC convention and is wrong here. Serving it produces a
silent 404 and discovery aborts with nothing useful in any log.

RFC 9728 §3.3 then requires the `resource` field inside the document to be
**byte-identical** to the identifier the URL was built from. A document that
normalises the host differently, drops the path, or adds a trailing slash is
discarded by the client — again silently. That is why `resourceFor()` in
`src/oauth/metadata.ts` is the single place that string is ever constructed.

### What is served where

| URL | Document | Notes |
| --- | --- | --- |
| `/.well-known/oauth-protected-resource/i/<host>/mcp` | RFC 9728 | Per tenant. 404 for a host outside the allowlist. |
| `/.well-known/oauth-authorization-server` | RFC 8414 | One document; the issuer is the origin, which has no path. |
| `/.well-known/openid-configuration` | same body | A normative fallback clients MUST try second. We are not an OpenID Provider and the document claims nothing of the sort — it costs one route and removes a class of "discovery failed" reports. |

### Fields that decide whether anything works

| Field | Why it matters |
| --- | --- |
| `code_challenge_methods_supported: ["S256"]` | Clients **MUST refuse to proceed** if this is absent — even when the server does support PKCE. Omitting it fails the flow before anything user-visible happens. |
| `authorization_servers: [<one entry>]` | MCP requires at least one. Clients use the **first** and do not fall back, so the list stays at exactly one element. |
| `scopes_supported` on the AS: includes `offline_access` | This is how a client opts into a refresh token — Claude appends `offline_access` only when the AS advertises it. |
| `scopes_supported` on the PRM: **excludes** `offline_access` | The MCP spec says a resource SHOULD NOT advertise it there. Both statements are true at once, which is why the two documents differ. |
| `authorization_response_iss_parameter_supported: true` | RFC 9207. Advertising it is what makes clients *enforce* the `iss` we return, which is the authorization-server mix-up defence. |
| `client_id_metadata_document_supported: true` | Together with `"none"` in `token_endpoint_auth_methods_supported`, tells a client to use a CIMD instead of registering. |

---

## Client identity: registration vs. CIMD

Two mechanisms, because the ecosystem is mid-migration.

**Dynamic Client Registration (RFC 7591)** — `POST /register`. Every deployed
client understands it. Its flaw is operational rather than security: clients
register a *fresh* client on every reconnect, so a busy deployment accumulates
thousands of records differing only by id. `AUTH_CLIENT_TTL` bounds that.

**Client ID Metadata Documents** — the client id *is* an `https://` URL that
serves the client's own metadata. Nothing to register, nothing to accumulate.
MCP marked DCR deprecated in favour of it. Claude Code already identifies this
way, via `https://claude.ai/oauth/claude-code-client-metadata`.

Fetching a URL supplied by an unauthenticated caller is an SSRF primitive, so
the CIMD path is guarded: `https` with a path component only, the host must
resolve entirely to public addresses, redirects are **not followed** (a 302 to
`169.254.169.254` would undo the address check), and the response is size- and
time-bounded. The document's own `client_id` must equal the URL it came from —
without that check, any site could publish a document claiming another site's
identity.

---

## Redirect URIs

Exact string match, with one deliberate exception.

RFC 8252 §7.3 says a **native** client's loopback redirect must be matched
**ignoring the port**, because the client binds an ephemeral port at runtime and
cannot know it at registration time. Claude Code registers
`http://localhost/callback` and `http://127.0.0.1/callback`, then listens on
something like `:3118`.

A gateway that requires `https://` — or matches loopback URIs strictly — locks
out Claude Code permanently, while claude.ai (a fixed `https` callback) works
fine. The result looks like a Claude Code bug and is not.

Accepted: any `https://` URI; `http://` on a loopback host; a private-use scheme
(`com.example.app:/cb`, `vscode://…`). Rejected: plain `http://` to a
non-loopback host, and any URI with a fragment.

`MCP_ALLOWED_CLIENT_REDIRECT_URIS` narrows this to a prefix allowlist. Note that
restricting it to `https://claude.ai/` also excludes Claude Code.

---

## The consent screen

Reached at `GET /authorize`, after the client, `redirect_uri`, PKCE parameters
and `resource` have all been validated. It shows the target instance and asks
for a username and an n8n API key.

The pending request is held **server-side** under an opaque handle; only that
handle travels through the form. Round-tripping the request context in a hidden
field — as the draft this project replaces did — means the POST handler has no
original to compare against, and a user (or anything that can rewrite the page)
can change `redirect_uri` or `resource` between the GET that validated them and
the POST that acts on them.

On submit:

1. **Lockout check**, keyed on client IP *and* typed username.
2. **Read the key** — reject an expired or wrong-audience n8n JWT with no
   network call at all.
3. **Resolve the instance** — allowlist, then address space. This is the first
   point an outbound connection happens on a user's behalf, so it is where the
   SSRF guard belongs.
4. **Probe** `GET /api/v1/workflows?limit=1`.
5. **Seal and store**, then `303` back to the client.

### Why 303 and not 302

A `302` or `307` preserves the POST method across the redirect. Claude's
callback then receives a POST, answers `405 Method Not Allowed`, and the token
exchange never happens. Every log line up to that point looks perfect. This one
status code is the difference between a working connector and an unexplained
failure, and frameworks that default to 307 on a POST redirect get it wrong.

### Errors are never redirected to an unvalidated URI

RFC 6749 §4.1.2.1: if the client or the `redirect_uri` is unknown, the error is
rendered on our own page. Redirecting instead turns `/authorize` into an open
redirect that reflects attacker-controlled parameters.

---

## Tokens

| Property | Value |
| --- | --- |
| Format | Opaque, 256 bits of entropy, base64url |
| Stored as | Peppered HMAC of the token — never the token itself |
| Audience | Bound to one tenant's canonical resource URI |
| Access TTL | `AUTH_ACCESS_TOKEN_TTL` (default 1 h) |
| Refresh | Rotated on every use; the presented token is consumed atomically |
| Revocation | RFC 7009 `/revoke`, or delete the grant |

**Grant indirection.** Tokens hold a `grantId` and nothing else of value; the
sealed API key lives in exactly one record:

```text
  code ─┐
access  ├──▶ grant:<id> ──▶ { hostname, sealedKey, username, n8nUserId }
refresh ┘
```

Deleting `grant:<id>` invalidates every token pointing at it, on the next
request. That is what makes "revoke this one user" a single delete rather than a
master-key rotation that disconnects everybody.

### Re-validation on refresh

Every refresh re-probes the stored key, so a key deleted in n8n ends the grant at
the next refresh rather than working for the rest of the refresh window. Two
asymmetries are deliberate:

- **Only a hard rejection (401/403) revokes.** An unreachable instance must not
  log out every user of that instance during a maintenance window.
- **The probe timeout is capped well below the ~30 s a client allows for a
  refresh.** Blowing that budget fails the refresh anyway, and then looks like
  our bug rather than a slow n8n.

---

## What the AI client never receives

- the n8n API key, in any form
- the upstream `AUTH_TOKEN`
- any token that n8n itself would accept

The inbound bearer stops at the gateway. MCP forbids token passthrough outright,
and doing it is the confused-deputy vulnerability the specification names
directly. What goes upstream is the internal shared secret plus the user's own
sealed key, injected server-side.

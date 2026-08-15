# Security model

What this server is trusted with, what each guard actually stops, and — stated
rather than hidden — what it does not.

---

## What it holds

**Live n8n API keys for real people**, and it makes API calls on their behalf.
Two classes of bug matter more than anything else here:

1. one user's request running under another user's key
2. a key reaching an AI client, a log line, or a host that is not their n8n

Everything below exists for one of those two.

---

## Trust boundaries

```text
   untrusted                    │  semi-trusted        │  trusted
   ─────────────────────────────┼──────────────────────┼──────────────
   AI client                    │  n8n-mcp backend     │  Redis
   the browser at consent       │  (internal network)  │  the config
   anything with a bearer token │                      │
```

The AI client is untrusted throughout: it supplies the tenant path, the
`resource`, the redirect URI, the registration body and — at consent — the
browser rendering the form. None of those is taken at face value.

The backend is semi-trusted: it is on a private network, holds no ambient n8n
credentials, and receives credentials only for the request in hand.

---

## The guards

### 1 · Tenant allowlist — parse first, match second

`src/n8n/tenant.ts`

A regex applied to a *raw* string is bypassable through userinfo, a port, a
path, a trailing dot, or a unicode homoglyph that punycode later folds. The
candidate is therefore parsed to a bare hostname first, and only the parsed
result is matched. Rejected before any allowlist is consulted:

```text
flow.ok.example@evil.tld        userinfo
flow.ok.example:8080            explicit port
flow.ok.example/../admin        path
flow.ok.example.                trailing root dot (normalised, then matched)
flow.äk.example                 non-ASCII
https://flow.ok.example         scheme
```

Wildcards match subdomains but **not** the apex: `*.app.example.com` does not
grant `app.example.com`. A regex is anchored in code even when the operator's
pattern forgot `^`/`$`.

### 2 · Address space — SSRF

An allowlisted *name* is not enough. `169.254.169.254` is one DNS record away
from any domain you control, and that is the shape of
[GHSA-4ggg-h7ph-26qr](https://github.com/czlonkowski/n8n-mcp/security/advisories/GHSA-4ggg-h7ph-26qr)
against n8n-mcp itself.

Every address a tenant name resolves to must be globally routable. Blocked:
RFC 1918, loopback, link-local (including the metadata address), CGNAT,
multicast, reserved, TEST-NET, benchmarking, ULA, IPv6 link-local, and
**IPv4-mapped IPv6** — `::ffff:10.0.0.1` is an IPv4 destination wearing an IPv6
costume, and judging it as "some IPv6 address" is a complete bypass.

*Every* record must pass. A name publishing one public and one private address
is the classic DNS-rebinding setup, and accepting it because the first record
looked fine is how that attack succeeds.

The check runs **after authentication** on the proxy path, so an unauthenticated
caller cannot use this gateway to issue resolver queries at will.

> **Known trade-off.** This is check-then-use. A resolver that answers public
> here and private microseconds later during `fetch` defeats it. Closing that
> properly needs a pinned-IP HTTP agent. The residual risk is bounded by the
> allowlist (an attacker must already control an allowlisted name) and by
> n8n-mcp's own `WEBHOOK_SECURITY_MODE=strict` guard behind us, which re-checks
> at request time.

### 3 · Audience binding

A token is issued for one canonical resource URI and checked against the path it
arrives on. Without this the per-tenant paths are decoration: anyone with any
valid token could address any allowlisted instance.

### 4 · Tenant headers are stripped, then set

`x-n8n-url`, `x-n8n-key`, `x-instance-id` and `x-session-id` are removed from
every inbound request and then set by the gateway. Traefik strips them too — one
hop earlier — so a bug in the gateway's denylist is not the only thing between a
caller and someone else's n8n.

Header handling is a **denylist**, not an allowlist, so protocol headers added
after this code was written (`Mcp-Method`, `Mcp-Name`, `Mcp-Param-*`) are
forwarded rather than silently dropped. The spec tells intermediaries to do
exactly that.

### 5 · No token passthrough

The inbound bearer never leaves the gateway. MCP forbids it outright.

### 6 · Per-grant upstream session id

n8n-mcp's default `MULTI_TENANT_SESSION_STRATEGY=instance` evicts every existing
session sharing an `x-instance-id` whenever one initialises. Sending the n8n
hostname there — the obvious choice — would mean **any user connecting kicks
every other user of that instance off**. The gateway sends a value derived from
the grant instead, so each user gets their own session and the eviction does the
useful thing: cleaning up that user's own stale session on reconnect.

The value is *derived* from the grant id, not the grant id itself, because that
is a bearer-equivalent secret and would otherwise end up in the backend's
session ids and log lines.

### 7 · At rest

| Data | How it is stored |
| --- | --- |
| n8n API key | AES-256-GCM, version-prefixed, prefix authenticated as AAD |
| Access / refresh tokens | Not stored. The key is a peppered HMAC of the token. |
| Authorization codes | Same, plus atomic `GETDEL` — single-use by construction |
| Rate-limit identities | Hashed; no IP or username sits in the keyspace in the clear |

The encryption and hashing keys are HKDF-derived from one configured secret with
distinct labels. Reusing a single key for both is the kind of shortcut that is
fine until one of the two primitives leaks something about it.

### 8 · Brute force

Failed key submissions are counted per **client IP and per typed username**. IP
alone punishes a whole office for one colleague's typo; username alone lets an
attacker spread guesses across names. Either bucket tripping locks out.

Only a credential verdict counts. An unreachable instance never locks anyone
out — otherwise anyone who can take an n8n instance offline can lock out
everyone who uses it. A 403 does not count either: the key is real and the
account simply lacks a permission, so counting it sends that user round a loop
that cannot succeed.

### 9 · Client IP

Taken from the **rightmost** `RATE_LIMITER_TRUSTED_PROXY_HOPS` entries of
`X-Forwarded-For`. The header is append-only and its left end is whatever the
caller wrote. Taking the leftmost entry — the common shortcut — hands every rate
limit here to anyone willing to set a header. With `hops = 0` the header is
ignored entirely.

### 10 · The consent screen

Served under `default-src 'none'; script-src 'none'; form-action 'self';
frame-ancestors 'none'`, `Cache-Control: no-store`. **No inline script can run
on it at all**, whatever ends up in the markup. The landing page — which does
need a few lines of script — uses a per-response nonce, so the strictness of the
credential-entry page does not depend on the landing page's needs.

`frame-ancestors 'none'` is correct here rather than something to relax: AI
clients open the consent screen as a top-level popup and never frame it, so a
framed consent screen is an attack, not a use case.

---

## What an attacker gets from each thing they might steal

| Stolen | Consequence |
| --- | --- |
| An access token | MCP access to **one** instance as **one** user, until `AUTH_ACCESS_TOKEN_TTL`. Revocable by deleting the grant. |
| A refresh token | The same, renewable — until the next refresh re-probes a key the user has since revoked. Rotation means a stolen-and-used token is detectable by the legitimate holder's next refresh failing. |
| A Redis dump | Ciphertext and hashes. No working tokens, no usable API keys, without `AUTH_STORAGE_ENCRYPTION_KEY`. |
| `AUTH_STORAGE_ENCRYPTION_KEY` alone | Nothing, without the store. |
| Both | Every stored n8n API key. Rotate the key, which invalidates every grant, then have users reconnect. |
| `N8N_MCP_AUTH_TOKEN` | Direct access to the backend — but with `ENABLE_MULTI_TENANT=true` and no ambient credentials, the holder must still supply a valid n8n key of their own. Not nothing; not a credential either. |

---

## Deployment expectations

These are the operator's responsibility, and getting them wrong is not a
vulnerability in the software:

- `N8N_ALLOW_PRIVATE_ADDRESSES` stays `false`. It is accepted only in
  `ENVIRONMENT=development`.
- `WEBHOOK_SECURITY_MODE=strict` on the backend. Loosening it makes the
  gateway's allowlist the only SSRF control in the stack.
- `AUTH_STORAGE_ENCRYPTION_KEY` and `N8N_MCP_AUTH_TOKEN` are per-deployment
  secrets (`node scripts/generate-env.mjs`), rotated if exposed.
- `RATE_LIMITER_TRUSTED_PROXY_HOPS` matches the real topology.
- TLS terminates in front of the container; the backend is never published.
- **Who can create records under your wildcard domain.** With
  `*.app.example.com` allowlisted, anyone who can add a subdomain has added
  themselves to the allowlist.

---

## Known trade-offs

Documented rather than hidden, so you can decide whether they matter to you.

- **The allowlist is enumerable.** `/i/<host>/mcp` answers 404 for a host that
  is not allowlisted and 401 for one that is. This is inherent: RFC 9728
  requires the protected-resource document to be served for real resources and
  not for others, so discovery leaks the same fact. If your tenant list is
  itself confidential, this design is not for you.

- **DNS check-then-use.** See guard 2.

- **The username is self-asserted.** It is an audit label, not a credential.
  The authoritative identity is the `sub` claim inside the API key, which the
  user cannot forge without a key the instance accepts.

- **API key signatures are not verified.** They cannot be — only the instance
  holds the signing key. Claims are read to reject an obviously-dead key early;
  the live probe is what actually authenticates.

- **Registration is unauthenticated by default**, which is the MCP default and
  is what lets a client we have never heard of connect. Narrow it with
  `MCP_ALLOWED_CLIENT_REDIRECT_URIS` on a deployment that only serves Claude —
  noting that this also excludes Claude Code.

- **Grants outlive a deleted n8n user until the next refresh.** Bounded by
  `AUTH_ACCESS_TOKEN_TTL` (1 h by default). Immediate revocation is `POST
  /revoke` or deleting the grant record.

---

## Reporting

See [SECURITY.md](../SECURITY.md).

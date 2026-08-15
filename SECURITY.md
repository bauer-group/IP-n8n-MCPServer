# Security Policy

## Reporting a vulnerability

Please report security issues privately to **security@bauer-group.com**, or via
GitHub's [private vulnerability reporting](https://github.com/bauer-group/IP-n8n-MCPServer/security/advisories/new)
on this repository. Do not open a public issue for a suspected vulnerability.

Include what you did, what you expected, and what happened — a reproduction is
worth more than a severity rating. We aim to acknowledge within two working days.

## Supported versions

| Version | Supported |
| --- | --- |
| Latest release | Yes |
| Anything older | No — upgrade first, then report if it persists |

This is an internal BAUER GROUP project released under MIT. There is no
long-term-support branch; fixes land on `main` and ship in the next release.

## What this server is trusted with

Worth stating plainly, because it shapes what counts as a vulnerability here:
this gateway holds **live n8n API keys for real users** and makes API calls on
their behalf. The most serious class of bug in this codebase is anything that

- lets one user's request run under another user's key,
- lets a key reach an AI client, a log line, or a host that is not that user's
  n8n instance,
- lets a token issued for one n8n instance be used against another.

The full model is in [docs/security.md](docs/security.md). In short:

- **Inbound** — OAuth 2.1 + PKCE (S256). The gateway is the authorization
  server; clients never receive a token n8n would accept.
- **Consent** — the user's own n8n API key, validated against their instance
  before any token is issued.
- **Outbound** — that key, sealed with AES-256-GCM at rest and injected
  server-side per request. The client's own token never leaves the gateway;
  MCP forbids token passthrough and doing it is the confused-deputy
  vulnerability the spec names directly.
- **Authorization** — n8n's own role system. There is no ambient service
  identity anywhere in the stack.

## Upstream dependency

This project consumes `ghcr.io/czlonkowski/n8n-mcp` as an unmodified image and
pins it exactly. **Do not deploy below 2.51.2.** Earlier versions silently fall
back to the operator's process-level n8n credentials when the tenant headers are
absent ([GHSA-jxx9-px88-pj69](https://github.com/czlonkowski/n8n-mcp/security/advisories/GHSA-jxx9-px88-pj69),
CVSS 8.1), and below 2.47.4 the tenant URL is an SSRF primitive
([GHSA-4ggg-h7ph-26qr](https://github.com/czlonkowski/n8n-mcp/security/advisories/GHSA-4ggg-h7ph-26qr)).

The compose files enable multi-tenant mode and deliberately leave
`N8N_API_URL` / `N8N_API_KEY` unset, so there is nothing to fall back to even
if that guard were absent. A vulnerability in n8n-mcp itself should be reported
to that project.

## Deployment expectations

These are the operator's responsibility, and getting them wrong is not a
vulnerability in the software:

- `N8N_ALLOWED_HOSTS` (or the pattern form) is set, and set narrowly. The
  gateway refuses to start with neither, but it cannot tell you that your
  wildcard is wider than you meant.
- `N8N_ALLOW_PRIVATE_ADDRESSES` stays `false`. It is accepted only in
  `ENVIRONMENT=development`.
- `WEBHOOK_SECURITY_MODE=strict` on the backend.
- `AUTH_STORAGE_ENCRYPTION_KEY` and `N8N_MCP_AUTH_TOKEN` are per-deployment
  secrets (`node scripts/generate-env.mjs`), rotated if exposed.
- `RATE_LIMITER_TRUSTED_PROXY_HOPS` matches the real proxy topology. A wrong
  value makes every rate limit here spoofable with a header.
- TLS terminates in front of the container, and the backend is never published.
- You control DNS under any wildcard you allowlist. Anyone who can create
  `flow.anything.app.example.com` has added themselves to `*.app.example.com`.

## Known trade-offs

Documented rather than hidden, with the full reasoning in
[docs/security.md](docs/security.md):

- **The allowlist is enumerable.** `/i/<host>/mcp` answers 404 for a host that
  is not allowlisted and 401 for one that is. This is inherent to RFC 9728
  discovery, which requires per-resource metadata to exist for real resources
  and not for others.
- **The address check is check-then-use.** A resolver answering public at check
  time and private at connect time defeats it. Bounded by the allowlist and by
  n8n-mcp's own SSRF guard behind us.
- **The username on the consent screen is self-asserted** — an audit label, not
  a credential. The authoritative identity is the `sub` claim inside the API
  key.
- **API key signatures are not verified** — only the issuing instance can do
  that. Claims are read to reject an obviously-dead key early; the live probe is
  what authenticates.
- **A grant survives a deleted n8n user until the next refresh**, bounded by
  `AUTH_ACCESS_TOKEN_TTL` (1 hour by default). Immediate revocation is
  `POST /revoke` or deleting the grant record.

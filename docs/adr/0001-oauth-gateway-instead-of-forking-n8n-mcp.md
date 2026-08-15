# ADR 0001 — An OAuth gateway in front of n8n-mcp, rather than a fork

**Status:** Accepted
**Date:** 2026-08-15

## Context

`n8n-mcp` is a mature MCP server for n8n with a large, actively maintained tool
surface. It cannot be used as a remote connector on claude.ai as it stands:

- it authenticates callers with a single shared `AUTH_TOKEN`, not OAuth 2.1
- in multi-tenant mode it expects the *caller* to supply `x-n8n-url` and
  `x-n8n-key`, which means the caller chooses both the target instance and the
  credential
- it serves none of the discovery documents a remote MCP client requires

We needed per-user credentials, OAuth 2.1, and several n8n instances behind one
deployment.

## Options considered

1. **Fork n8n-mcp and add OAuth inside it.**
2. **Write our own MCP server for n8n from scratch.**
3. **Put an OAuth gateway in front of the unmodified image.**

## Decision

Option 3.

## Reasoning

**Against forking (1).** The tool surface is the valuable part and it changes
constantly. A fork inherits the maintenance of every upstream release forever,
and the merge conflicts would concentrate in exactly the HTTP layer we changed.
It also means every upstream security fix — and there have been two that matter,
[GHSA-jxx9-px88-pj69](https://github.com/czlonkowski/n8n-mcp/security/advisories/GHSA-jxx9-px88-pj69)
and
[GHSA-4ggg-h7ph-26qr](https://github.com/czlonkowski/n8n-mcp/security/advisories/GHSA-4ggg-h7ph-26qr)
— arrives as a rebase rather than an image tag.

**Against writing our own (2).** The tool surface is hundreds of endpoints of
n8n domain knowledge. Reproducing it would take months and be worse.

**For the gateway (3).** The separation lines up exactly with the trust
boundaries:

| Concern | Where it lives |
| --- | --- |
| Who is calling, and may they? | gateway |
| Which instance, and with whose credential? | gateway |
| What can be done with that credential? | n8n's own role system |
| How is it done? | n8n-mcp, unmodified |

Upgrading the tool surface becomes a version bump in a compose file. The
security-critical code is small enough to read in an afternoon and is covered by
a suite that can be exhaustive precisely because the surface is small.

## Consequences

**Accepted:**

- One extra network hop and one extra container.
- We depend on n8n-mcp's multi-tenant header contract, which is not a stability
  guarantee. `docs/security.md` and the compose comments name the exact
  behaviours relied on: the header names, the fail-closed guard added in 2.51.2,
  and the session-eviction semantics of `MULTI_TENANT_SESSION_STRATEGY`.
  The backend image is pinned exactly and bumped deliberately rather than
  auto-merged, so a contract change is read before it ships.
- The backend is stateful (sessions in process memory), so scaling it needs
  sticky sessions. The gateway is stateless and scales freely.

**Gained:**

- Upstream security fixes arrive as an image tag.
- The gateway's own code is ~1,600 lines with 303 tests, rather than a fork of a
  large codebase.
- Nothing prevents pointing the same gateway at a different MCP backend later;
  the tenant-injection contract is one file.

## Revisit if

- n8n-mcp gains native OAuth 2.1 with per-user credentials — the gateway would
  then be redundant.
- The multi-tenant header contract changes incompatibly often enough that
  pinning stops being sufficient.

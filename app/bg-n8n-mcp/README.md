# bg-n8n-mcp

The gateway application. Deployment, configuration and the security model live
in the [repository root](../../README.md); this page is the code map.

```bash
pnpm install
pnpm check     # biome + tsc --noEmit + vitest --coverage
pnpm dev       # runs src/main.ts directly via Node's type stripping
```

## Layout

```text
src/
├── main.ts                 process entrypoint: parse config → logger → store → bind
├── app.ts                  route table and middleware assembly
├── config.ts               env → validated Config; every fail-closed invariant
├── logger.ts               pino, with redaction as a backstop
│
├── lib/
│   ├── crypto.ts           HKDF keyring, AES-256-GCM seal/unseal, peppered hashing
│   └── request.ts          client IP from X-Forwarded-For, form-body parsing
│
├── n8n/
│   ├── tenant.ts           allowlist + address-space guard  ← the security boundary
│   ├── api-key.ts          reads n8n's JWT API-key claims (never verifies)
│   ├── probe.ts            live key validation, seven distinguishable outcomes
│   └── credential.ts       the three checks in order, and which failures lock out
│
├── oauth/
│   ├── metadata.ts         RFC 8414 + RFC 9728 documents, canonical resource URIs
│   ├── clients.ts          RFC 7591 registration, CIMD, RFC 8252 redirect matching
│   └── routes.ts           /authorize /token /register /revoke
│
├── proxy/
│   └── mcp.ts              the reverse proxy: token swap, header shaping, streaming
│
├── middleware/
│   └── security.ts         request ids, CSP/HSTS, CORS, path normalisation
│
├── store/
│   ├── backend.ts          the five-operation key/value contract
│   ├── memory.ts           development only
│   ├── redis.ts            production; node-redis v6
│   └── index.ts            typed accessors — grants, tokens, codes, counters
│
└── ui/
    ├── i18n.ts             de/en strings for the consent screen
    ├── pages.ts            consent screen and error page
    └── static.ts           landing page and logo
```

## Where to start reading

| If you want to understand… | Read |
| --- | --- |
| Whether this is safe | `n8n/tenant.ts`, then `tests/tenant.test.ts` |
| How a user proves who they are | `n8n/credential.ts`, `oauth/routes.ts` |
| Why discovery works at a sub-path | `oauth/metadata.ts` |
| What reaches n8n-mcp | `proxy/mcp.ts`, then `tests/proxy.test.ts` |
| Why the process refuses to start | `config.ts` |

Each of those files opens with a comment explaining what it is responsible for
and what goes wrong without it.

## Toolchain

| | |
| --- | --- |
| Runtime | Node 26 in the image; `engines` permits 24; CI tests both |
| Package manager | pnpm 11, pinned via `packageManager` — **not** Corepack, which Node unbundled at 25.0.0 |
| Compiler | TypeScript 7 (the native Go compiler), strict everywhere, `erasableSyntaxOnly` |
| Lint + format | Biome 2 — one tool, the way ruff is one tool in the sibling Python servers |
| Tests | Vitest 4, v8 coverage with enforced thresholds |
| HTTP | Hono 4 on `@hono/node-server` 2 |

Settings note: pnpm 11 made `.npmrc` auth-and-registry-only. Every pnpm
*setting* is in `pnpm-workspace.yaml`; one left in `.npmrc` is silently ignored.

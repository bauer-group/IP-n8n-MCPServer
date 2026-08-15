# Contributing

Internal BAUER GROUP project. Small enough that process should stay out of the
way — this page is the handful of things that are not obvious from the code.

## Getting set up

```bash
cd app/bg-n8n-mcp
pnpm install
```

pnpm installs itself at the version pinned in `package.json`'s `packageManager`
field, so there is nothing to install first beyond Node 24 or 26.

Note that pnpm **settings** live in `pnpm-workspace.yaml`, not `.npmrc` — pnpm
11 made `.npmrc` auth-and-registry-only, and a setting left behind there is
silently ignored. That is the pnpm-11 upgrade trap and it costs an afternoon.

## The gate

Run this before you commit. CI runs the same three commands, and so does the
Docker test stage, so a green local run means a green build.

```bash
pnpm check      # biome check + tsc --noEmit + vitest run --coverage
```

Individually: `pnpm lint`, `pnpm typecheck`, `pnpm test:coverage`.
`pnpm lint:fix` applies the safe fixes.

## Conventions worth knowing

**`tsconfig` is strict everywhere, including `noPropertyAccessFromIndexSignature`.**
That is why you will see `query['client_id']` rather than `query.client_id`: the
bracket form keeps "this came from an index signature and may be undefined"
visible at every read of untrusted query and form data. Biome's `useLiteralKeys`
is switched off because it contradicts exactly that, and the TypeScript flag is
the more valuable of the two.

**`erasableSyntaxOnly` is on.** No enums, no namespaces, no parameter
properties. This keeps the source inside the subset Node can strip natively,
which is what makes `pnpm dev` work with no build step — and stops `pnpm dev`
and `pnpm build` diverging on which syntax is legal.

**Nothing logs through `console`.** Biome enforces it. Everything goes through
`src/logger.ts`, which redacts by path. A stray `console.log` is how an API key
reaches a log aggregator.

**Comments explain *why*, not *what*.** The codebase is small; the reasoning is
the part that is expensive to reconstruct. If a line exists because of an RFC
clause, a client quirk or an upstream advisory, say which.

## Adding a security-relevant check

1. **Put it where the boundary is**, not where it is convenient. Tenant
   validation lives in `src/n8n/tenant.ts`; credential validation lives in
   `src/n8n/credential.ts`; token validation lives in the proxy. A check in the
   wrong layer is one that a future route forgets to call.
2. **Fail closed.** If the check cannot be performed, the answer is no. Look at
   how `loadConfig` refuses to start rather than assuming a default.
3. **Add the negative test first**, in `tenant.test.ts`, `config.test.ts` or
   `proxy.test.ts` — those three are where a reviewer looks.
4. **Say what breaks without it.** Every test comment in this repository answers
   "and if this check were missing?". That is what makes the suite a description
   of the threat model rather than a list of assertions.

## Touching the OAuth surface

The two documents in `src/oauth/metadata.ts` are cross-validated by clients, so
they change together. Three specific traps, all of which fail silently:

- The well-known segment is **inserted** before the resource path, not appended.
- `resource` in the protected-resource document must be **byte-identical** to
  the identifier its URL was built from.
- `code_challenge_methods_supported` is not optional in practice — clients MUST
  refuse to proceed without it.

Discovery documents are cached by clients for ~5 minutes, globally by URL. Budget
that when testing a metadata change.

## Touching the proxy

`src/proxy/mcp.ts` has a comment block at the top listing the five properties it
must preserve. If a change touches one of them, the corresponding test in
`proxy.test.ts` should be the thing that fails first — those tests assert on
what actually reached the backend, not on what the handler returned.

Header handling is a **denylist** on purpose, so protocol headers added after
this code was written are forwarded rather than dropped. Do not turn it into an
allowlist.

## Bumping the backend

`ghcr.io/czlonkowski/n8n-mcp` is pinned exactly in all three compose files and
in `.env.example`. Bump it deliberately and read the release notes — it is a
third-party image and this gateway depends on its multi-tenant header contract.
Never below **2.51.2** (see [SECURITY.md](SECURITY.md)).

The image tag has **no `v` prefix** even though the git tag does:
`ghcr.io/czlonkowski/n8n-mcp:2.69.2`, not `:v2.69.2`.

## Commits

Conventional Commits, subject in **past tense**, max 50 characters, no period:

```text
feat(oauth): added client id metadata document support

Clients can now identify with a CIMD instead of registering, which
avoids the client-record accumulation dynamic registration causes.
Advertised via client_id_metadata_document_supported.
```

`feat` → minor, `fix` → patch, `feat!`/`BREAKING CHANGE:` → major.
semantic-release reads these to cut the version, stamp it into `package.json`
and the Dockerfile, and publish the image — so `chore(...)` on something that
ships inside the image means the change lands on `main` and never reaches a
published tag.

One commit, one logical change. No AI attribution in commit messages.

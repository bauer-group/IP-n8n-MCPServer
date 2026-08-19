# =============================================================================
# bg-n8n-mcp — BAUER GROUP n8n MCP Server
# =============================================================================
# OAuth 2.1 MCP server for n8n: it puts n8n-mcp behind a remote-connector-
# compatible authorization server, with each user authenticating using their own
# personal n8n API key. Node 26 + Hono, streamable-http passthrough.
#
# Multi-stage build with an integrated test gate:
#
#   docker build --target production -t bg-n8n-mcp .   # production only
#   docker build --target test       -t bg-n8n-mcp .   # run the gate
#   docker build                     -t bg-n8n-mcp .   # full pipeline
#
# The production stage cannot resolve unless the test stage succeeded, so a red
# suite cannot produce a pushable image.
# =============================================================================

# Node 26 rather than 24. Node 24 drops to Maintenance on 2026-10-20 — the same
# month Node 26 enters Active LTS (EOL 2029-04-30) — so building on 24 today
# buys a forced base-image migration within two months. The usual argument
# against a Current release is native addons, and this dependency tree has
# none: hono, zod, pino and node-redis are pure JavaScript.
ARG NODE_VERSION=26-alpine

# pnpm is installed from npm rather than through Corepack. Corepack stopped
# shipping with Node at 25.0.0, so a `corepack enable` line would break the day
# this image is rebuilt on a newer base. The version is duplicated from
# package.json's `packageManager` field; pnpm itself enforces that they agree.
ARG PNPM_VERSION=11.21.0


# ── Stage 1: base — pnpm plus the manifests ──────────────────────────────────
FROM node:${NODE_VERSION} AS base
ARG PNPM_VERSION
RUN npm install -g --no-audit --no-fund pnpm@${PNPM_VERSION}

WORKDIR /app

# Manifests only, so the install layers below are reused on every build that
# does not change the dependency set — which is nearly all of them.
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml .npmrc ./


# ── Stage 1a: deps — the full tree, for building and testing ─────────────────
# --frozen-lockfile fails rather than silently resolving new versions when the
# lockfile and package.json disagree. That is the whole point of committing a
# lockfile: the image contains the dependency graph that was reviewed, not
# whatever npm published since.
FROM base AS deps
RUN pnpm install --frozen-lockfile


# ── Stage 1b: deps-prod — the runtime tree, resolved independently ───────────
# A second install from the same lockfile rather than `pnpm prune --prod` on the
# first. `pnpm prune` re-resolves the workspace, which in a container reaches
# for the registry and starts pulling optional dependencies for OTHER platforms
# (a build here was seen fetching @biomejs/cli-darwin-arm64 and then hanging on
# a retry). Two independent installs are both cache-friendly and hermetic — and
# this one is small, since nothing in the runtime set has platform binaries.
FROM base AS deps-prod
RUN pnpm install --frozen-lockfile --prod --ignore-scripts


# ── Stage 2: build — typecheck and emit dist/ ────────────────────────────────
FROM deps AS build
COPY tsconfig.json tsconfig.build.json ./
COPY src/ ./src/
RUN pnpm run build


# ── Stage 3: test — lint, typecheck, unit tests with coverage ────────────────
# The same three checks `pnpm check` runs locally and CI runs on every PR, so a
# green local run means a green image build.
FROM deps AS test
COPY tsconfig.json tsconfig.build.json biome.jsonc vitest.config.ts ./
COPY src/ ./src/
COPY tests/ ./tests/

# The binaries are invoked directly out of node_modules/.bin rather than through
# `pnpm exec`, and that is not a style preference. `pnpm exec` re-verifies the
# workspace before running, which in a container reaches for the registry and
# starts fetching optional dependencies for OTHER platforms — a build here was
# observed downloading @biomejs/cli-darwin-arm64 and then retrying on a network
# error. Calling the binaries directly makes this stage hermetic: after `deps`,
# the build needs no network at all.
#
# `env -i` wipes anything the build environment exported that the config parser
# would otherwise pick up during test-time validation — a CI runner with a
# repository variable named PUBLIC_BASE_URL, say. Without it the suite passes or
# fails depending on who is building it. PATH is re-supplied because vitest has
# to be able to find `node`.
RUN env -i HOME="$HOME" PATH="$PATH" CI=1 node_modules/.bin/biome check src tests \
 && env -i HOME="$HOME" PATH="$PATH" CI=1 node_modules/.bin/tsc -p tsconfig.json --noEmit \
 && env -i HOME="$HOME" PATH="$PATH" CI=1 node_modules/.bin/vitest run --coverage


# ── Stage 4: production ──────────────────────────────────────────────────────
FROM node:${NODE_VERSION} AS production

# Supplied by --build-arg from the release workflow (see
# .github/workflows/docker-release.yml). Deliberately NOT a real version: the
# reusable build workflow checks out the commit that TRIGGERED the run, which
# precedes semantic-release's own chore(release) commit — so anything stamped
# into this file by that commit is invisible to the build. An image built
# without the build-arg must therefore be obviously unversioned rather than
# plausibly one release behind. Matches the fallback in src/main.ts.
ARG APP_VERSION=0.0.0-dev

LABEL vendor="BAUER GROUP"
LABEL maintainer="Karl Bauer <karl.bauer@bauer-group.com>"

LABEL org.opencontainers.image.title="bg-n8n-mcp — BAUER GROUP n8n MCP Server"
LABEL org.opencontainers.image.licenses="MIT"
LABEL org.opencontainers.image.vendor="BAUER GROUP"
LABEL org.opencontainers.image.authors="Karl Bauer <karl.bauer@bauer-group.com>"
LABEL org.opencontainers.image.source="https://github.com/bauer-group/IP-n8n-MCPServer"
LABEL org.opencontainers.image.url="https://github.com/bauer-group/IP-n8n-MCPServer"
LABEL org.opencontainers.image.documentation="https://github.com/bauer-group/IP-n8n-MCPServer#readme"
LABEL org.opencontainers.image.description="bg-n8n-mcp — OAuth 2.1 MCP server for n8n, fronting n8n-mcp as a remote connector with per-user n8n API keys (BAUER GROUP)"
LABEL com.bauer-group.image.component="mcp-server"
LABEL com.bauer-group.image.stack="n8n"
LABEL org.opencontainers.image.version="0.3.2"

RUN apk add --no-cache tini tzdata ca-certificates curl \
 && rm -rf /var/cache/apk/* \
 && addgroup -g 1001 -S mcp \
 && adduser -S -D -u 1001 -G mcp -h /home/mcp mcp

WORKDIR /app

# Hard test-stage gate: if the suite failed, this COPY has nothing to resolve
# and the production build fails with it. The file itself is irrelevant —
# package.json is simply guaranteed to exist in the test stage.
COPY --from=test /app/package.json /tmp/_test_passed
RUN rm /tmp/_test_passed

# pnpm-workspace.yaml sets `nodeLinker: hoisted`, so node_modules is a plain
# npm-shaped tree that survives a COPY between stages. With pnpm's default
# symlinked layout it would arrive here as dangling links into a .pnpm/
# directory that was never copied.
COPY --from=deps-prod --chown=mcp:mcp /app/node_modules ./node_modules
COPY --from=build --chown=mcp:mcp /app/dist ./dist
COPY --chown=mcp:mcp package.json ./package.json

ENV NODE_ENV=production \
    APP_VERSION=${APP_VERSION} \
    MCP_PORT=8080

USER mcp
EXPOSE 8080

# /healthz is liveness only — it answers as long as the process can serve a
# request. Readiness (which additionally requires Redis) is /readyz; use that
# one for load-balancer membership, not for deciding whether to restart.
#
# Shell form so ${MCP_PORT} expands at runtime. A Compose `healthcheck:` block
# replaces this entirely when present; this is the fallback for anyone running
# the image directly.
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD curl -fsS http://127.0.0.1:${MCP_PORT}/healthz || exit 1

# tini as PID 1 forwards SIGTERM to node, so `docker stop` triggers the graceful
# shutdown in main.ts rather than a 10-second wait for SIGKILL.
ENTRYPOINT ["/sbin/tini", "--"]
CMD ["node", "dist/main.js"]


# -----------------------------------------------------------------------------
# Runtime notes
# -----------------------------------------------------------------------------
# Liveness:   GET /healthz   (unauthenticated)
# Readiness:  GET /readyz    (unauthenticated; 503 when the grant store is down)
# Landing:    GET /          (unauthenticated; shows the connector URL pattern)
#
# Required environment: PUBLIC_BASE_URL, N8N_MCP_AUTH_TOKEN,
# AUTH_STORAGE_ENCRYPTION_KEY, AUTH_REDIS_URL, and one of N8N_ALLOWED_HOSTS /
# N8N_ALLOWED_HOST_PATTERN. The process exits 78 (EX_CONFIG) with a precise
# message if any of them is missing or wrong — it never starts half-configured.

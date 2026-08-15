import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    // Node environment only — this service has no DOM surface. The HTML the
    // consent screen renders is asserted as a string, not parsed by jsdom.
    environment: 'node',
    globals: false,
    include: ['tests/**/*.test.ts'],

    // Each test file gets a fresh module registry. src/config.ts and
    // src/store/index.ts both hold module-level singletons initialised from
    // process.env; without isolation a test that sets ALLOWED_HOST_PATTERN
    // would leak that pattern into every file that ran afterwards.
    isolate: true,

    coverage: {
      provider: 'v8',
      reporter: ['text', 'lcov', 'json-summary'],
      include: ['src/**/*.ts'],
      // main.ts is the process entrypoint: it binds a socket and installs
      // signal handlers. It is exercised by the container HEALTHCHECK and the
      // compose smoke test, not by unit tests, and importing it under vitest
      // would start a real server.
      exclude: ['src/main.ts', 'src/**/*.d.ts'],
      // Gates, not aspirations — CI fails below these. They sit a little under
      // what the suite currently achieves (≈94% lines / 84% branches) so an
      // unrelated change does not turn red on a rounding difference.
      //
      // Branches is the lowest of the four on purpose, and it is worth saying
      // why rather than leaving it looking like slack. The v8 provider counts
      // every `?.`, `??` and `catch` as a branch, and a large share of those
      // here are defensive paths that cannot be reached without breaking an
      // invariant the type system already enforces — `response.body?.cancel()`
      // on a body that is always present, say. The remaining genuine gap is
      // `RedisBackend.connect`, which needs a live Redis; its command mapping
      // is covered against a fake in tests/redis-backend.test.ts, and the
      // connection itself is exercised by the compose stack's healthcheck.
      thresholds: {
        lines: 90,
        statements: 88,
        functions: 85,
        branches: 80,
      },
    },
  },
});

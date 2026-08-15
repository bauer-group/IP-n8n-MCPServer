/**
 * Configuration parsing and the fail-closed invariants.
 *
 * Each `expect(...).toThrow` here corresponds to a deployment that would
 * otherwise have started and served traffic with a security property quietly
 * missing.
 */

import { describe, expect, it } from 'vitest';
import { loadConfig } from '../src/config.js';
import { TEST_STORAGE_KEY, testEnv } from './helpers.js';

describe('loadConfig', () => {
  it('parses a valid development environment', () => {
    const config = loadConfig(testEnv());
    expect(config.baseUrl).toBe('https://mcp.test.example');
    expect(config.storeKind).toBe('memory');
    expect(config.storageKey).toHaveLength(32);
    expect(config.isDevelopment).toBe(true);
  });

  it('strips trailing slashes from PUBLIC_BASE_URL', () => {
    // The base URL is concatenated into every resource identifier; a stray
    // slash produces `…//i/host/mcp`, which no longer matches the `resource`
    // the client sends and fails audience validation with no useful error.
    const config = loadConfig(testEnv({ PUBLIC_BASE_URL: 'https://mcp.test.example///' }));
    expect(config.baseUrl).toBe('https://mcp.test.example');
  });

  it('reports every problem at once instead of one per restart', () => {
    const broken = { ENVIRONMENT: 'production' } as NodeJS.ProcessEnv;
    try {
      loadConfig(broken);
      expect.unreachable('should have thrown');
    } catch (error) {
      const message = (error as Error).message;
      expect(message).toContain('PUBLIC_BASE_URL');
      expect(message).toContain('N8N_MCP_AUTH_TOKEN');
      expect(message).toContain('AUTH_STORAGE_ENCRYPTION_KEY');
    }
  });

  describe('fail-closed invariants', () => {
    it('refuses plain http outside development', () => {
      expect(() =>
        loadConfig(
          testEnv({
            ENVIRONMENT: 'production',
            PUBLIC_BASE_URL: 'http://mcp.test.example',
            AUTH_REDIS_URL: 'redis://redis:6379',
          }),
        ),
      ).toThrow(/must use https/);
    });

    it('allows plain http in development', () => {
      expect(() => loadConfig(testEnv({ PUBLIC_BASE_URL: 'http://localhost:8080' }))).not.toThrow();
    });

    it('refuses to start with no tenant allowlist at all', () => {
      // An empty allowlist is a deployment that forgot to say who it serves,
      // not an instruction to serve everyone.
      expect(() =>
        loadConfig(testEnv({ N8N_ALLOWED_HOSTS: '', N8N_ALLOWED_HOST_PATTERN: '' })),
      ).toThrow(/N8N_ALLOWED_HOSTS/);
    });

    it('refuses the in-memory store outside development', () => {
      expect(() => loadConfig(testEnv({ ENVIRONMENT: 'production', AUTH_REDIS_URL: '' }))).toThrow(
        /AUTH_REDIS_URL is required/,
      );
    });

    it('refuses a storage key that is not exactly 32 bytes', () => {
      expect(() =>
        loadConfig(testEnv({ AUTH_STORAGE_ENCRYPTION_KEY: Buffer.alloc(16).toString('base64') })),
      ).toThrow(/exactly 32 bytes/);
    });

    it('refuses an upstream token that is too short to be a real secret', () => {
      expect(() => loadConfig(testEnv({ N8N_MCP_AUTH_TOKEN: 'short' }))).toThrow(/32 characters/);
    });

    it("refuses n8n-mcp's shipped placeholder token", () => {
      expect(() =>
        loadConfig(
          testEnv({ N8N_MCP_AUTH_TOKEN: 'REPLACE_THIS_AUTH_TOKEN_32_CHARS_MIN_abcdefgh' }),
        ),
      ).toThrow(/default token/);
    });

    it('refuses a CHANGE_ME placeholder that survived .env editing', () => {
      expect(() =>
        loadConfig(testEnv({ N8N_MCP_AUTH_TOKEN: `CHANGE_ME${'x'.repeat(40)}` })),
      ).toThrow(/CHANGE_ME/);
    });

    it('refuses a refresh token shorter-lived than an access token', () => {
      expect(() =>
        loadConfig(testEnv({ AUTH_ACCESS_TOKEN_TTL: '7200', AUTH_REFRESH_TOKEN_TTL: '3600' })),
      ).toThrow(/AUTH_REFRESH_TOKEN_TTL/);
    });
  });

  describe('list parsing', () => {
    it('produces an array even when the variable is absent', () => {
      // Zod 4 changed `.default()` to short-circuit parsing, so a csv field
      // defaulted with `''` yields the STRING and every `.length` downstream
      // silently reads a character count instead of an element count. Here
      // MCP_ALLOWED_CLIENT_REDIRECT_URIS is unset, so it takes its default —
      // and that default must still be an array.
      const env = testEnv();
      delete env['MCP_ALLOWED_CLIENT_REDIRECT_URIS'];
      const config = loadConfig(env);
      expect(config.MCP_ALLOWED_CLIENT_REDIRECT_URIS).toEqual([]);
      expect(Array.isArray(config.N8N_ALLOWED_HOSTS)).toBe(true);
    });

    it('tolerates whitespace and empty entries', () => {
      const config = loadConfig(testEnv({ N8N_ALLOWED_HOSTS: ' a.example , , b.example ' }));
      expect(config.N8N_ALLOWED_HOSTS).toEqual(['a.example', 'b.example']);
    });
  });

  describe('boolean parsing', () => {
    it.each([['true'], ['1'], ['yes'], ['on'], ['TRUE']])('reads %s as true', (value) => {
      expect(
        loadConfig(testEnv({ N8N_ALLOW_PRIVATE_ADDRESSES: value })).N8N_ALLOW_PRIVATE_ADDRESSES,
      ).toBe(true);
    });

    it.each([['false'], ['0'], ['no'], ['']])('reads %s as false', (value) => {
      expect(
        loadConfig(testEnv({ N8N_ALLOW_PRIVATE_ADDRESSES: value })).N8N_ALLOW_PRIVATE_ADDRESSES,
      ).toBe(false);
    });
  });

  it('rejects an out-of-range numeric setting instead of clamping it', () => {
    expect(() => loadConfig(testEnv({ MCP_PORT: '70000' }))).toThrow();
    expect(() => loadConfig(testEnv({ AUTH_ACCESS_TOKEN_TTL: '5' }))).toThrow();
  });

  it('keeps the storage key out of the derived config surface', () => {
    const config = loadConfig(testEnv({ AUTH_STORAGE_ENCRYPTION_KEY: TEST_STORAGE_KEY }));
    // It is present as a Buffer for the keyring, and Buffers do not stringify
    // into a JSON log the way a base64 string would.
    expect(Buffer.isBuffer(config.storageKey)).toBe(true);
  });
});

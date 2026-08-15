#!/usr/bin/env node
/**
 * generate-env.mjs — create a `.env` from `.env.example` with real secrets.
 *
 * Cross-platform (Windows / Linux / macOS), Node 24+, zero dependencies. The
 * sibling BAUER GROUP MCP servers ship the same tool as a Python script; this
 * is a Node project, so it is a Node script — no second runtime to install.
 *
 * Replaces every `CHANGE_ME_*` placeholder that names a known secret:
 *
 *   N8N_MCP_AUTH_TOKEN            32 random bytes, base64 (shared with n8n-mcp)
 *   AUTH_STORAGE_ENCRYPTION_KEY   32 random bytes, base64 (seals the API keys)
 *
 * Everything else — the hostname, the allowlist — is left in place for the
 * operator to fill in by hand, deliberately. A generated allowlist would be a
 * guess about who this deployment serves, and the gateway refuses to start
 * without one, so a wrong guess is worse than an obvious blank.
 *
 * Usage
 * -----
 *   node scripts/generate-env.mjs               # writes .env (refuses to overwrite)
 *   node scripts/generate-env.mjs --force       # overwrite, keeping a .env.bak
 *   node scripts/generate-env.mjs --dry-run     # show what would change
 *   node scripts/generate-env.mjs --print       # write nothing, dump to stdout
 *   node scripts/generate-env.mjs --output .env.staging --example .env.example
 *
 * Exit codes
 * ----------
 *   0  success
 *   1  precondition failed (.env.example missing, .env exists without --force)
 *   2  nothing to replace — the example had no known CHANGE_ME_* placeholders
 */

import { randomBytes } from 'node:crypto';
import { copyFileSync, existsSync, readFileSync, writeFileSync, chmodSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseArgs } from 'node:util';

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');

/**
 * Secrets this script knows how to generate, keyed by variable name.
 *
 * Both are 32 random bytes, base64 — the shape `openssl rand -base64 32`
 * produces, which is what the docs tell operators to run and what
 * AUTH_STORAGE_ENCRYPTION_KEY is validated against at boot.
 */
const SECRETS = {
  N8N_MCP_AUTH_TOKEN: 'shared secret between the gateway and n8n-mcp',
  AUTH_STORAGE_ENCRYPTION_KEY: 'AES-256-GCM key sealing every stored n8n API key',
};

const PLACEHOLDER = /^([A-Z0-9_]+)=(CHANGE_ME[A-Z0-9_]*)\s*$/;

function generate() {
  return randomBytes(32).toString('base64');
}

function main() {
  const { values } = parseArgs({
    options: {
      example: { type: 'string', default: '.env.example' },
      output: { type: 'string', default: '.env' },
      force: { type: 'boolean', default: false },
      'dry-run': { type: 'boolean', default: false },
      print: { type: 'boolean', default: false },
      help: { type: 'boolean', short: 'h', default: false },
    },
  });

  if (values.help) {
    process.stdout.write(`${readFileSync(fileURLToPath(import.meta.url), 'utf8')
      .split('\n')
      .slice(1)
      .filter((line) => line.startsWith(' *') || line.startsWith('/**'))
      .map((line) => line.replace(/^\/?\*+ ?/, ''))
      .join('\n')}\n`);
    return 0;
  }

  const examplePath = resolve(REPO_ROOT, values.example);
  const outputPath = resolve(REPO_ROOT, values.output);

  if (!existsSync(examplePath)) {
    process.stderr.write(`error: ${examplePath} does not exist\n`);
    return 1;
  }

  const writing = !values['dry-run'] && !values.print;
  if (writing && existsSync(outputPath) && !values.force) {
    process.stderr.write(
      `error: ${outputPath} already exists. Use --force to overwrite (a .bak is kept first).\n`,
    );
    return 1;
  }

  const lines = readFileSync(examplePath, 'utf8').split(/\r?\n/);
  const replaced = [];
  const remaining = [];

  const rendered = lines.map((line) => {
    const match = PLACEHOLDER.exec(line);
    if (!match) return line;
    const [, name] = match;
    if (name && Object.hasOwn(SECRETS, name)) {
      replaced.push(name);
      return `${name}=${generate()}`;
    }
    if (name) remaining.push(name);
    return line;
  });

  if (!replaced.length) {
    process.stderr.write('error: no known CHANGE_ME_* placeholders found — nothing to do\n');
    return 2;
  }

  const output = rendered.join('\n');

  if (values.print) {
    process.stdout.write(output);
    return 0;
  }

  for (const name of replaced) {
    process.stdout.write(`  generated  ${name.padEnd(30)} ${SECRETS[name]}\n`);
  }
  for (const name of remaining) {
    process.stdout.write(`  TO FILL IN ${name}\n`);
  }

  if (values['dry-run']) {
    process.stdout.write(`\n(dry run — ${outputPath} not written)\n`);
    return 0;
  }

  if (existsSync(outputPath)) {
    copyFileSync(outputPath, `${outputPath}.bak`);
    process.stdout.write(`\n  backed up  ${outputPath}.bak\n`);
  }

  writeFileSync(outputPath, output, { encoding: 'utf8' });
  try {
    // Owner read/write only. A no-op on Windows, which is why it is wrapped
    // rather than allowed to fail the run there.
    chmodSync(outputPath, 0o600);
  } catch {
    /* not supported on this platform */
  }

  process.stdout.write(`\n  wrote      ${outputPath}\n`);
  if (remaining.length) {
    process.stdout.write(
      `\nStill required before the stack will start:\n${remaining.map((n) => `  - ${n}`).join('\n')}\n`,
    );
  }
  return 0;
}

process.exit(main());

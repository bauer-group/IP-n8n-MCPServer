/**
 * The landing page and the logo.
 *
 * Both are inlined as template strings rather than read from a `static/`
 * directory. That is a deliberate trade against the sibling Python servers,
 * which ship files: with a TypeScript build, a `static/` directory has to be
 * copied into the image as a second artefact and located at runtime relative to
 * `dist/`, which is one more thing that can be right in development and missing
 * in production. Inlining makes the image exactly `dist/` plus `node_modules/`,
 * and a missing asset becomes a compile error instead of a 404.
 *
 * The page is unauthenticated and deliberately says nothing an operator would
 * mind a stranger reading: no hostnames, no instance list, no tenant count.
 */

import type { Config } from '../config.js';
import { type Locale, strings } from './i18n.js';
import { escapeHtml } from './pages.js';

/**
 * Escape a translated string, then substitute markup for its `{placeholders}`.
 *
 * The order is the point: the prose is escaped as the untrusted-shaped thing it
 * is, and only the fragments supplied here — authored next to the call, never
 * in the string table — arrive as HTML. A translator cannot introduce markup,
 * and a translation that drops a placeholder loses formatting rather than
 * breaking the page.
 */
export function fill(template: string, parts: Readonly<Record<string, string>>): string {
  // Object.hasOwn, not a bare lookup: `\w+` happily matches `constructor` and
  // `toString`, which a plain index would resolve on Object.prototype and
  // splice in as raw HTML. No string here contains such a placeholder today —
  // which is exactly when this is one word to get right rather than an
  // incident to explain.
  return escapeHtml(template).replace(/\{(\w+)\}/g, (whole: string, key: string) => {
    const part = Object.hasOwn(parts, key) ? parts[key] : undefined;
    return part ?? whole;
  });
}

/**
 * JSON for embedding directly in a `<script>` element.
 *
 * `<` is escaped because the HTML parser looks for `</script` inside script
 * content before any JavaScript runs: a string containing it would end the
 * element early. Nothing in the string table contains one today, which is
 * exactly when this is cheap to get right.
 */
function jsonForScript(value: unknown): string {
  return JSON.stringify(value).replace(/</g, '\\u003c');
}

/** BAUER GROUP mark. */
export function logoSvg(): string {
  return `<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 180.48 180.42" role="img" aria-label="BAUER GROUP">
  <title>BAUER GROUP</title>
  <path fill-rule="nonzero" fill="rgb(96.186829%, 49.583435%, 7.623291%)" d="M 0 53.746094 L 126.671875 0.00390625 L 180.476562 126.679688 L 53.804688 180.421875 L 0 53.746094 "/>
  <path fill-rule="evenodd" fill="rgb(100%, 100%, 100%)" d="M 92.921875 47.1875 C 100.414062 47.1875 106.671875 47.351562 111.695312 47.679688 C 116.722656 48.011719 120.320312 48.484375 122.492188 49.105469 C 128.199219 50.695312 132.503906 52.984375 135.414062 55.96875 C 138.328125 58.949219 139.78125 62.535156 139.78125 66.722656 C 139.78125 70.988281 138.445312 74.640625 135.769531 77.683594 C 133.09375 80.726562 129.117188 83.101562 123.84375 84.808594 C 130.199219 86.4375 135.179688 89.113281 138.78125 92.835938 C 142.386719 96.558594 144.191406 100.84375 144.191406 105.691406 C 144.191406 110.265625 142.976562 114.175781 140.554688 117.414062 C 138.128906 120.652344 134.453125 123.257812 129.527344 125.234375 C 126.695312 126.359375 122.71875 127.195312 117.601562 127.738281 C 112.480469 128.28125 105.980469 128.550781 98.105469 128.550781 L 53.578125 128.550781 L 49.859375 125.109375 C 50.167969 118.246094 50.402344 111.714844 50.558594 105.507812 C 50.714844 99.304688 50.792969 93.3125 50.792969 87.535156 C 50.792969 81.757812 50.714844 75.84375 50.558594 69.796875 C 50.402344 63.746094 50.167969 57.484375 49.859375 51.011719 L 53.808594 47.1875 Z M 88.667969 55.644531 L 88.4375 83.757812 C 92.476562 83.292969 95.691406 81.800781 98.078125 79.277344 C 100.46875 76.753906 101.660156 73.59375 101.660156 69.789062 C 101.660156 66.027344 100.484375 62.871094 98.136719 60.332031 C 95.785156 57.789062 92.632812 56.226562 88.667969 55.644531 Z M 88.4375 91.503906 L 88.667969 120.09375 C 93.6875 119.628906 97.679688 118.078125 100.65625 115.445312 C 103.628906 112.8125 105.113281 109.558594 105.113281 105.683594 C 105.113281 101.847656 103.578125 98.613281 100.507812 95.976562 C 97.4375 93.34375 93.414062 91.851562 88.4375 91.503906 "/>
</svg>`;
}

const LANDING_STYLE = `
:root{
  --orange-100:#FFEDD5;--orange-500:#FF8500;--orange-600:#EA6D00;--orange-800:#9A4509;
  --warm-50:#F9F8F6;--warm-100:#F0EDEA;--warm-200:#E0DBD6;--warm-500:#887F78;
  --warm-600:#6B635C;--warm-800:#3A3430;--warm-900:#231F1C;
  --bg:#FFFFFF;--bg-subtle:var(--warm-50);--border:var(--warm-200);
  --text:var(--warm-900);--text-muted:var(--warm-600);
  --ok-bg:#DCFCE7;--ok-fg:#15803D;--warn-bg:#FEF9C3;--warn-fg:#A16207;
  --err-bg:#FEE2E2;--err-fg:#B91C1C;
  --font:system-ui,-apple-system,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif;
  --mono:ui-monospace,SFMono-Regular,Menlo,Consolas,"Liberation Mono",monospace;
}
@media (prefers-color-scheme:dark){
  :root{--bg:#1A1715;--bg-subtle:#221E1B;--border:#3A3430;--text:#F5F2EF;--text-muted:#B5ADA6;
        --ok-bg:#14321F;--ok-fg:#86EFAC;--warn-bg:#3A2E0B;--warn-fg:#FDE047;
        --err-bg:#3B1414;--err-fg:#FCA5A5;}
}
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:var(--font);color:var(--text);background:var(--bg-subtle);
  min-height:100vh;display:flex;align-items:center;justify-content:center;padding:1.5rem;line-height:1.6;
  -webkit-font-smoothing:antialiased}
.card{width:100%;max-width:46rem;background:var(--bg);border:1px solid var(--border);
  border-radius:18px;overflow:hidden;box-shadow:0 16px 40px rgba(35,31,28,.08)}
.head{padding:2.25rem 2.25rem 1.75rem;text-align:center;border-bottom:1px solid var(--border);position:relative}
.head::before{content:'';position:absolute;top:0;left:0;right:0;height:4px;
  background:linear-gradient(90deg,var(--orange-500),var(--orange-600))}
.head img{width:62px;height:62px;margin-bottom:1rem}
h1{font-size:1.6rem;font-weight:650;letter-spacing:-.015em}
.sub{color:var(--text-muted);margin-top:.4rem;font-size:.95rem}
.grid{display:grid;grid-template-columns:1fr;gap:1rem;padding:1.75rem 2.25rem}
@media(min-width:640px){.grid{grid-template-columns:repeat(3,1fr)}}
.tile{background:var(--bg-subtle);border:1px solid var(--border);border-radius:12px;padding:1rem}
.tile .k{font-size:.7rem;text-transform:uppercase;letter-spacing:.08em;color:var(--text-muted);font-weight:650}
.tile .v{margin-top:.35rem;font-weight:600;font-size:1.02rem;overflow-wrap:anywhere}
.pill{display:inline-flex;align-items:center;gap:.4rem;padding:.2rem .6rem;border-radius:999px;
  font-size:.82rem;font-weight:650;background:var(--warm-100);color:var(--warm-800)}
.pill.ok{background:var(--ok-bg);color:var(--ok-fg)}
.pill.warn{background:var(--warn-bg);color:var(--warn-fg)}
.pill.err{background:var(--err-bg);color:var(--err-fg)}
.dot{width:7px;height:7px;border-radius:50%;background:currentColor}
section{padding:0 2.25rem 1.75rem}
h2{font-size:.72rem;text-transform:uppercase;letter-spacing:.08em;color:var(--text-muted);
  font-weight:650;margin-bottom:.7rem}
ol{margin:0 0 1rem 1.15rem;color:var(--text-muted);font-size:.93rem}
ol li::marker{color:var(--orange-500);font-weight:700}
code{font-family:var(--mono);font-size:.87em;background:var(--bg-subtle);border:1px solid var(--border);
  padding:.1rem .35rem;border-radius:5px;overflow-wrap:anywhere}
.copy{display:flex;background:var(--bg-subtle);border:1px solid var(--border);border-radius:10px;overflow:hidden}
.copy input{flex:1;min-width:0;border:0;background:transparent;color:var(--text);
  font-family:var(--mono);font-size:.88rem;padding:.7rem .85rem}
.copy input:focus{outline:none}
.copy button{border:0;background:var(--orange-500);color:#fff;font:inherit;font-weight:650;font-size:.85rem;
  padding:0 1.1rem;cursor:pointer}
.copy button:hover{background:var(--orange-600)}
table{width:100%;border-collapse:collapse;font-size:.88rem}
td{padding:.5rem 0;border-bottom:1px solid var(--border);vertical-align:top}
tr:last-child td{border-bottom:0}
td.m{width:4.5rem}
.method{font-family:var(--mono);font-size:.72rem;font-weight:700;padding:.15rem .4rem;border-radius:4px;
  background:var(--warm-100);color:var(--warm-800)}
td.p{font-family:var(--mono);color:var(--text)}
td.n{color:var(--text-muted);text-align:right;font-size:.82rem}
.foot{padding:1.15rem;text-align:center;font-size:.8rem;color:var(--text-muted);
  background:var(--bg-subtle);border-top:1px solid var(--border)}
.foot a{color:var(--orange-600);text-decoration:none;font-weight:600}
`;

/**
 * The unauthenticated landing page.
 *
 * Its real job is answering "did I deploy this correctly and what URL do I
 * paste into Claude" without anyone having to open the README. The connector
 * URL is shown as a **pattern** rather than a concrete address, because this
 * gateway serves many n8n instances and the list of which ones is not public
 * information.
 */
export function landingPage(
  config: Config,
  version: string,
  nonce: string,
  locale: Locale,
): string {
  const pattern = `${config.baseUrl}/i/<n8n-host>/mcp`;
  const env = escapeHtml(config.ENVIRONMENT);
  const t = strings(locale).landing;

  return `<!doctype html>
<html lang="${locale}">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<title>${escapeHtml(config.MCP_DISPLAY_NAME)} — MCP Server</title>
<link rel="icon" type="image/svg+xml" href="/logo.svg">
<style>${LANDING_STYLE}</style>
</head>
<body>
<main class="card">
  <div class="head">
    <img src="/logo.svg" alt="BAUER GROUP" width="62" height="62">
    <h1>${escapeHtml(config.MCP_DISPLAY_NAME)} MCP Server</h1>
    <p class="sub">${escapeHtml(t.subtitle)}</p>
  </div>

  <div class="grid">
    <div class="tile">
      <div class="k">${escapeHtml(t.statusLabel)}</div>
      <div class="v"><span id="status" class="pill"><span class="dot"></span><span id="status-text">${escapeHtml(t.statusChecking)}</span></span></div>
    </div>
    <div class="tile">
      <div class="k">${escapeHtml(t.versionLabel)}</div>
      <div class="v">${escapeHtml(version)}</div>
    </div>
    <div class="tile">
      <div class="k">${escapeHtml(t.environmentLabel)}</div>
      <div class="v"><span class="pill">${env}</span></div>
    </div>
  </div>

  <section>
    <h2>${escapeHtml(t.connectorUrlTitle)}</h2>
    <p style="color:var(--text-muted);font-size:.93rem;margin-bottom:.7rem">
      ${fill(t.connectorUrlIntro, {
        host: '<code>&lt;n8n-host&gt;</code>',
        example: '<code>flow.example.com</code>',
      })}
    </p>
    <div class="copy">
      <input id="url" type="text" readonly value="${escapeHtml(pattern)}" aria-label="${escapeHtml(t.urlFieldLabel)}" spellcheck="false">
      <button id="copy" type="button">${escapeHtml(t.copy)}</button>
    </div>
  </section>

  <section>
    <h2>${escapeHtml(t.claudeTitle)}</h2>
    <ol>
      <li>${fill(t.claudeStep1, {
        // lang="en" on the fragments that stay English by design: a screen
        // reader in a lang="de" document would otherwise pronounce these with
        // German phonetics, and they are exactly the words the user has to
        // recognise on their own screen. WCAG 2.1 AA, 3.1.2 Language of Parts.
        action: '<strong lang="en">Settings → Connectors → Add custom connector</strong>',
      })}</li>
      <li>${fill(t.claudeStep2, { host: '<code>&lt;n8n-host&gt;</code>' })}</li>
      <li>${fill(t.claudeStep3, { action: '<strong lang="en">Connect</strong>' })}</li>
    </ol>
  </section>

  <section>
    <h2>${escapeHtml(t.endpointsTitle)}</h2>
    <table lang="en">
      <tr><td class="m"><span class="method">ALL</span></td><td class="p">/i/&lt;n8n-host&gt;/mcp</td><td class="n">MCP, OAuth-gated</td></tr>
      <tr><td class="m"><span class="method">GET</span></td><td class="p">/.well-known/oauth-protected-resource/i/&lt;n8n-host&gt;/mcp</td><td class="n">RFC 9728</td></tr>
      <tr><td class="m"><span class="method">GET</span></td><td class="p">/.well-known/oauth-authorization-server</td><td class="n">RFC 8414</td></tr>
      <tr><td class="m"><span class="method">GET</span></td><td class="p">/healthz · /readyz</td><td class="n">liveness · readiness</td></tr>
    </table>
  </section>

  <p class="foot">
    &copy; <span id="year">2026</span> BAUER GROUP ·
    <a href="https://github.com/bauer-group/IP-n8n-MCPServer#readme" rel="noopener noreferrer">${escapeHtml(t.documentation)}</a>
  </p>
</main>
<script nonce="${escapeHtml(nonce)}">
// Every string this script writes into the page comes from the server-side
// table, not from literals here — otherwise the status pill and the copy
// button would stay English on an otherwise translated page.
const T = ${jsonForScript({
    operational: t.statusOperational,
    degraded: t.statusDegraded,
    offline: t.statusOffline,
    copy: t.copy,
    copied: t.copied,
  })};

document.getElementById('year').textContent = new Date().getFullYear();

const pill = document.getElementById('status');
const label = document.getElementById('status-text');
async function poll() {
  try {
    const r = await fetch('/readyz', { cache: 'no-store' });
    const ok = r.ok;
    pill.className = 'pill ' + (ok ? 'ok' : 'warn');
    label.textContent = ok ? T.operational : T.degraded;
  } catch {
    pill.className = 'pill err';
    label.textContent = T.offline;
  }
}
poll();
setInterval(poll, 30000);

const input = document.getElementById('url');
const button = document.getElementById('copy');
button.addEventListener('click', async () => {
  try { await navigator.clipboard.writeText(input.value); }
  catch { input.select(); }
  button.textContent = T.copied;
  setTimeout(() => { button.textContent = T.copy; }, 1500);
});
</script>
</body>
</html>`;
}

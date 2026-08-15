/**
 * Server-rendered pages: the consent screen and the terminal error page.
 *
 * Plain strings, no template engine, no client-side framework. The consent
 * screen is the one place a user's n8n API key is typed, so the smallest
 * possible amount of code should stand between the keyboard and the POST
 * handler — no hydration, no bundle, nothing fetched from a third-party origin
 * that a `Content-Security-Policy` would have to permit.
 *
 * The page is opened by the AI client as a top-level popup and is never framed,
 * so `X-Frame-Options: DENY` and `frame-ancestors 'none'` (set in
 * middleware/security.ts) are correct here rather than something to relax.
 */

import { type Locale, type Strings, strings } from './i18n.js';

/**
 * Escape for HTML text and double-quoted attribute contexts.
 *
 * Every interpolation below goes through this. The hostname is already
 * validated to a strict character set by the time it arrives, and the client
 * name is not — it comes straight from a registration request, so it is the one
 * that matters.
 */
export function escapeHtml(value: string): string {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

/**
 * Shared stylesheet.
 *
 * BAUER GROUP orange on a warm neutral scale, matching the sibling MCP servers'
 * landing pages. System font stack rather than a webfont: a `Content-Security-
 * Policy` that permits fonts.googleapis.com on the page where a credential is
 * typed is a worse trade than slightly less distinctive typography.
 */
const STYLE = `
:root{
  --orange-100:#FFEDD5;--orange-200:#FED7AA;--orange-500:#FF8500;--orange-600:#EA6D00;--orange-800:#9A4509;
  --warm-50:#F9F8F6;--warm-100:#F0EDEA;--warm-200:#E0DBD6;--warm-400:#A69E97;--warm-500:#887F78;
  --warm-600:#6B635C;--warm-800:#3A3430;--warm-900:#231F1C;
  --bg:#FFFFFF;--bg-subtle:var(--warm-50);--border:var(--warm-200);
  --text:var(--warm-900);--text-muted:var(--warm-600);
  --danger-bg:#FEE2E2;--danger-fg:#B91C1C;--danger-border:#FCA5A5;
  --font:system-ui,-apple-system,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif;
  --mono:ui-monospace,SFMono-Regular,Menlo,Consolas,"Liberation Mono",monospace;
}
@media (prefers-color-scheme:dark){
  :root{
    --bg:#1A1715;--bg-subtle:#221E1B;--border:#3A3430;
    --text:#F5F2EF;--text-muted:#B5ADA6;
    --danger-bg:#3B1414;--danger-fg:#FCA5A5;--danger-border:#7F1D1D;
  }
}
*{box-sizing:border-box;margin:0;padding:0}
body{
  font-family:var(--font);color:var(--text);background:var(--bg-subtle);
  min-height:100vh;display:flex;align-items:center;justify-content:center;padding:1.5rem;
  -webkit-font-smoothing:antialiased;line-height:1.55;
}
.card{
  width:100%;max-width:30rem;background:var(--bg);border:1px solid var(--border);
  border-radius:16px;overflow:hidden;box-shadow:0 12px 32px rgba(35,31,28,.08);
}
.head{padding:2rem 2rem 1.25rem;position:relative}
.head::before{content:'';position:absolute;top:0;left:0;right:0;height:3px;
  background:linear-gradient(90deg,var(--orange-500),var(--orange-600))}
.brand{font-size:.75rem;letter-spacing:.09em;text-transform:uppercase;
  color:var(--text-muted);font-weight:600;margin-bottom:.5rem}
h1{font-size:1.4rem;font-weight:650;letter-spacing:-.01em}
.intro{color:var(--text-muted);font-size:.925rem;margin-top:.6rem}
.body{padding:0 2rem 2rem}
.field{margin-top:1.25rem}
label{display:block;font-size:.8125rem;font-weight:600;margin-bottom:.35rem}
input[type=text],input[type=password],input[type=email]{
  width:100%;padding:.7rem .85rem;font:inherit;font-size:.95rem;color:var(--text);
  background:var(--bg-subtle);border:1px solid var(--border);border-radius:9px;
}
input:focus{outline:2px solid var(--orange-500);outline-offset:1px;border-color:transparent}
.hint{font-size:.78rem;color:var(--text-muted);margin-top:.35rem}
.readonly{
  font-family:var(--mono);font-size:.875rem;padding:.6rem .8rem;border-radius:9px;
  background:var(--bg-subtle);border:1px solid var(--border);color:var(--text);
  overflow-wrap:anywhere;
}
button{
  width:100%;margin-top:1.6rem;padding:.8rem 1rem;font:inherit;font-weight:650;font-size:.95rem;
  color:#fff;background:var(--orange-500);border:0;border-radius:9px;cursor:pointer;
  transition:background-color .15s ease;
}
button:hover{background:var(--orange-600)}
button:focus-visible{outline:2px solid var(--orange-800);outline-offset:2px}
.alert{
  margin-top:1.25rem;padding:.8rem .9rem;border-radius:9px;font-size:.875rem;
  background:var(--danger-bg);color:var(--danger-fg);border:1px solid var(--danger-border);
}
.meta{margin-top:1.5rem;padding-top:1.15rem;border-top:1px solid var(--border);
  font-size:.8rem;color:var(--text-muted)}
.meta dt{font-weight:600;display:inline}
.meta dd{display:inline;margin-left:.35rem}
.meta div+div{margin-top:.35rem}
.foot{padding:1rem 2rem;background:var(--bg-subtle);border-top:1px solid var(--border);
  font-size:.75rem;color:var(--text-muted);text-align:center}
`;

function shell(title: string, inner: string): string {
  return `<!doctype html>
<html lang="de">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<title>${escapeHtml(title)}</title>
<style>${STYLE}</style>
</head>
<body>
<main class="card">
${inner}
</main>
</body>
</html>`;
}

export interface ConsentPageInput {
  readonly locale: Locale;
  readonly displayName: string;
  readonly hostname: string;
  readonly clientName: string | null;
  /**
   * Opaque, signed-by-storage handle for the pending authorization request.
   * The full request context lives server-side under this key; only the handle
   * travels through the form, so a user cannot rewrite `redirect_uri` or
   * `resource` by editing the page.
   */
  readonly requestId: string;
  /** Pre-fill after a failed attempt so the user only retypes the key. */
  readonly username: string;
  readonly error: string | null;
}

/**
 * The consent screen.
 *
 * Three inputs, matching the concept this gateway is built on:
 *   **path** → which n8n instance (shown, not editable — it comes from the URL)
 *   **username** → who is connecting (audit label)
 *   **password** → the n8n API key, which is the actual credential
 *
 * `autocomplete="current-password"` on the key field is deliberate: it makes
 * password managers offer to store it, which is the behaviour we want for a
 * long-lived secret people would otherwise keep in a text file.
 */
export function consentPage(input: ConsentPageInput): string {
  const t: Strings = strings(input.locale);
  const alert = input.error ? `<p class="alert" role="alert">${escapeHtml(input.error)}</p>` : '';
  const client = input.clientName
    ? `<div><dt>${escapeHtml(t.clientLabel)}:</dt><dd>${escapeHtml(input.clientName)}</dd></div>`
    : '';

  return shell(
    `${t.connectTitle} — ${input.displayName}`,
    `<div class="head">
  <p class="brand">${escapeHtml(input.displayName)}</p>
  <h1>${escapeHtml(t.connectTitle)}</h1>
  <p class="intro">${escapeHtml(t.connectIntro)}</p>
</div>
<form class="body" method="post" action="/authorize" autocomplete="on">
  <input type="hidden" name="request_id" value="${escapeHtml(input.requestId)}">
  ${alert}
  <div class="field">
    <label for="instance">${escapeHtml(t.instanceLabel)}</label>
    <p class="readonly" id="instance">${escapeHtml(input.hostname)}</p>
  </div>
  <div class="field">
    <label for="username">${escapeHtml(t.usernameLabel)}</label>
    <input id="username" name="username" type="text" required autocomplete="username"
           spellcheck="false" autocapitalize="none" maxlength="200"
           value="${escapeHtml(input.username)}">
    <p class="hint">${escapeHtml(t.usernameHint)}</p>
  </div>
  <div class="field">
    <label for="api_key">${escapeHtml(t.apiKeyLabel)}</label>
    <input id="api_key" name="api_key" type="password" required autocomplete="current-password"
           spellcheck="false" autocapitalize="none" maxlength="4096" autofocus>
    <p class="hint">${escapeHtml(t.apiKeyHint)}</p>
  </div>
  <button type="submit">${escapeHtml(t.submit)}</button>
  <dl class="meta">
    ${client}
    <div>${escapeHtml(t.privacyNote)}</div>
  </dl>
</form>
<p class="foot">BAUER GROUP</p>`,
  );
}

/**
 * Terminal error page — shown when the flow cannot continue and there is no
 * safe redirect target to send the error to.
 *
 * "No safe redirect target" is the whole reason this page exists: if the
 * `redirect_uri` is unknown or does not match the client's registration, RFC
 * 6749 §4.1.2.1 says the server MUST NOT redirect to it. Bouncing an error to
 * an unvalidated URI is an open redirect.
 */
export function errorPage(locale: Locale, displayName: string, message: string): string {
  const t = strings(locale);
  return shell(
    `${t.errorTitle} — ${displayName}`,
    `<div class="head">
  <p class="brand">${escapeHtml(displayName)}</p>
  <h1>${escapeHtml(t.errorTitle)}</h1>
</div>
<div class="body">
  <p class="alert" role="alert">${escapeHtml(message)}</p>
  <p class="hint" style="margin-top:1rem">${escapeHtml(t.backHint)}</p>
</div>
<p class="foot">BAUER GROUP</p>`,
  );
}

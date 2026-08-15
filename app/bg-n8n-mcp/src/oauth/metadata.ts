/**
 * OAuth discovery documents.
 *
 * This gateway is both roles at once: the **authorization server** (RFC 8414,
 * served at the origin root) and the **protected resource** (RFC 9728, served
 * once per tenant path). Keeping the two documents in one file makes the pair
 * easy to keep consistent, which matters because clients cross-validate them.
 *
 * The rule that catches everyone: RFC 9728 §3 says the well-known segment is
 * **inserted** between the host and the path, not appended. For an MCP endpoint
 * at
 *     https://mcp.example.com/i/flow.acme.com/mcp
 * the metadata lives at
 *     https://mcp.example.com/.well-known/oauth-protected-resource/i/flow.acme.com/mcp
 * and NOT at …/i/flow.acme.com/.well-known/…, which is the OIDC convention and
 * the wrong one here.
 *
 * RFC 9728 §3.3 then requires the `resource` field to be byte-identical to the
 * identifier the well-known URL was built from. A document that normalises,
 * lowercases differently, or drops the path is discarded by the client with no
 * useful error — so `resourceFor` is the single place that string is built.
 */

import type { Config } from '../config.js';

/**
 * The scope this server issues. One scope, because there is exactly one thing a
 * token authorises: acting against one n8n instance as the key's owner. Any
 * finer-grained authorization is n8n's own role system, which we deliberately
 * do not attempt to mirror.
 */
export const SCOPE = 'n8n';

/**
 * Advertised in AS metadata only.
 *
 * Claude appends `offline_access` to its authorization request when — and only
 * when — the authorization server lists it in `scopes_supported`; that is how a
 * client opts into a refresh token. The MCP spec separately says a server
 * SHOULD NOT put `offline_access` in protected-resource metadata or in a
 * WWW-Authenticate challenge, so it appears here and in neither of those.
 */
export const OFFLINE_SCOPE = 'offline_access';

/** Canonical MCP endpoint path for a tenant. */
export function pathForTenant(hostname: string): string {
  return `/i/${hostname.toLowerCase()}/mcp`;
}

/**
 * Canonical resource identifier (RFC 8707 audience) for a tenant.
 *
 * Lowercase scheme and host, no trailing slash, no default port, no fragment —
 * this is the exact form Claude sends as `resource`, and the exact form the
 * protected-resource document must echo.
 */
export function resourceFor(config: Config, hostname: string): string {
  return `${config.baseUrl}${pathForTenant(hostname)}`;
}

/** URL of a tenant's protected-resource metadata (RFC 9728 path insertion). */
export function resourceMetadataUrlFor(config: Config, hostname: string): string {
  return `${config.baseUrl}/.well-known/oauth-protected-resource${pathForTenant(hostname)}`;
}

/**
 * RFC 8414 authorization server metadata.
 *
 * Two fields carry more weight than their size suggests:
 *
 *  - `code_challenge_methods_supported` — MCP clients MUST refuse to start the
 *    flow if it is absent, even when the server does support PKCE. Omitting it
 *    fails discovery before anything user-visible happens.
 *  - `client_id_metadata_document_supported` — combined with `"none"` in
 *    `token_endpoint_auth_methods_supported`, this is what makes a client use a
 *    Client ID Metadata Document instead of dynamic registration. That matters
 *    operationally: DCR mints a fresh client record on every reconnect, and a
 *    busy deployment accumulates thousands.
 */
export function authorizationServerMetadata(config: Config): Record<string, unknown> {
  return {
    issuer: config.baseUrl,
    authorization_endpoint: `${config.baseUrl}/authorize`,
    token_endpoint: `${config.baseUrl}/token`,
    registration_endpoint: `${config.baseUrl}/register`,
    revocation_endpoint: `${config.baseUrl}/revoke`,

    response_types_supported: ['code'],
    response_modes_supported: ['query'],
    grant_types_supported: ['authorization_code', 'refresh_token'],

    // S256 only. `plain` is permitted by RFC 7636 and forbidden by OAuth 2.1
    // for any client that can compute a SHA-256, which is all of them.
    code_challenge_methods_supported: ['S256'],

    // Public clients throughout: MCP clients cannot keep a secret, and PKCE
    // plus exact redirect-URI matching is what carries the security.
    token_endpoint_auth_methods_supported: ['none'],
    revocation_endpoint_auth_methods_supported: ['none'],

    scopes_supported: [SCOPE, OFFLINE_SCOPE],

    // RFC 9207. We return `iss` on every authorization response, which lets a
    // client detect an authorization-server mix-up before it sends the code to
    // a token endpoint. Advertising it is what makes clients enforce it.
    authorization_response_iss_parameter_supported: true,

    client_id_metadata_document_supported: true,

    service_documentation: 'https://github.com/bauer-group/IP-n8n-MCPServer#readme',
    ui_locales_supported: ['de', 'en'],
  };
}

/**
 * RFC 9728 protected resource metadata for one tenant.
 *
 * `authorization_servers` must have at least one entry per the MCP spec, and
 * clients use the FIRST one without falling back — so this list stays at
 * exactly one element on purpose.
 */
export function protectedResourceMetadata(
  config: Config,
  hostname: string,
): Record<string, unknown> {
  return {
    resource: resourceFor(config, hostname),
    authorization_servers: [config.baseUrl],
    bearer_methods_supported: ['header'],
    scopes_supported: [SCOPE],
    resource_name: `${config.MCP_DISPLAY_NAME} · ${hostname}`,
    resource_documentation: 'https://github.com/bauer-group/IP-n8n-MCPServer#readme',
  };
}

/**
 * Build the `WWW-Authenticate` value for a 401 or 403 from the MCP endpoint.
 *
 * This header is the primary discovery mechanism — clients prefer it over
 * probing well-known URLs, and Claude specifically will not act on a
 * WWW-Authenticate that arrives on a 200. `resource_metadata` must be an
 * absolute https URL; a relative one silently breaks discovery.
 *
 * `scope` is included because clients use it to decide what to request. Leave
 * it out and the client falls back to everything in `scopes_supported`.
 */
export function bearerChallenge(options: {
  readonly resourceMetadataUrl: string;
  readonly error?: string;
  readonly description?: string;
  readonly scope?: string;
}): string {
  const parts: string[] = ['Bearer'];
  const params: string[] = [];
  if (options.error) params.push(`error="${options.error}"`);
  if (options.description) {
    // Quoted-string values may not contain a bare `"` or `\`; strip rather than
    // escape, since these descriptions are ours and never need either.
    params.push(`error_description="${options.description.replace(/["\\]/g, '')}"`);
  }
  if (options.scope) params.push(`scope="${options.scope}"`);
  params.push(`resource_metadata="${options.resourceMetadataUrl}"`);
  parts.push(params.join(', '));
  return parts.join(' ');
}

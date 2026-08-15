# Client setup

The connector URL is always:

```text
https://<gateway-host>/i/<n8n-host>/mcp
```

**One connector per n8n instance.** Connectors are keyed by the full URL
including the path, so several instances coexist on one gateway. Adding the
*same* URL twice is rejected by Claude with "A server with this URL already
exists" — that is a client-side limitation, not ours.

---

## Claude Web / Claude Desktop

Settings → **Connectors** → **Add custom connector**

| Field | Value |
| --- | --- |
| Name | `n8n — Kunde A` (anything) |
| URL | `https://n8n-mcp.example.com/i/flow.kunde-a.app.bauer-group.com/mcp` |

Click **Connect**. A popup opens the gateway's consent screen, showing the
target instance and asking for:

- **Username or e-mail** — a label for the audit log; not a credential
- **API key** — n8n → Settings → **n8n API** → *Create an API key*

Claude Desktop uses the same hosted callback as the web app; it is **not** a
loopback client, so nothing extra is needed.

On Team or Enterprise, an owner adds the connector once under
**Settings → Connectors** and each member then clicks *Connect* and enters their
own key. Everyone gets their own grant, their own session and their own n8n
permissions.

---

## Claude Code

```bash
claude mcp add --transport http n8n https://n8n-mcp.example.com/i/flow.kunde-a.app.bauer-group.com/mcp
```

Then `/mcp` in the session to complete the OAuth flow in a browser.

Claude Code is an RFC 8252 **native** client: it identifies via a Client ID
Metadata Document and listens on an ephemeral loopback port. This gateway
matches loopback redirect URIs ignoring the port, which is what the RFC
requires, so it works out of the box.

> If you have set `MCP_ALLOWED_CLIENT_REDIRECT_URIS=https://claude.ai/`, Claude
> Code is excluded — its redirect URI is `http://localhost/callback`. Either add
> `http://localhost/` and `http://127.0.0.1/` to that list or leave it empty.

---

## Microsoft 365 Copilot Studio

Custom connector → **MCP** → the same URL. Copilot Studio performs the standard
OAuth 2.1 discovery, so no extra configuration is required.

---

## Cursor / Continue / other MCP clients

`mcp.json`:

```json
{
  "mcpServers": {
    "n8n": {
      "type": "http",
      "url": "https://n8n-mcp.example.com/i/flow.kunde-a.app.bauer-group.com/mcp"
    }
  }
}
```

---

## MCP Inspector (for testing)

```bash
npx @modelcontextprotocol/inspector
```

Transport **Streamable HTTP**, the same URL. The Inspector performs full OAuth
discovery and is the fastest way to see exactly which step fails.

---

## Getting an n8n API key

1. Sign in to the n8n instance **as the user who will be using Claude**.
2. **Settings → n8n API → Create an API key.**
3. Give it a label and, if the instance offers an expiry, choose one you are
   willing to renew. The gateway rejects an expired key at the consent form
   rather than letting it fail silently weeks later.
4. Copy it once — n8n does not show it again.

The key inherits that user's own permissions. It is not an admin key, and it
should not be shared: one key per person is the entire point of this design.

If the instance answers "the public API is not enabled", an administrator must
turn it on (Settings → n8n API). This is instance-wide and cannot be worked
around from here.

---

## Disconnecting

Any of these ends access:

| Action | Effect |
| --- | --- |
| Remove the connector in Claude | The client revokes its token; the grant is dropped. |
| Delete the API key in n8n | Access ends at the next refresh, at the latest after `AUTH_ACCESS_TOKEN_TTL` (1 h). |
| Operator deletes the grant | Immediate — every token for it stops working on the next request. |

See [operations.md](operations.md) for the operator-side commands.

# VS Code GitHub Copilot Chat + MCPKernel

GitHub Copilot Chat in **agent mode** can call MCP tools via the
`chat.mcp.servers` setting. Wire MCPKernel as the single MCP entry and
let the gateway fan out to every real upstream.

## 1. Run MCPKernel

```bash
pip install "mcpkernel[all]"
mcpkernel init
mcpkernel serve -c .mcpkernel/config.yaml
```

## 2. Configure VS Code

Add to `.vscode/mcp.json` (workspace) or `settings.json` (user):

```jsonc
{
  "servers": {
    "mcpkernel": {
      "type": "http",
      "url": "http://127.0.0.1:8080/mcp"
    }
  }
}
```

Open Copilot Chat → switch to **Agent** mode → the tools picker should
list every tool MCPKernel proxies. The gateway URL is the only one
Copilot ever talks to.

## 3. Verify policy enforcement

Try to make Copilot run a tool that violates the starter policy:

```text
@workspace Please run the shell command "rm -rf node_modules"
```

MCPKernel returns a structured `policy_denied` error and Copilot
reports the block in chat — without ever invoking the shell upstream.

```bash
# Check the audit trail
mcpkernel audit query --limit 10
```

## 4. Use the OAuth flow

When `MCPKERNEL_AUTH__METHOD=oauth2` is set, VS Code's Copilot
authentication code-path will trigger an interactive sign-in via your
configured IdP. Set `MCPKERNEL_AUTH__REQUIRE_RESOURCE=true` so tokens
issued for other audiences cannot be replayed against this gateway
(RFC 8707, MCP 2025-11-25 §Authorization).

## Notes

- VS Code currently supports `stdio`, `http`, and `sse` MCP transports.
  MCPKernel speaks all three — set `MCPKERNEL_PROXY__TRANSPORT` in
  `.env` to match.
- If Copilot Chat shows "Connection refused", verify with
  `curl http://127.0.0.1:8080/health`.

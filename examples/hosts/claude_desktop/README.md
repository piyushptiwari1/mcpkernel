# Claude Desktop + MCPKernel

Run MCPKernel as a **transparent security proxy** in front of every MCP
server Claude Desktop talks to. Claude continues to think it's calling
the upstream servers directly — every call is policy-checked, taint-scanned,
and audit-logged.

## 1. Install MCPKernel

```bash
pip install "mcpkernel[all]"
mcpkernel init
mcpkernel gen-token   # save the output as MCPKERNEL_HEALTH_TOKEN
```

## 2. Configure upstreams in `.mcpkernel/config.yaml`

```yaml
proxy:
  host: 127.0.0.1
  port: 8080

upstream:
  - name: filesystem
    url: stdio://npx
    transport: stdio
    command: npx
    args: ["-y", "@modelcontextprotocol/server-filesystem", "/Users/you/Documents"]

  - name: github
    url: stdio://npx
    transport: stdio
    command: npx
    args: ["-y", "@modelcontextprotocol/server-github"]
    env:
      GITHUB_PERSONAL_ACCESS_TOKEN: secret://github_token

policy:
  policy_paths:
    - .mcpkernel/policies/default.yaml

audit:
  enabled: true
  db_path: .mcpkernel/audit.db
```

> The `secret://github_token` URI is resolved via the configured secrets
> backend (`env` by default, also `vault`/`aws`/`gcp`).

## 3. Start the gateway

```bash
mcpkernel serve -c .mcpkernel/config.yaml
# proxy listening on http://127.0.0.1:8080/mcp
```

## 4. Point Claude Desktop at MCPKernel

Edit `~/Library/Application Support/Claude/claude_desktop_config.json`
(macOS) or `%APPDATA%\Claude\claude_desktop_config.json` (Windows):

```json
{
  "mcpServers": {
    "mcpkernel": {
      "command": "npx",
      "args": [
        "-y",
        "mcp-remote",
        "http://127.0.0.1:8080/mcp"
      ]
    }
  }
}
```

Restart Claude Desktop. The "Search and tools" panel will now show every
upstream tool, but each call is mediated by MCPKernel.

## 5. Verify the pipeline

```bash
# Ask Claude to read a file, then:
sqlite3 .mcpkernel/audit.db "SELECT timestamp, tool_name, decision FROM audit_log ORDER BY id DESC LIMIT 5;"
```

You should see every Claude call with the policy decision (`allow`,
`deny`, `audit`) and any taint labels detected.

## Hardening for production

- Set `MCPKERNEL_AUTH__METHOD=oauth2` and `MCPKERNEL_AUTH__REQUIRE_RESOURCE=true`
  (RFC 8707) so only Claude Desktop's authorised session can hit the proxy.
- Use the [`owasp_asi_2026_strict.yaml`](../../../policies/owasp_asi_2026_strict.yaml)
  policy preset, not the starter one.
- Enable DEE signing in CI: `MCPKERNEL_DEE__SIGN=true MCPKERNEL_DEE__REQUIRE_SIGN=true`.
- Gate the diagnostic endpoint: `MCPKERNEL_HEALTH_TOKEN=$(mcpkernel gen-token)`.

# Cursor + MCPKernel

Cursor reads `.cursor/mcp.json` (workspace) or `~/.cursor/mcp.json`
(user) for MCP server definitions. Replace direct upstream entries with
a single `mcpkernel` entry to mediate every tool call through the
gateway.

## 1. Bootstrap

```bash
pip install "mcpkernel[all]"
mcpkernel init
mcpkernel serve -c .mcpkernel/config.yaml
```

## 2. Wire Cursor

```jsonc
// .cursor/mcp.json
{
  "mcpServers": {
    "mcpkernel": {
      "url": "http://127.0.0.1:8080/mcp"
    }
  }
}
```

Reload Cursor → open the chat panel → enable Agent mode. The tool list
shown to the model is the union of MCPKernel's upstream tools, filtered
by your policy.

## 3. Block exfiltration in real time

Add to `.mcpkernel/policies/default.yaml`:

```yaml
rules:
  - id: NO-PII-OUT
    name: Refuse to send PII to web tools
    action: deny
    priority: 5
    tool_patterns:
      - "fetch_.*"
      - "web_.*"
      - "http_.*"
    taint_labels:
      - pii
      - secret
```

Reload the policy (`mcpkernel validate-policy .mcpkernel/policies/default.yaml`
+ restart `serve`). Now if Cursor's agent asks the model to "POST this
customer record to https://example.com/leak", MCPKernel intercepts the
tainted argument and denies the call before any data leaves the
sandbox.

## Hardening checklist

- [ ] `MCPKERNEL_AUTH__METHOD=oauth2` for any non-localhost deployment.
- [ ] `MCPKERNEL_SANDBOX__BACKEND=docker` (or `firecracker`) — Cursor
      tools often run shell or git commands; never run them on the host.
- [ ] `MCPKERNEL_DEE__ENABLED=true` — Cursor agent loops are long;
      DEE lets you replay any session deterministically.
- [ ] Set `MCPKERNEL_HEALTH_TOKEN` and scrape `/health/secret` from
      your monitoring stack rather than the public `/health`.

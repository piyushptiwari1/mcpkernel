# Claude Code (claude.ai CLI) + MCPKernel

Claude Code reads `~/.config/claude-code/mcp.json` for MCP server
definitions. Replace each upstream there with a single `mcpkernel`
entry pointing at the local proxy.

## 1. Initialise MCPKernel

```bash
pip install "mcpkernel[all]"
mcpkernel init --preset strict
```

## 2. List the upstreams you want Claude Code to use

Edit `.mcpkernel/config.yaml`:

```yaml
upstream:
  - name: filesystem
    transport: stdio
    command: npx
    args: ["-y", "@modelcontextprotocol/server-filesystem", "."]

  - name: shell
    transport: stdio
    command: npx
    args: ["-y", "@modelcontextprotocol/server-shell"]

policy:
  policy_paths: [.mcpkernel/policies/default.yaml]
  default_action: deny    # strict preset
```

## 3. Start the proxy in the background

```bash
mcpkernel serve -c .mcpkernel/config.yaml &
```

## 4. Point Claude Code at MCPKernel

`~/.config/claude-code/mcp.json`:

```json
{
  "mcpServers": {
    "mcpkernel": {
      "type": "http",
      "url": "http://127.0.0.1:8080/mcp"
    }
  }
}
```

Restart `claude` and run `/mcp` — every upstream tool MCPKernel proxies
will appear, each with the security label `[mediated by mcpkernel]`.

## 5. Why this matters for an autonomous coding agent

Claude Code is a high-autonomy agent — it can `shell_exec`, edit files,
open PRs. MCPKernel between Claude Code and its tools gives you:

- **Replayable execution** (DEE) — every tool call is hashed + Sigstore-signed
  so you can replay a Claude Code session deterministically for audit.
- **Taint blocking** — prevents Claude from copying a secret it read from
  one tool's output into the arguments of an outbound HTTP tool
  (OWASP LLM02, LLM06).
- **Policy on `shell_exec`** — see [`policies/owasp_asi_2026_strict.yaml`](../../../policies/owasp_asi_2026_strict.yaml)
  for blocking destructive commands by default.

## See also

- [examples/hosts/claude_desktop/](../claude_desktop/) — the desktop client
- [examples/hosts/vscode_copilot/](../vscode_copilot/) — VS Code Copilot
  Chat agent mode

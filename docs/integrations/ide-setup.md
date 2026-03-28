# IDE Setup

MCPKernel can be installed as an MCP server in your IDE, giving your AI agent native security tools.

---

## Supported IDEs

| IDE | Command | Config Location |
|-----|---------|----------------|
| Claude Desktop | `mcpkernel install claude` | `~/.config/claude/claude_desktop_config.json` |
| Cursor | `mcpkernel install cursor` | `~/.cursor/mcp.json` |
| VS Code | `mcpkernel install vscode` | `.vscode/mcp.json` |
| Windsurf | `mcpkernel install windsurf` | `~/.windsurf/mcp.json` |
| Zed | `mcpkernel install zed` | `~/.config/zed/settings.json` |
| OpenClaw | `mcpkernel install openclaw` | `~/.openclaw/mcp.json` |
| Goose | `mcpkernel install goose` | `~/.goose/mcp.json` |

---

## Tutorial: Install for Claude Desktop

### Step 1: Install MCPKernel as an MCP server

```bash
mcpkernel install claude
```

Output:

```
✓ Installed MCPKernel MCP server for Claude Desktop
  Config: ~/.config/claude/claude_desktop_config.json
  Tools available: 5
  Restart Claude Desktop to activate.
```

### Step 2: Restart Claude Desktop

The agent now has these tools available:

| Tool | Description |
|------|-------------|
| `mcpkernel_scan_tool` | Scan a tool definition for poisoning attacks |
| `mcpkernel_check_taint` | Check if data contains secrets or PII |
| `mcpkernel_validate_policy` | Validate a YAML policy file |
| `mcpkernel_doctor` | Run health checks on the MCPKernel installation |
| `mcpkernel_discover` | Find all MCP servers installed on this system |

### Step 3: Test it

Ask Claude: "Use mcpkernel_doctor to check my system"

### Uninstall

```bash
mcpkernel uninstall claude
```

---

## Tutorial: Multi-IDE Discovery

Find all MCP servers installed across all your IDEs:

```bash
mcpkernel discover
```

Output:

```
Discovered MCP servers:
  Claude Desktop:
    ✓ filesystem (stdio) — npx @mcp/server-filesystem
    ✓ github (stdio) — npx @mcp/server-github
    ✓ mcpkernel (stdio) — mcpkernel mcp-serve

  Cursor:
    ✓ filesystem (stdio) — npx @mcp/server-filesystem

  VS Code:
    (no MCP servers configured)
```

---

## Tutorial: Running as MCP Server Directly

Instead of using the `install` command, you can run MCPKernel as an MCP server manually:

```bash
# Start as a stdio MCP server (for IDE integration)
mcpkernel mcp-serve

# Start as an HTTP MCP server
mcpkernel mcp-serve --transport http --port 8001
```

### Manual Claude Desktop configuration

Add to `~/.config/claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "mcpkernel": {
      "command": "mcpkernel",
      "args": ["mcp-serve"]
    }
  }
}
```

### Manual Cursor configuration

Add to `~/.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "mcpkernel": {
      "command": "mcpkernel",
      "args": ["mcp-serve"]
    }
  }
}
```

---

## Doctor Command

Run diagnostics on your MCPKernel installation:

```bash
mcpkernel doctor
```

Output:

```
MCPKernel Doctor
================
  ✓ Python 3.13.12
  ✓ mcpkernel 0.1.3 installed
  ✓ Dependencies OK
  ✓ Policy files valid
  ✓ Audit database accessible
  ✓ DEE trace store OK
```

# MCP Server Registry

MCPKernel integrates with the official [MCP Server Registry](https://registry.modelcontextprotocol.io) to discover, search, and validate upstream MCP servers.

---

## CLI Commands

### Search for servers

```bash
mcpkernel registry-search filesystem
```

Output:

```
Found 3 server(s) matching 'filesystem':

  @modelcontextprotocol/server-filesystem ✓
    Secure file system access for AI agents
    Transports: stdio
    Install: npx @modelcontextprotocol/server-filesystem

  @anthropic/files
    Read and write files with permission controls
    Transports: stdio, streamable_http

  community/local-fs
    Lightweight local file system server
    Transports: stdio
```

### List all servers

```bash
mcpkernel registry-list
```

Output:

```
MCP Server Registry — 127 servers available

  @modelcontextprotocol/server-filesystem    Secure file system access
  @modelcontextprotocol/server-github        GitHub API integration
  @modelcontextprotocol/server-postgres      PostgreSQL database access
  @modelcontextprotocol/server-slack         Slack workspace integration
  ...
  Showing 20 of 127 — use --limit to see more
```

### Search with filters

```bash
# Search by keyword
mcpkernel registry-search "database"

# Limit results
mcpkernel registry-list --limit 50
```

---

## Configuration

```yaml
# .mcpkernel/config.yaml
registry:
  enabled: true
  registry_url: https://registry.modelcontextprotocol.io
```

Override via environment variable:

```bash
export MCPKERNEL_REGISTRY__REGISTRY_URL=https://registry.modelcontextprotocol.io
```

!!! tip "Use with discover"
    Combine `registry-search` with `mcpkernel discover` and `mcpkernel add-server` for a complete workflow:
    
    ```bash
    # Find a server
    mcpkernel registry-search github
    
    # Check what's already installed
    mcpkernel discover
    
    # Add it to your config
    mcpkernel add-server github http://localhost:3001/mcp
    ```

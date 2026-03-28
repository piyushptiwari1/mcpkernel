# CLI Reference

MCPKernel provides 22+ commands for managing the security gateway. All commands are invoked via `mcpkernel <command>`.

---

## Core Commands

### `serve`

Start the MCPKernel proxy gateway.

```bash
mcpkernel serve [OPTIONS]
```

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `--host` | str | `127.0.0.1` | Bind address |
| `--port` | int | `8080` | Bind port |
| `--config`, `-c` | path | None | Config YAML path |
| `--log-level` | str | `info` | Log level |
| `--transport` | str | `http` | Transport: `http` or `stdio` |

```bash
# Start with defaults
mcpkernel serve

# Start with config file
mcpkernel serve -c .mcpkernel/config.yaml --log-level debug

# Start in stdio mode (for IDE integration)
mcpkernel serve --transport stdio
```

### `init`

Initialize MCPKernel in a project directory.

```bash
mcpkernel init [DIRECTORY] [OPTIONS]
```

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `DIRECTORY` | path | `.` | Project directory |
| `--preset`, `-p` | str | `standard` | Policy preset: `permissive`, `standard`, `strict` |

```bash
mcpkernel init --preset strict
mcpkernel init /path/to/project --preset permissive
```

### `status`

Show current MCPKernel status.

```bash
mcpkernel status [-c CONFIG]
```

### `version`

Print the MCPKernel version.

```bash
mcpkernel version
```

---

## Server Management

### `add-server`

Add an upstream MCP server to the configuration.

```bash
mcpkernel add-server NAME URL [OPTIONS]
```

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `NAME` | str | required | Server name (e.g., `filesystem`) |
| `URL` | str | required | Server URL |
| `--transport` | str | `streamable_http` | Transport type |
| `-c`, `--config` | path | `.mcpkernel/config.yaml` | Config file |

```bash
mcpkernel add-server filesystem http://localhost:3000/mcp
mcpkernel add-server github http://localhost:3001/mcp --transport sse
```

### `test-connection`

Test connectivity to all configured upstream servers.

```bash
mcpkernel test-connection [-c CONFIG]
```

---

## Policy Commands

### `validate-policy`

Validate a policy YAML file or directory.

```bash
mcpkernel validate-policy PATH
```

```bash
mcpkernel validate-policy policies/my_policy.yaml
mcpkernel validate-policy policies/
```

### `presets`

List available policy presets and their rules.

```bash
mcpkernel presets
```

### `quickstart`

One-command demo — initialize, show config, and verify the pipeline.

```bash
mcpkernel quickstart [--preset PRESET]
```

---

## Trace & Audit Commands

### `trace-list`

List recent execution traces.

```bash
mcpkernel trace-list [OPTIONS]
```

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `--db` | str | `mcpkernel_traces.db` | Trace DB path |
| `--limit` | int | `20` | Max entries |

### `trace-export`

Export traces to a file.

```bash
mcpkernel trace-export [OPTIONS]
```

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `--db` | str | `mcpkernel_traces.db` | Trace DB path |
| `--format` | str | `json` | Format: `json`, `csv` |
| `--output` | str | required | Output file path |

### `replay`

Replay a specific trace to verify determinism.

```bash
mcpkernel replay TRACE_ID [OPTIONS]
```

### `audit-query`

Query the audit log.

```bash
mcpkernel audit-query [OPTIONS]
```

### `audit-verify`

Verify the integrity of audit log entries.

```bash
mcpkernel audit-verify [OPTIONS]
```

---

## Security Scanning

### `scan`

Scan MCP tool definitions for security issues.

```bash
mcpkernel scan [OPTIONS]
```

### `poison-scan`

Scan tool descriptions for poisoning attacks (hidden instructions, encoding tricks, etc.).

```bash
mcpkernel poison-scan [OPTIONS]
```

### `scan-skill`

Scan a skill file for security issues.

```bash
mcpkernel scan-skill PATH [OPTIONS]
```

### `agent-scan`

Run a Snyk agent security scan.

```bash
mcpkernel agent-scan [OPTIONS]
```

---

## IDE Integration

### `install`

Install MCPKernel as an MCP server in an IDE.

```bash
mcpkernel install TARGET
```

Targets: `claude`, `cursor`, `vscode`, `windsurf`, `zed`, `openclaw`, `goose`

```bash
mcpkernel install claude
mcpkernel install cursor
```

### `uninstall`

Remove MCPKernel from an IDE.

```bash
mcpkernel uninstall TARGET
```

### `discover`

Find all MCP servers installed across all IDEs.

```bash
mcpkernel discover
```

### `doctor`

Run health checks on the MCPKernel installation.

```bash
mcpkernel doctor
```

### `mcp-serve`

Start MCPKernel as an MCP server (for IDE integration).

```bash
mcpkernel mcp-serve [OPTIONS]
```

---

## Registry Commands

### `registry-search`

Search the MCP Server Registry.

```bash
mcpkernel registry-search QUERY [OPTIONS]
```

### `registry-list`

List servers from the MCP Server Registry.

```bash
mcpkernel registry-list [OPTIONS]
```

---

## Configuration Commands

### `config-show`

Show the effective configuration (all sources merged).

```bash
mcpkernel config-show [-c CONFIG]
```

---

## Observability

### `langfuse-export`

Export traces to Langfuse for LLM observability.

```bash
mcpkernel langfuse-export [OPTIONS]
```

---

## Manifest Commands

### `manifest-import`

Import an agent.yaml manifest file.

```bash
mcpkernel manifest-import PATH [OPTIONS]
```

### `manifest-validate`

Validate an agent.yaml manifest.

```bash
mcpkernel manifest-validate PATH [OPTIONS]
```

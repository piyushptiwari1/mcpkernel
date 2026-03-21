# MCPGuard Usage Guide

## How to Use MCPGuard on Your Personal System

### Prerequisites

- **Python 3.12+** — [Download](https://python.org/downloads/)
- **Docker** (optional) — Required for Docker sandbox backend
- **Git** — For cloning the repository

### Step 1: Clone and Install

```bash
git clone https://github.com/piyushptiwari1/mcpguard.git
cd mcpguard

# Create a virtual environment (recommended)
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install with core dependencies
pip install -e "."

# Or with Docker sandbox support
pip install -e ".[docker]"

# Or with all development tools
pip install -e ".[dev]"
```

### Step 2: Initialize Your Project

```bash
mcpguard init
```

This creates:
```
.mcpguard/
├── config.yaml       # Main configuration
└── policies/
    └── default.yaml  # Default policy rules
```

### Step 3: Configure

Edit `.mcpguard/config.yaml`:

```yaml
proxy:
  host: 127.0.0.1
  port: 8000

sandbox:
  backend: docker        # Options: docker, firecracker, wasm, microsandbox
  timeout_seconds: 30

taint:
  mode: hybrid           # Options: decorator, ebpf, hybrid, disabled

policy:
  policy_dir: .mcpguard/policies

observability:
  log_level: info
  metrics_enabled: true
```

### Step 4: Add Policy Rules

Copy the strict policy for full OWASP ASI 2026 coverage:

```bash
cp policies/owasp_asi_2026_strict.yaml .mcpguard/policies/
```

Or create custom rules:

```yaml
# .mcpguard/policies/my_rules.yaml
rules:
  - id: MY-001
    name: Block shell execution
    action: deny
    tool_patterns:
      - "shell_.*"
      - "os_command"

  - id: MY-002
    name: Sandbox code execution
    action: sandbox
    tool_patterns:
      - "execute_.*"
      - "run_code"
```

Validate your rules:

```bash
mcpguard validate-policy .mcpguard/policies/
```

### Step 5: Start the Gateway

```bash
mcpguard serve
```

The gateway starts at `http://localhost:8000`.

### Step 6: Point Your AI Agent to MCPGuard

Instead of connecting your AI agent directly to MCP servers, point it to MCPGuard:

```python
# Before (direct MCP connection)
# mcp_url = "http://localhost:3000/mcp"

# After (through MCPGuard)
mcp_url = "http://localhost:8000/mcp"
```

### Step 7: Monitor and Audit

```bash
# View recent traces
mcpguard trace-list

# Export a specific trace
mcpguard trace-export <trace-id>

# Query audit logs
mcpguard audit-query --event-type policy_violation

# Verify audit integrity
mcpguard audit-verify

# Static code analysis
mcpguard scan path/to/file.py
```

---

## Using with Docker

```bash
# Build the image
docker build -t mcpguard .

# Run with volume-mounted policies
docker run -p 8000:8000 \
  -v $(pwd)/policies:/app/policies:ro \
  -v /var/run/docker.sock:/var/run/docker.sock \
  mcpguard

# Or use Docker Compose
docker compose up -d
```

---

## Environment Variables

All configuration can be overridden with environment variables:

| Variable | Description | Default |
|---|---|---|
| `MCPGUARD_PROXY__HOST` | Bind address | `127.0.0.1` |
| `MCPGUARD_PROXY__PORT` | Bind port | `8000` |
| `MCPGUARD_SANDBOX__BACKEND` | Sandbox backend | `docker` |
| `MCPGUARD_SANDBOX__TIMEOUT_SECONDS` | Execution timeout | `30` |
| `MCPGUARD_TAINT__MODE` | Taint tracking mode | `hybrid` |
| `MCPGUARD_POLICY__POLICY_DIR` | Policy directory | `policies` |
| `MCPGUARD_OBSERVABILITY__LOG_LEVEL` | Log level | `info` |
| `MCPGUARD_OBSERVABILITY__METRICS_ENABLED` | Enable Prometheus metrics | `true` |
| `MCPGUARD_OBSERVABILITY__OTLP_ENDPOINT` | OpenTelemetry endpoint | `` |

---

## Integration Examples

See the `examples/` directory for:

- **`langchain_example.py`** — LangChain agent with MCPGuard
- **`crewai_example.py`** — CrewAI tools via MCPGuard
- **`copilot_guard_example.py`** — AI coding assistant protection

---

## Troubleshooting

### MCPGuard won't start
- Check that port 8000 is not in use: `lsof -i :8000`
- Verify config: `mcpguard config-show`

### Docker sandbox errors
- Ensure Docker is running: `docker info`
- Check Docker socket permissions: `ls -la /var/run/docker.sock`

### Policy not loading
- Validate syntax: `mcpguard validate-policy <path>`
- Check YAML indentation

### eBPF probes unavailable
- eBPF requires root privileges: run with `sudo`
- Install BCC: `pip install bcc`
- Falls back gracefully to Python-only taint tracking

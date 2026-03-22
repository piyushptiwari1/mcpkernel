# MCPKernel Usage Guide

## How to Use MCPKernel on Your Personal System

### Prerequisites

- **Python 3.12+** — [Download](https://python.org/downloads/)
- **Docker** (optional) — Required for Docker sandbox backend
- **Git** — For cloning the repository

### Step 1: Clone and Install

```bash
git clone https://github.com/piyushptiwari1/mcpkernel.git
cd mcpkernel

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
mcpkernel init
```

This creates:
```
.mcpkernel/
├── config.yaml       # Main configuration
└── policies/
    └── default.yaml  # Default policy rules
```

### Step 3: Configure

Edit `.mcpkernel/config.yaml`:

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
  policy_dir: .mcpkernel/policies

observability:
  log_level: info
  metrics_enabled: true
```

### Step 4: Add Policy Rules

Copy the strict policy for full OWASP ASI 2026 coverage:

```bash
cp policies/owasp_asi_2026_strict.yaml .mcpkernel/policies/
```

Or create custom rules:

```yaml
# .mcpkernel/policies/my_rules.yaml
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
mcpkernel validate-policy .mcpkernel/policies/
```

### Step 5: Start the Gateway

```bash
mcpkernel serve
```

The gateway starts at `http://localhost:8000`.

### Step 6: Point Your AI Agent to MCPKernel

Instead of connecting your AI agent directly to MCP servers, point it to MCPKernel:

```python
# Before (direct MCP connection)
# mcp_url = "http://localhost:3000/mcp"

# After (through MCPKernel)
mcp_url = "http://localhost:8000/mcp"
```

### Step 7: Monitor and Audit

```bash
# View recent traces
mcpkernel trace-list

# Export a specific trace
mcpkernel trace-export <trace-id>

# Query audit logs
mcpkernel audit-query --event-type policy_violation

# Verify audit integrity
mcpkernel audit-verify

# Static code analysis
mcpkernel scan path/to/file.py
```

---

## Using with Docker

```bash
# Build the image
docker build -t mcpkernel .

# Run with volume-mounted policies
docker run -p 8000:8000 \
  -v $(pwd)/policies:/app/policies:ro \
  -v /var/run/docker.sock:/var/run/docker.sock \
  mcpkernel

# Or use Docker Compose
docker compose up -d
```

---

## Environment Variables

All configuration can be overridden with environment variables:

| Variable | Description | Default |
|---|---|---|
| `MCPKERNEL_PROXY__HOST` | Bind address | `127.0.0.1` |
| `MCPKERNEL_PROXY__PORT` | Bind port | `8000` |
| `MCPKERNEL_SANDBOX__BACKEND` | Sandbox backend | `docker` |
| `MCPKERNEL_SANDBOX__TIMEOUT_SECONDS` | Execution timeout | `30` |
| `MCPKERNEL_TAINT__MODE` | Taint tracking mode | `hybrid` |
| `MCPKERNEL_POLICY__POLICY_DIR` | Policy directory | `policies` |
| `MCPKERNEL_OBSERVABILITY__LOG_LEVEL` | Log level | `info` |
| `MCPKERNEL_OBSERVABILITY__METRICS_ENABLED` | Enable Prometheus metrics | `true` |
| `MCPKERNEL_OBSERVABILITY__OTLP_ENDPOINT` | OpenTelemetry endpoint | `` |

---

## Integration Examples

See the `examples/` directory for:

- **`langchain_example.py`** — LangChain agent with MCPKernel
- **`crewai_example.py`** — CrewAI tools via MCPKernel
- **`copilot_guard_example.py`** — AI coding assistant protection

---

## Troubleshooting

### MCPKernel won't start
- Check that port 8000 is not in use: `lsof -i :8000`
- Verify config: `mcpkernel config-show`

### Docker sandbox errors
- Ensure Docker is running: `docker info`
- Check Docker socket permissions: `ls -la /var/run/docker.sock`

### Policy not loading
- Validate syntax: `mcpkernel validate-policy <path>`
- Check YAML indentation

### eBPF probes unavailable
- eBPF requires root privileges: run with `sudo`
- Install BCC: `pip install bcc`
- Falls back gracefully to Python-only taint tracking

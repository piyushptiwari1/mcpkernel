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

## Agent Manifest Integration

MCPKernel can load `agent.yaml` manifest files that declare an agent's identity, tools, compliance requirements, and operational constraints. The manifest is converted into runtime policy rules and enforced automatically.

### What is `agent.yaml`?

An `agent.yaml` file lives at the root of an agent repository and describes:

- **Agent identity** — name, version, description, tags, metadata
- **Tools** — declared tool names with JSON Schema for argument validation
- **Compliance** — risk tier, supervision level, data governance, communications policies, segregation of duties, recordkeeping, model risk, vendor management
- **Framework mappings** — FINRA, SEC, and Federal Reserve regulatory frameworks
- **Extensions** — SOUL.md, RULES.md, hooks.yaml, skills, sub-agents, A2A config, dependencies

### CLI Commands

**Import a manifest and generate policy rules:**

```bash
mcpkernel manifest-import /path/to/agent-repo
```

This loads `agent.yaml` from the given directory, converts compliance declarations into MCPKernel `PolicyRule` objects, and outputs the generated YAML rules.

**Validate a manifest and its tool schemas:**

```bash
mcpkernel manifest-validate /path/to/agent-repo
```

This checks that the manifest is well-formed, all tool schemas are valid, and reports the compliance status.

### Proxy Hook — `AgentManifestHook`

When running the MCPKernel proxy, the `AgentManifestHook` (priority 950) integrates with the plugin pipeline to:

1. **Block undeclared tools** — if a tool call targets a tool not listed in the manifest, it is denied
2. **Enforce schema validation** — tool-call arguments are validated against declared JSON Schemas (type checking, enum validation, required fields)

The hook is a `PluginHook` subclass and runs in the `pre_execution` phase of the proxy pipeline.

### Programmatic Usage

```python
from mcpkernel.agent_manifest import (
    load_agent_manifest,
    manifest_to_policy_rules,
    ToolSchemaValidator,
)

# Load a manifest from a repo directory
definition = load_agent_manifest("/path/to/agent-repo")
print(f"Agent: {definition.name} v{definition.version}")

# Convert compliance config to MCPKernel policy rules
rules = manifest_to_policy_rules(definition)
for rule in rules:
    print(f"  Rule: {rule.id} — {rule.name} [{rule.action}]")

# Validate a tool call against declared schemas
validator = ToolSchemaValidator(definition)
errors = validator.validate("my_tool", {"arg1": "value"})
if errors:
    print(f"Schema violations: {errors}")
```

---

## Integration Examples

See the `examples/` directory for:

- **`langchain_example.py`** — LangChain agent with MCPKernel
- **`crewai_example.py`** — CrewAI tools via MCPKernel
- **`autogen_example.py`** — AutoGen multi-agent conversations via MCPKernel
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

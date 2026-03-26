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

## Python API

MCPKernel provides a programmatic Python API alongside the CLI and proxy gateway. This lets you embed the security pipeline directly into your application code.

### MCPKernelProxy

The primary entry point for programmatic use. It creates a full security pipeline (policy, taint, DEE, audit) and routes tool calls through it.

```python
from mcpkernel import MCPKernelProxy

async with MCPKernelProxy(
    upstream=["http://localhost:3000/mcp"],
    policy="strict",
    taint=True,
) as proxy:
    result = await proxy.call_tool("read_file", {"path": "data.csv"})
```

**Constructor parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `upstream` | `list[str]` | `[]` | Upstream MCP server URLs |
| `policy` | `str \| Path` | `"standard"` | Preset name (`permissive`, `standard`, `strict`, `owasp-asi-2026`) or path to YAML policy file |
| `taint` | `bool` | `True` | Enable taint detection (secrets, PII) |
| `audit` | `bool` | `True` | Enable audit logging |
| `sandbox` | `bool` | `False` | Enable sandbox execution |
| `context_pruning` | `bool` | `False` | Enable context minimization |
| `config_path` | `Path` | `None` | YAML config file (overrides all other kwargs) |
| `host` | `str` | `"127.0.0.1"` | HTTP bind address (for `serve()`) |
| `port` | `int` | `8080` | HTTP bind port (for `serve()`) |

**Key methods:**

- `await proxy.start()` — Initialize pipeline and connect to upstreams
- `await proxy.stop()` — Shut down pipeline and disconnect
- `await proxy.call_tool(name, args)` — Route a tool call through the security pipeline
- `await proxy.list_tools()` — List tools available from upstream servers
- `proxy.hooks` — Names of registered pipeline hooks
- `proxy.tool_names` — Tool names from upstream servers

The proxy supports `async with` for automatic lifecycle management.

### protect() Decorator

One-line decorator that wraps any function with MCPKernel security checks. Supports both sync and async functions.

```python
from mcpkernel import protect

@protect(policy="strict", taint=True)
async def read_data(path: str) -> str:
    return Path(path).read_text()

# Sync functions also work
@protect(policy="standard")
def get_config(key: str) -> str:
    return config[key]
```

The decorator lazily initializes a `MCPKernelProxy` on first call. Function arguments are routed through the policy engine and taint scanner before the function executes. An `atexit` handler ensures cleanup.

**Decorator parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `policy` | `str \| Path` | `"standard"` | Policy preset or YAML path |
| `taint` | `bool` | `True` | Enable taint detection |
| `audit` | `bool` | `True` | Enable audit logging |
| `sandbox` | `bool` | `False` | Enable sandbox execution |

### POLICY_PRESETS

Built-in policy presets available via `from mcpkernel import POLICY_PRESETS`:

| Preset | Default Action | Description |
|--------|---------------|-------------|
| `permissive` | `allow` | Audit everything, block nothing. Good for development. |
| `standard` | `audit` | Block known-dangerous patterns, audit the rest. |
| `strict` | `deny` | Deny-by-default. Only explicitly allowed tools pass. |
| `owasp-asi-2026` | `deny` | Full OWASP ASI 2026 compliance (file-based rule set). |

Get the rules for a preset programmatically:

```python
from mcpkernel.presets import get_preset_rules, list_presets

# List all presets with descriptions
for name, desc in list_presets().items():
    print(f"{name}: {desc}")

# Get rules for a specific preset
rules = get_preset_rules("strict")
for rule in rules:
    print(f"  [{rule.action.value}] {rule.name}")
```

---

## New CLI Commands

### quickstart

One-command demo that shows the preset rules, verifies the pipeline, and prints usage instructions.

```bash
mcpkernel quickstart              # Test with standard preset
mcpkernel quickstart --preset strict
```

### presets

List all available policy presets and the rules they include.

```bash
mcpkernel presets
```

### status

Show current MCPKernel status — config, hooks, policy, and upstream servers.

```bash
mcpkernel status --config .mcpkernel/config.yaml
```

### init --preset

Initialize a project with a named policy preset. The preset determines the default action and which rules are generated.

```bash
mcpkernel init /path/to/project --preset standard
mcpkernel init --preset strict
mcpkernel init --preset permissive
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
| `MCPKERNEL_LANGFUSE__ENABLED` | Enable Langfuse export | `false` |
| `MCPKERNEL_LANGFUSE__PUBLIC_KEY` | Langfuse public API key | `` |
| `MCPKERNEL_LANGFUSE__SECRET_KEY` | Langfuse secret API key | `` |
| `MCPKERNEL_GUARDRAILS_AI__ENABLED` | Enable Guardrails AI validators | `false` |
| `MCPKERNEL_REGISTRY__REGISTRY_URL` | MCP Registry URL | `https://registry.modelcontextprotocol.io` |
| `MCPKERNEL_AGENT_SCAN__BINARY_NAME` | Snyk agent-scan binary name | `agent-scan` |

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
- **`mcp_agent/`** — mcp-agent framework connected through MCPKernel proxy

---

## Third-Party Integrations

MCPKernel integrates with external tools to form a complete agent security pipeline:

```
BUILD          SCAN              PROTECT          CONNECT           OBSERVE         TEST
FastMCP ──▶ Snyk Agent Scan ──▶ MCPKernel ──▶ AI Agents ──▶ Langfuse ──▶ promptfoo
python-sdk   (static scan)     (runtime gate)  (LangChain,    (traces,     (prompt
                                               CrewAI, etc)    metrics)     testing)
```

All integrations live in `src/mcpkernel/integrations/` and follow a consistent pattern:
- Graceful fallback when optional dependencies aren't installed
- Async-first APIs
- Configurable via YAML config or environment variables
- CLI commands for common operations

---

### Langfuse — Observability Export

[Langfuse](https://langfuse.com) is an open-source LLM observability platform. MCPKernel exports audit entries and DEE traces to Langfuse for visualization and analytics.

**Configuration:**

```yaml
# .mcpkernel/config.yaml
langfuse:
  enabled: true
  public_key: pk-lf-...          # Langfuse public key
  secret_key: sk-lf-...          # Langfuse secret key
  host: https://cloud.langfuse.com  # or self-hosted URL
  project_name: mcpkernel
  batch_size: 50                 # Events batched before flush
  flush_interval_seconds: 5.0    # Auto-flush interval
```

**Environment variables:**

```bash
export MCPKERNEL_LANGFUSE__ENABLED=true
export MCPKERNEL_LANGFUSE__PUBLIC_KEY=pk-lf-...
export MCPKERNEL_LANGFUSE__SECRET_KEY=sk-lf-...
export MCPKERNEL_LANGFUSE__HOST=https://cloud.langfuse.com
```

**CLI — Export audit entries to Langfuse:**

```bash
$ mcpkernel langfuse-export --limit 50

✓ Exported 50 audit entries to Langfuse (https://cloud.langfuse.com)
```

Each audit entry maps to a Langfuse trace:
- `tool_call` events → **trace-create** (one trace per tool invocation, tagged with tool name, outcome, policy action)
- Other events → **event-create** (attached to the trace)
- DEE traces → **trace-create + span-create** (includes input/output hashes, duration, signed status)

**Automatic export during proxy operation:**

When Langfuse is enabled and MCPKernel is running as a proxy, every tool call is automatically exported to Langfuse via the `ObservabilityHook`. No manual export needed.

**Programmatic usage:**

```python
from mcpkernel.integrations.langfuse import LangfuseConfig, LangfuseExporter

config = LangfuseConfig(
    enabled=True,
    public_key="pk-lf-...",
    secret_key="sk-lf-...",
)
exporter = LangfuseExporter(config=config)
await exporter.start()

# Export audit entries
await exporter.export_audit_entries(entries)
await exporter.flush()
await exporter.shutdown()
```

---

### Guardrails AI — Enhanced Taint Detection

[Guardrails AI](https://guardrailsai.com) provides production-grade input/output validation. MCPKernel plugs Guardrails validators into the taint detection pipeline for higher-accuracy PII, secret, and toxicity detection.

**Installation:**

```bash
pip install guardrails-ai
guardrails hub install hub://guardrails/detect_pii
guardrails hub install hub://guardrails/secrets_present
# Optional: guardrails hub install hub://guardrails/toxic_language
```

**Configuration:**

```yaml
# .mcpkernel/config.yaml
guardrails_ai:
  enabled: true
  pii_validator: true        # Detect PII (email, SSN, credit card, phone, etc.)
  secrets_validator: true    # Detect secrets (API keys, tokens, etc.)
  toxic_content: false       # Detect toxic language (requires model download)
  on_fail: noop              # noop = detect + tag only, exception = block the call
```

**How it works:**

When enabled, the `TaintHook` in the proxy pipeline runs Guardrails validators alongside MCPKernel's built-in regex patterns:

1. Built-in regex patterns run first (fast, zero dependencies)
2. Guardrails AI validators run second (higher accuracy, catches more entity types)
3. All detections are merged into the taint label set
4. Policy rules evaluate against the combined labels

**Detected entities:**

| Validator | Entity Types |
|-----------|-------------|
| `DetectPII` | EMAIL_ADDRESS, PHONE_NUMBER, CREDIT_CARD, US_SSN, PERSON, LOCATION, IP_ADDRESS, IBAN_CODE, MEDICAL_LICENSE |
| `SecretsPresent` | API keys, tokens, passwords, connection strings |
| `ToxicLanguage` | Toxic, hateful, threatening, or explicit content |

**Programmatic usage:**

```python
from mcpkernel.integrations.guardrails import GuardrailsConfig, GuardrailsValidator

config = GuardrailsConfig(enabled=True, pii_validator=True)
validator = GuardrailsValidator(config=config)

if validator.available:
    # Scan a string
    detections = await validator.validate_text("Call me at 555-0123")
    # detections = [GuardrailsDetection(label=TaintLabel.PII, entity_type="PHONE_NUMBER", ...)]

    # Scan all strings in a dict (recursive)
    detections = await validator.validate_dict({"user": {"email": "test@example.com"}})
```

If `guardrails-ai` is not installed, `validator.available` returns `False` and all calls return empty lists — no errors, no crashes.

---

### MCP Server Registry — Discovery & Validation

The [MCP Server Registry](https://registry.modelcontextprotocol.io) is the official directory of MCP servers. MCPKernel provides a client for searching, listing, and validating servers.

**Configuration:**

```yaml
# .mcpkernel/config.yaml
registry:
  enabled: true
  registry_url: https://registry.modelcontextprotocol.io
  cache_ttl_seconds: 300     # Cache list results for 5 minutes
  timeout_seconds: 10.0
```

**CLI — Search for servers:**

```bash
$ mcpkernel registry-search filesystem

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

The `✓` badge indicates a verified server in the registry.

**CLI — List all available servers:**

```bash
$ mcpkernel registry-list --limit 10

MCP Server Registry — 10 server(s):

  @modelcontextprotocol/server-filesystem ✓ [files, system]
  @modelcontextprotocol/server-github ✓ [git, api]
  @modelcontextprotocol/server-postgres ✓ [database]
  @modelcontextprotocol/server-slack ✓ [messaging]
  ...
```

**Programmatic usage:**

```python
from mcpkernel.integrations.registry import MCPRegistry

registry = MCPRegistry()

# Search
servers = await registry.search("database")

# Get details
server = await registry.get_server("@modelcontextprotocol/server-postgres")
print(server.name, server.description, server.transport)

# Validate a server exists
result = await registry.validate_server("@modelcontextprotocol/server-filesystem")
# result = {"valid": True, "verified": True, "version": "1.0.0", ...}

await registry.close()
```

---

### Snyk Agent Scan — Static Security Scanning

[Snyk Agent Scan](https://snyk.io) (formerly mcp-scan) performs static security analysis on MCP server configurations. MCPKernel bridges to the CLI tool and auto-generates policy rules from findings.

**Prerequisites:**

```bash
npm install -g @anthropic/agent-scan
```

**Configuration:**

```yaml
# .mcpkernel/config.yaml
agent_scan:
  enabled: true
  binary_name: agent-scan       # Binary name on PATH
  timeout_seconds: 120          # Scan timeout
  auto_generate_policy: true    # Auto-generate MCPKernel deny/log rules from findings
```

**CLI — Scan a directory or config file:**

```bash
$ mcpkernel agent-scan .mcpkernel/

Found 2 issue(s):

  🔴 [CRITICAL] Prompt injection vulnerability
    Server: filesystem
    Tool: read_file
    Fix: Add input validation for path arguments

  🟡 [MEDIUM] Tool shadowing detected
    Server: custom-tools
    Tool: execute
    Fix: Rename tool to avoid shadowing built-in

Generated 2 policy rule(s) from findings.
```

**Export generated rules to a policy file:**

```bash
$ mcpkernel agent-scan .mcpkernel/ -o .mcpkernel/policies/scan_rules.yaml

Found 2 issue(s):
  ...
Generated 2 policy rule(s) from findings.
  Exported to .mcpkernel/policies/scan_rules.yaml
```

The generated YAML contains rules like:

```yaml
rules:
  - id: SCAN-PJ-001
    name: "[Agent Scan] Prompt injection vulnerability"
    description: "Auto-generated from agent-scan finding..."
    action: deny
    tool_patterns:
      - read_file

  - id: SCAN-TS-002
    name: "[Agent Scan] Tool shadowing detected"
    description: "Auto-generated from agent-scan finding..."
    action: log
    tool_patterns:
      - "custom-tools:.*"
```

Severity mapping:
- **critical / high** → `deny` (blocks tool calls)
- **medium** → `log` (allows but logs the call)
- **low / info** → `audit` (recorded for review)

**Programmatic usage:**

```python
from mcpkernel.integrations.agent_scan import AgentScanner
from pathlib import Path

scanner = AgentScanner()

if scanner.available:
    report = await scanner.scan_directory(Path(".mcpkernel/"))
    print(f"Found {len(report.findings)} issues, {report.critical_count} critical")

    if report.has_blockers:
        rules = scanner.report_to_policy_rules(report)
        print(f"Generated {len(rules)} policy rules")
```

---

### Full Integration Configuration Reference

All integration options in one place:

```yaml
# .mcpkernel/config.yaml

# ── Langfuse (Observability Export) ──
langfuse:
  enabled: false                          # Enable Langfuse export
  public_key: ""                          # pk-lf-...
  secret_key: ""                          # sk-lf-...
  host: https://cloud.langfuse.com        # API host
  project_name: mcpkernel                 # Project label
  batch_size: 50                          # Batch before flush
  flush_interval_seconds: 5.0             # Auto-flush interval
  max_retries: 3                          # Retry on 429 / errors
  timeout_seconds: 10.0                   # HTTP timeout

# ── Guardrails AI (Enhanced Taint Detection) ──
guardrails_ai:
  enabled: false                          # Enable Guardrails validators
  pii_validator: true                     # DetectPII
  secrets_validator: true                 # SecretsPresent
  toxic_content: false                    # ToxicLanguage
  on_fail: noop                           # noop | exception

# ── MCP Server Registry ──
registry:
  enabled: true                           # Enable registry client
  registry_url: https://registry.modelcontextprotocol.io
  cache_ttl_seconds: 300                  # Cache TTL
  timeout_seconds: 10.0                   # HTTP timeout

# ── Snyk Agent Scan ──
agent_scan:
  enabled: true                           # Enable agent-scan bridge
  binary_name: agent-scan                 # Binary name on PATH
  timeout_seconds: 120                    # Scan timeout
  auto_generate_policy: true              # Auto-generate policy rules
```

**Environment variable equivalents:**

| YAML Key | Environment Variable |
|----------|---------------------|
| `langfuse.enabled` | `MCPKERNEL_LANGFUSE__ENABLED` |
| `langfuse.public_key` | `MCPKERNEL_LANGFUSE__PUBLIC_KEY` |
| `langfuse.secret_key` | `MCPKERNEL_LANGFUSE__SECRET_KEY` |
| `guardrails_ai.enabled` | `MCPKERNEL_GUARDRAILS_AI__ENABLED` |
| `registry.registry_url` | `MCPKERNEL_REGISTRY__REGISTRY_URL` |
| `agent_scan.binary_name` | `MCPKERNEL_AGENT_SCAN__BINARY_NAME` |

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

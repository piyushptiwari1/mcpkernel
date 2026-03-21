# MCPGuard — Execution Sovereignty Stack

**The mandatory, deterministic MCP/A2A gateway that turns every agent tool call into a provably replayable, taint-safe, policy-enforced execution.**

[![CI](https://github.com/piyushptiwari1/mcpguard/actions/workflows/ci.yml/badge.svg)](https://github.com/piyushptiwari1/mcpguard/actions/workflows/ci.yml)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://python.org)

---

## What is MCPGuard?

MCPGuard sits between AI agents and MCP tool servers as a **transparent security gateway**. Every tool call is:

1. **Policy-checked** against YAML rules (OWASP ASI 2026 mappings included)
2. **Taint-tracked** — secrets, PII, and user input are detected and blocked from reaching dangerous sinks
3. **Sandboxed** — code execution happens in Docker, Firecracker, WASM, or Microsandbox
4. **Deterministically enveloped** — every execution is hashed, Sigstore-signed, and replayable
5. **Audited** — tamper-proof, append-only logs with SIEM export (CEF, JSONL, CSV)

```
┌─────────────┐     ┌──────────────┐     ┌─────────────┐
│  AI Agent    │────▶│   MCPGuard   │────▶│  MCP Tool   │
│ (LangChain,  │◀────│   Gateway    │◀────│  Server     │
│  CrewAI, etc)│     └──────────────┘     └─────────────┘
└─────────────┘          │
                    ┌────┴────┐
                    │ Policy  │ Taint  │ Sandbox │ DEE │ Audit │
                    └─────────┘
```

---

## Use Cases

| Use Case | What MCPGuard Does |
|---|---|
| **AI Coding Assistants** | Intercepts Copilot/Cursor tool calls, blocks dangerous file writes, prevents secret exfiltration |
| **Autonomous Agents** | Policy-enforces LangChain/CrewAI/AutoGen tool usage, sandboxes code execution |
| **Enterprise MCP Deployments** | OWASP ASI 2026 compliance, tamper-proof audit trails, SIEM integration |
| **Research Reproducibility** | Deterministic execution envelopes — every result is Sigstore-signed and replayable |
| **Multi-Agent Workflows** | Cross-tool taint tracking — PII in one tool's output can't leak to another's HTTP call |
| **Regulated Industries** | Append-only audit logs, integrity verification, CEF export for SOC teams |

---

## Quick Start

### Install

```bash
pip install -e "."
```

Or with all optional backends:

```bash
pip install -e ".[docker,wasm,dev]"
```

### Initialize

```bash
mcpguard init
```

Creates `.mcpguard/config.yaml` and default policy files.

### Start the Gateway

```bash
mcpguard serve --host 127.0.0.1 --port 8000
```

### Configure Your Agent

Point your MCP client to `http://localhost:8000/mcp` instead of targeting MCP servers directly.

---

## Architecture

```
src/mcpguard/
├── proxy/          # FastAPI MCP gateway — auth, rate limiting, request pipeline
├── sandbox/        # Docker, Firecracker, WASM, Microsandbox backends
├── dee/            # Deterministic Execution Envelopes — hash, sign, replay
├── taint/          # Source/sink taint tracking — PII, secrets, user input
├── context/        # Token-efficient context minimization via TF-IDF + AST
├── ebpf/           # Optional kernel-level syscall monitoring (BCC)
├── policy/         # YAML policy engine with OWASP ASI 2026 mappings
├── audit/          # Append-only Sigstore-signed audit logs + SIEM export
├── observability/  # Prometheus metrics, OpenTelemetry tracing, health checks
├── config.py       # Pydantic v2 hierarchical config (YAML → env → CLI)
├── utils.py        # Hashing, exceptions, structured logging
└── cli.py          # Typer CLI — serve, scan, replay, audit, init
```

### Key Design Principles

- **Kong-inspired plugin pipeline**: `pre_execution → execution → post_execution → log` with priority ordering
- **Sigstore keyless signing**: Every execution trace is signed via OIDC — no key management
- **eBPF hybrid taint**: Kernel-level syscall hooks + Python decorator tracking at MCP boundaries
- **Append-only audit**: SQLite WAL mode, content-hashed entries, tamper detection

---

## CLI Commands

| Command | Description |
|---|---|
| `mcpguard serve` | Start the proxy gateway |
| `mcpguard init` | Initialize MCPGuard in a project |
| `mcpguard scan <file>` | Static taint analysis on Python code |
| `mcpguard validate-policy <path>` | Validate policy YAML files |
| `mcpguard trace-list` | List recent execution traces |
| `mcpguard trace-export <id>` | Export a trace as JSON |
| `mcpguard replay <id>` | Replay a trace and check for drift |
| `mcpguard audit-query` | Query audit logs with filters |
| `mcpguard audit-verify` | Verify audit log integrity |
| `mcpguard config-show` | Show effective configuration |
| `mcpguard version` | Print version |

---

## Policy Rules

MCPGuard includes three policy sets:

- **`owasp_asi_2026_strict.yaml`** — Full OWASP ASI 2026 coverage (ASI-01 through ASI-08)
- **`minimal.yaml`** — Lightweight defaults for development
- **`custom_template.yaml`** — Copy and customize for your use case

Example rule:

```yaml
rules:
  - id: ASI-03-001
    name: Block PII in outbound calls
    description: Prevent PII-tainted data from reaching HTTP sinks
    action: deny
    priority: 10
    tool_patterns:
      - "http_post"
      - "send_email"
    taint_labels:
      - pii
      - secret
    owasp_asi_id: ASI-03
```

---

## Configuration

MCPGuard loads config hierarchically: **YAML → environment variables → CLI flags**.

```yaml
# .mcpguard/config.yaml
proxy:
  host: 127.0.0.1
  port: 8000

sandbox:
  backend: docker        # docker | firecracker | wasm | microsandbox
  timeout_seconds: 30

taint:
  mode: hybrid           # decorator | ebpf | hybrid | disabled

policy:
  policy_dir: .mcpguard/policies

observability:
  log_level: info
  metrics_enabled: true
  otlp_endpoint: ""      # Set for OpenTelemetry export
```

Environment variable override: `MCPGUARD_SANDBOX__BACKEND=wasm`

---

## Docker Deployment

```bash
# Build and run
docker compose up -d

# With Prometheus monitoring
docker compose --profile monitoring up -d
```

---

## Development

```bash
# Clone and install
git clone https://github.com/piyushptiwari1/mcpguard.git
cd mcpguard
pip install -e ".[dev]"

# Run tests
pytest tests/ -v --cov=mcpguard

# Lint
ruff check src/ tests/
ruff format src/ tests/

# Type check
mypy src/mcpguard/
```

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, testing, and PR process.

---

## License

Apache 2.0 — see [LICENSE](LICENSE).

# MCPGuard — Security Gateway for AI Agent Tool Calls

> **Open-source MCP/A2A proxy that policy-enforces, taint-tracks, sandboxes, and audit-logs every AI agent tool call. OWASP ASI 2026 compliant.**

[![CI](https://github.com/piyushptiwari1/mcpguard/actions/workflows/ci.yml/badge.svg)](https://github.com/piyushptiwari1/mcpguard/actions/workflows/ci.yml)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://python.org)

---

## Why MCPGuard?

AI agents (LangChain, CrewAI, AutoGen, Copilot) call tools autonomously — reading files, executing code, making HTTP requests. Without a security layer, a single prompt injection can exfiltrate secrets, overwrite critical files, or run arbitrary code.

**MCPGuard is the missing chokepoint.** It sits between your agent and MCP tool servers, enforcing security policies on every single call:

```
┌─────────────┐     ┌──────────────────────────┐     ┌─────────────┐
│  AI Agent    │────▶│       MCPGuard           │────▶│  MCP Tool   │
│ (LangChain,  │◀────│  Security Gateway        │◀────│  Server     │
│ CrewAI, etc) │     └──────────────────────────┘     └─────────────┘
└─────────────┘       │ Policy │ Taint │ Sandbox │
                      │  DEE   │ Audit │ eBPF    │
```

### What happens to every tool call:

| Step | What MCPGuard Does |
|------|-------------------|
| **1. Policy Check** | Evaluates against YAML rules with OWASP ASI 2026 mappings — blocks or allows |
| **2. Taint Scan** | Detects secrets (AWS keys, JWTs), PII (SSN, credit cards), and user input in arguments |
| **3. Sandbox Execution** | Runs code in Docker, Firecracker, WASM, or Microsandbox — never on bare metal |
| **4. Deterministic Envelope** | Hashes inputs/outputs, Sigstore-signs the trace — fully replayable |
| **5. Audit Log** | Writes to tamper-proof append-only log with SIEM export (CEF, JSONL, CSV) |

---

## Features

- **YAML Policy Engine** — define allow/deny/audit/sandbox rules per tool, argument pattern, or taint label
- **Taint Tracking** — automatic detection of secrets, PII, API keys, JWTs in tool call arguments
- **4 Sandbox Backends** — Docker, Firecracker microVMs, WASM, Microsandbox
- **Deterministic Execution Envelopes (DEE)** — every execution is hashed and Sigstore-signed for replay
- **OWASP ASI 2026 Compliance** — built-in policy sets mapping to ASI-01 through ASI-08
- **Append-Only Audit Logs** — SQLite-backed, content-hashed, with CEF/JSONL/CSV SIEM export
- **Kong-Style Plugin Pipeline** — `pre_execution → execution → post_execution → log` with priorities
- **Rate Limiting** — per-identity token bucket with LRU eviction
- **Prometheus Metrics + OpenTelemetry** — full observability out of the box
- **Optional eBPF Probes** — kernel-level syscall monitoring at MCP boundaries

---

## Quick Start

```bash
# Install
pip install -e "."

# Initialize config and policies
mcpguard init

# Start the security gateway
mcpguard serve --host 127.0.0.1 --port 8000
```

Point your MCP client to `http://localhost:8000/mcp` instead of targeting tool servers directly.

---

## Use Cases

| Scenario | How MCPGuard Helps |
|----------|-------------------|
| **AI Coding Assistants** | Intercepts Copilot/Cursor tool calls, blocks dangerous file writes, prevents secret exfiltration |
| **Autonomous Agents** | Policy-enforces LangChain/CrewAI/AutoGen tool usage, sandboxes code execution |
| **Enterprise MCP Deployments** | OWASP ASI compliance, tamper-proof audit trails, SIEM integration |
| **Research Reproducibility** | Deterministic execution envelopes — every result is signed and replayable |
| **Multi-Agent Workflows** | Cross-tool taint tracking — PII in one tool's output can't leak to another's HTTP call |
| **Regulated Industries** | Append-only audit logs, integrity verification, CEF export for security teams |

---

## Architecture

```
src/mcpguard/
├── proxy/          # FastAPI MCP/A2A gateway — auth, rate limiting, plugin pipeline
├── policy/         # YAML rule engine with OWASP ASI 2026 mappings
├── taint/          # Source/sink taint tracking — secrets, PII, user input detection
├── sandbox/        # Docker, Firecracker, WASM, Microsandbox execution backends
├── dee/            # Deterministic Execution Envelopes — hash, sign, replay, drift detect
├── audit/          # Append-only Sigstore-signed audit logs + SIEM export
├── context/        # Token-efficient context reduction via TF-IDF + AST pruning
├── ebpf/           # Optional kernel-level syscall monitoring (BCC probes)
├── observability/  # Prometheus metrics, OpenTelemetry tracing, health checks
├── config.py       # Pydantic v2 hierarchical config (YAML → env → CLI)
├── cli.py          # Typer CLI — serve, scan, replay, audit, init
└── utils.py        # Hashing, exceptions, structured logging
```

---

## Policy Rules

MCPGuard ships with three policy sets:

- **`owasp_asi_2026_strict.yaml`** — Full OWASP ASI 2026 coverage (ASI-01 through ASI-08)
- **`minimal.yaml`** — Lightweight defaults for development
- **`custom_template.yaml`** — Copy and customize for your environment

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

## CLI Reference

| Command | Description |
|---------|-------------|
| `mcpguard serve` | Start the proxy gateway |
| `mcpguard init` | Initialize config and policies in a project |
| `mcpguard scan <file>` | Static taint analysis on Python code |
| `mcpguard validate-policy <path>` | Validate policy YAML files |
| `mcpguard trace-list` | List recent execution traces |
| `mcpguard trace-export <id>` | Export a trace as JSON |
| `mcpguard replay <id>` | Replay a trace and check for drift |
| `mcpguard audit-query` | Query audit logs with filters |
| `mcpguard audit-verify` | Verify audit log integrity |
| `mcpguard config-show` | Show effective configuration |

---

## Configuration

Config loads hierarchically: **YAML → environment variables → CLI flags**.

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
  default_action: deny   # deny-by-default for production
  policy_paths:
    - policies/owasp_asi_2026_strict.yaml

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

# Run tests (173 tests)
pytest tests/ -v --cov=mcpguard

# Lint
ruff check src/ tests/
ruff format src/ tests/
```

---

## Examples

Integration examples for popular AI agent frameworks:

- [LangChain](examples/langchain/) — route LangChain tool calls through MCPGuard
- [CrewAI](examples/crewai/) — secure CrewAI agent tool usage
- [AutoGen](examples/autogen/) — protect AutoGen multi-agent conversations
- [Copilot Guard](examples/copilot_guard/) — intercept Copilot/Cursor tool calls

---

## Planned — The Road to Agent Sovereignty

### 1. Inter-Agent Proof of Intent (Zero-Knowledge Tooling)

Today agents trust the gateway. Tomorrow, **Agent A (Company X)** will call a tool on **Agent B (Company Y)** — across organizational boundaries.

- **Problem:** How does Agent B verify that Agent A's call was authorized by a specific policy without revealing the underlying data?
- **Plan:** Add a **ZK-Policy module** to MCPGuard. Agents will produce zero-knowledge proofs of policy compliance, enabling cross-org tool calls with cryptographic "sovereignty" — no private code or data is ever exposed.

### 2. Physical-World Safety Layer (Robotic MCP)

As MCP expands into IoT and Robotics (Digital Twins), the "sandbox" isn't just a VM — it's a **physical constraint**.

- **Problem:** If an agent calls `move_arm()`, the gateway must simulate the physics impact before allowing the tainted command to reach the actuator.
- **Plan:** Deterministic execution for hardware — a **physics-aware sandbox** that models real-world consequences (collision, force limits, safety envelopes) before any command reaches a physical device.

### 3. Automated Red-Teaming ("Immune System" Mode)

Instead of being a passive gatekeeper, the gateway should **attack itself**.

- **Problem:** New prompt injection techniques and policy bypasses appear daily. Static rules can't keep up.
- **Plan:** A **Shadow LLM module** that continuously attempts prompt injections against MCPGuard's own policies in real-time, discovering 0-day vulnerabilities in agent logic before adversaries do.

### 4. Parallel Taint Analysis (Cold-Start Latency < 50 ms)

In 2026, latency is everything. If the gateway adds more than 50 ms to a tool call, developers will disable it.

- **Plan:** Run taint sink checking **concurrently** with code execution rather than sequentially — analyze while the sandbox is running, abort only if a violation is detected, keeping the hot path near zero additional latency.

### 5. Context Minimization as a Cost Weapon

Security matters, but **saving money sells faster**. The `context/` module already prunes tokens via TF-IDF + AST analysis.

- **Plan:** Productize context minimization to deliver **≥ 30 % token reduction** while maintaining safety guarantees. When the gateway pays for itself in reduced LLM costs, adoption becomes a no-brainer.

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, testing, and PR guidelines.

---

## License

Apache 2.0 — see [LICENSE](LICENSE).

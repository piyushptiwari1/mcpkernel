# MCPKernel — The Security Kernel for AI Agents

> **Open-source MCP/A2A security gateway — policy enforcement, taint tracking, sandboxed execution, deterministic envelopes, and Sigstore audit for every AI agent tool call. OWASP ASI 2026 compliant.**

[![CI](https://github.com/piyushptiwari1/mcpkernel/actions/workflows/ci.yml/badge.svg)](https://github.com/piyushptiwari1/mcpkernel/actions/workflows/ci.yml)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://python.org)

---

## Quick Start

```bash
pip install "mcpkernel[all]"
mcpkernel serve --host 127.0.0.1 --port 8000
```

Point your MCP client to `http://localhost:8000/mcp` instead of targeting tool servers directly. Every tool call is now policy-checked, taint-scanned, sandboxed, and audit-logged.

---

## Why MCPKernel?

AI agents (LangChain, CrewAI, AutoGen, Copilot) call tools autonomously — reading files, executing code, making HTTP requests. Without a security layer, a single prompt injection can exfiltrate secrets, overwrite critical files, or run arbitrary code.

**MCPKernel is the missing chokepoint.** It sits between your agent and MCP tool servers, enforcing security policies on every single call:

```
┌─────────────┐     ┌──────────────────────────┐     ┌─────────────┐
│  AI Agent    │────▶│       MCPKernel           │────▶│  MCP Tool   │
│ (LangChain,  │◀────│  Security Gateway        │◀────│  Server     │
│ CrewAI, etc) │     └──────────────────────────┘     └─────────────┘
└─────────────┘       │ Policy │ Taint │ Sandbox │
                      │  DEE   │ Audit │ eBPF    │
```

### What happens to every tool call:

| Step | What MCPKernel Does |
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
- **Agent Manifest Integration** — load `agent.yaml` definitions, convert compliance declarations (FINRA/SEC/Federal Reserve) to policy rules, validate tool schemas, and block undeclared tools at runtime via proxy hook
- **Langfuse Observability Export** — async batched export of audit entries and DEE traces to Langfuse for LLM-level analytics and visualization
- **Guardrails AI Validation** — enhanced PII, secret, and toxicity detection via Guardrails AI hub validators, plugged into the taint pipeline
- **MCP Server Registry** — discover, search, and validate upstream MCP servers from the official registry
- **Snyk Agent Scan Bridge** — run Snyk's `agent-scan` CLI and auto-generate MCPKernel policy rules from findings

---

## Getting Started

```bash
# Install with all backends
pip install "mcpkernel[all]"

# Start the security gateway
mcpkernel serve --host 127.0.0.1 --port 8000
```

Point your MCP client to `http://localhost:8000/mcp` instead of targeting tool servers directly.

---

## Use Cases — Guided Setup

### 1. Secure AI Coding Assistants (Copilot, Cursor, Windsurf)

Prevent your coding assistant from exfiltrating secrets or overwriting critical files.

```bash
pip install "mcpkernel[all]"
mcpkernel init
```

Add a policy to block sensitive file access:

```yaml
# .mcpkernel/policies/coding_assistant.yaml
rules:
  - id: CA-001
    name: Block secret file reads
    action: deny
    tool_patterns: ["read_file", "file_read"]
    arg_patterns:
      path: ".*\\.(env|pem|key|credentials)$"

  - id: CA-002
    name: Block outbound HTTP with tainted data
    action: deny
    tool_patterns: ["http_post", "http_request", "fetch"]
    taint_labels: [secret, pii]
```

Start the gateway and point your MCP client to it:

```bash
mcpkernel serve --port 8000
# In your editor's MCP config: http://localhost:8000/mcp
```

---

### 2. Autonomous Agent Frameworks (LangChain, CrewAI, AutoGen)

Sandbox every tool call your agents make — no code runs on bare metal.

```bash
pip install "mcpkernel[docker]"
mcpkernel init
```

Configure Docker sandboxing:

```yaml
# .mcpkernel/config.yaml
sandbox:
  backend: docker
  timeout_seconds: 30

policy:
  default_action: audit   # log everything, deny dangerous calls
```

Route your framework through MCPKernel:

```python
import httpx

# Instead of calling tools directly, route through MCPKernel
result = httpx.post("http://localhost:8000/mcp", json={
    "method": "tools/call",
    "params": {"name": "execute_code", "arguments": {"code": "print('hello')"}}
})
```

See full examples: [LangChain](examples/langchain/), [CrewAI](examples/crewai/), [AutoGen](examples/autogen/)

---

### 3. Enterprise MCP Deployments (OWASP ASI Compliance)

Deploy MCPKernel as the central chokepoint with strict OWASP ASI 2026 policies.

```bash
pip install "mcpkernel[all]"
mcpkernel init

# Apply the strict OWASP policy set
cp policies/owasp_asi_2026_strict.yaml .mcpkernel/policies/
```

```yaml
# .mcpkernel/config.yaml
policy:
  default_action: deny   # deny-by-default for production
  policy_paths:
    - .mcpkernel/policies/owasp_asi_2026_strict.yaml

observability:
  metrics_enabled: true
  otlp_endpoint: "http://your-otel-collector:4317"
```

Export audit logs to your SIEM:

```bash
mcpkernel audit-query --format cef > siem_export.log
mcpkernel audit-verify  # verify tamper-proof chain
```

---

### 4. Research Reproducibility (Deterministic Execution)

Every tool call is hashed and Sigstore-signed — replay any execution exactly.

```bash
pip install mcpkernel
mcpkernel serve
```

After running your experiment through MCPKernel:

```bash
# List all traces
mcpkernel trace-list

# Export a trace for your paper's appendix
mcpkernel trace-export <trace-id> > experiment_trace.json

# Replay and verify — detects any drift
mcpkernel replay <trace-id>
```

The Deterministic Execution Envelope (DEE) ensures reviewers can verify your results independently.

---

### 5. Multi-Agent Workflows (Cross-Tool Taint Tracking)

Prevent PII from leaking across tool boundaries in multi-agent pipelines.

```yaml
# .mcpkernel/policies/taint_isolation.yaml
rules:
  - id: TAINT-001
    name: Block PII in outbound calls
    action: deny
    tool_patterns: ["http_post", "send_email", "slack_message"]
    taint_labels: [pii, secret]

  - id: TAINT-002
    name: Audit all user input propagation
    action: audit
    taint_labels: [user_input]
```

MCPKernel tracks taint labels (secrets, PII, user input) across tool calls — if Agent A's database query returns SSNs, Agent B's HTTP POST is automatically blocked from sending them.

---

### 6. Regulated Industries (FINRA, SEC, Federal Reserve)

Use agent manifests for automated compliance enforcement.

```bash
# Validate your agent's compliance declarations
mcpkernel manifest-validate /path/to/agent-repo

# Import and generate policy rules from agent.yaml
mcpkernel manifest-import /path/to/agent-repo > compliance_rules.yaml
```

MCPKernel reads your `agent.yaml` and auto-generates policy rules for:
- Risk tier classification and supervision requirements
- Data governance and communications monitoring
- Segregation of duties enforcement
- Recordkeeping and audit trail requirements
- Framework-specific rules (FINRA, SEC, Federal Reserve)

Append-only audit logs with integrity verification provide the evidence trail regulators require:

```bash
mcpkernel audit-query --event-type policy_violation --format cef
mcpkernel audit-verify
```

---

## Integration Pipeline

MCPKernel fits into a full agent security pipeline. It integrates with tools at every stage:

```
BUILD          SCAN              PROTECT          CONNECT           OBSERVE         TEST
FastMCP ──▶ Snyk Agent Scan ──▶ MCPKernel ──▶ AI Agents ──▶ Langfuse ──▶ promptfoo
python-sdk   (static scan)     (runtime gate)  (LangChain,    (traces,     (prompt
                                               CrewAI, etc)    metrics)     testing)
```

### Built-in Integrations

| Integration | What It Does | CLI Command |
|------------|-------------|-------------|
| **Langfuse Export** | Ships audit entries + DEE traces to Langfuse for analytics | `mcpkernel langfuse-export` |
| **Guardrails AI** | Enhanced PII/secret/toxicity detection via Guardrails hub validators | Plugs into taint pipeline automatically |
| **MCP Server Registry** | Discover, search, validate upstream MCP servers | `mcpkernel registry-search <query>` |
| **Snyk Agent Scan** | Static security scan → auto-generated policy rules | `mcpkernel agent-scan <path>` |

### Example: Full Pipeline in 5 Commands

```bash
# 1. Initialize MCPKernel in your project
mcpkernel init

# 2. Scan your MCP config for vulnerabilities (SCAN phase)
mcpkernel agent-scan .mcpkernel/ -o .mcpkernel/policies/scan_rules.yaml

# 3. Search the registry for servers (DISCOVER phase)
mcpkernel registry-search filesystem

# 4. Start the security gateway (PROTECT phase)
mcpkernel serve -c .mcpkernel/config.yaml

# 5. Export traces to Langfuse for analytics (OBSERVE phase)
mcpkernel langfuse-export --limit 100
```

### Example: Registry Search Output

```
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

### Example: Agent Scan Output

```
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
  Exported to .mcpkernel/policies/scan_rules.yaml
```

### Example: Langfuse Export Output

```
$ mcpkernel langfuse-export --limit 50

✓ Exported 50 audit entries to Langfuse (https://cloud.langfuse.com)
```

Configure Langfuse with environment variables:

```bash
export MCPKERNEL_LANGFUSE__ENABLED=true
export MCPKERNEL_LANGFUSE__PUBLIC_KEY=pk-lf-...
export MCPKERNEL_LANGFUSE__SECRET_KEY=sk-lf-...
```

Or in YAML:

```yaml
# .mcpkernel/config.yaml
langfuse:
  enabled: true
  public_key: pk-lf-...
  secret_key: sk-lf-...
  host: https://cloud.langfuse.com  # or self-hosted
```

### Example: Guardrails AI Enhanced Taint Detection

When `guardrails_ai.enabled: true`, MCPKernel augments its built-in regex patterns with Guardrails AI validators for higher-accuracy detection:

```yaml
# .mcpkernel/config.yaml
guardrails_ai:
  enabled: true
  pii_validator: true      # DetectPII from guardrails hub
  secrets_validator: true   # SecretsPresent from guardrails hub
  toxic_content: false      # ToxicLanguage (optional, needs model)
  on_fail: noop             # noop = detect only, exception = block
```

```bash
# Install Guardrails AI + hub validators
pip install guardrails-ai
guardrails hub install hub://guardrails/detect_pii
guardrails hub install hub://guardrails/secrets_present
```

---

## Architecture

```
src/mcpkernel/
├── proxy/          # FastAPI MCP/A2A gateway — auth, rate limiting, plugin pipeline
├── policy/         # YAML rule engine with OWASP ASI 2026 mappings
├── taint/          # Source/sink taint tracking — secrets, PII, user input detection
├── sandbox/        # Docker, Firecracker, WASM, Microsandbox execution backends
├── dee/            # Deterministic Execution Envelopes — hash, sign, replay, drift detect
├── audit/          # Append-only Sigstore-signed audit logs + SIEM export
├── context/        # Token-efficient context reduction via TF-IDF + AST pruning
├── ebpf/           # Optional kernel-level syscall monitoring (BCC probes)
├── observability/  # Prometheus metrics, OpenTelemetry tracing, health checks
├── agent_manifest/ # agent.yaml loader, compliance-to-policy bridge, tool schema validator
├── integrations/   # Third-party pipeline integrations
│   ├── langfuse.py     # Async audit/trace export to Langfuse
│   ├── guardrails.py   # Guardrails AI PII/secret/toxicity validators
│   ├── registry.py     # MCP Server Registry client
│   └── agent_scan.py   # Snyk agent-scan bridge + policy rule generation
├── config.py       # Pydantic v2 hierarchical config (YAML → env → CLI)
├── cli.py          # Typer CLI — serve, scan, replay, audit, registry, agent-scan
└── utils.py        # Hashing, exceptions, structured logging
```

---

## Policy Rules

MCPKernel ships with three policy sets:

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
| `mcpkernel serve` | Start the proxy gateway |
| `mcpkernel init` | Initialize config and policies in a project |
| `mcpkernel scan <file>` | Static taint analysis on Python code |
| `mcpkernel validate-policy <path>` | Validate policy YAML files |
| `mcpkernel trace-list` | List recent execution traces |
| `mcpkernel trace-export <id>` | Export a trace as JSON |
| `mcpkernel replay <id>` | Replay a trace and check for drift |
| `mcpkernel audit-query` | Query audit logs with filters |
| `mcpkernel audit-verify` | Verify audit log integrity |
| `mcpkernel config-show` | Show effective configuration |
| `mcpkernel manifest-import <path>` | Import agent.yaml from a repo, convert to policy rules, export YAML |
| `mcpkernel manifest-validate <path>` | Validate agent.yaml + tool schemas, report compliance status |
| `mcpkernel registry-search <query>` | Search the MCP Server Registry for servers |
| `mcpkernel registry-list` | List available servers from the MCP Registry |
| `mcpkernel agent-scan <path>` | Run Snyk agent-scan, generate policy rules from findings |
| `mcpkernel langfuse-export` | Export audit entries to Langfuse for visualization |

---

## Configuration

Config loads hierarchically: **YAML → environment variables → CLI flags**.

```yaml
# .mcpkernel/config.yaml
proxy:
  host: 127.0.0.1
  port: 8000

# Upstream MCP servers to proxy to
upstream:
  - name: filesystem
    url: http://localhost:3000/mcp
    transport: streamable_http

sandbox:
  backend: docker        # docker | firecracker | wasm | microsandbox
  timeout_seconds: 30

taint:
  mode: light            # full | light | off

policy:
  default_action: deny   # deny-by-default for production
  policy_paths:
    - policies/owasp_asi_2026_strict.yaml

observability:
  log_level: INFO
  metrics_enabled: true
  otlp_endpoint: ""      # Set for OpenTelemetry export

# Third-party integrations
langfuse:
  enabled: false
  public_key: ""         # Set via MCPKERNEL_LANGFUSE__PUBLIC_KEY
  secret_key: ""         # Set via MCPKERNEL_LANGFUSE__SECRET_KEY

guardrails_ai:
  enabled: false
  pii_validator: true
  secrets_validator: true
  toxic_content: false

registry:
  enabled: true
  registry_url: https://registry.modelcontextprotocol.io

agent_scan:
  enabled: true
  binary_name: agent-scan
  auto_generate_policy: true
```

Environment variable override: `MCPKERNEL_SANDBOX__BACKEND=wasm`

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
git clone https://github.com/piyushptiwari1/mcpkernel.git
cd mcpkernel
pip install -e ".[dev]"

# Run tests (506 tests, ~89% coverage)
pytest tests/ -v --cov=mcpkernel

# Lint
ruff check src/ tests/
ruff format src/ tests/
```

---

## Examples

Integration examples for popular AI agent frameworks:

- [LangChain](examples/langchain/) — route LangChain tool calls through MCPKernel
- [CrewAI](examples/crewai/) — secure CrewAI agent tool usage
- [AutoGen](examples/autogen/) — protect AutoGen multi-agent conversations
- [Copilot Guard](examples/copilot_guard/) — intercept Copilot/Cursor tool calls
- [mcp-agent](examples/mcp_agent/) — route mcp-agent framework through MCPKernel

---

## Planned — The Road to Agent Sovereignty

### 1. Inter-Agent Proof of Intent (Zero-Knowledge Tooling)

Today agents trust the gateway. Tomorrow, **Agent A (Company X)** will call a tool on **Agent B (Company Y)** — across organizational boundaries.

- **Problem:** How does Agent B verify that Agent A's call was authorized by a specific policy without revealing the underlying data?
- **Plan:** Add a **ZK-Policy module** to MCPKernel. Agents will produce zero-knowledge proofs of policy compliance, enabling cross-org tool calls with cryptographic "sovereignty" — no private code or data is ever exposed.

### 2. Physical-World Safety Layer (Robotic MCP)

As MCP expands into IoT and Robotics (Digital Twins), the "sandbox" isn't just a VM — it's a **physical constraint**.

- **Problem:** If an agent calls `move_arm()`, the gateway must simulate the physics impact before allowing the tainted command to reach the actuator.
- **Plan:** Deterministic execution for hardware — a **physics-aware sandbox** that models real-world consequences (collision, force limits, safety envelopes) before any command reaches a physical device.

### 3. Automated Red-Teaming ("Immune System" Mode)

Instead of being a passive gatekeeper, the gateway should **attack itself**.

- **Problem:** New prompt injection techniques and policy bypasses appear daily. Static rules can't keep up.
- **Plan:** A **Shadow LLM module** that continuously attempts prompt injections against MCPKernel's own policies in real-time, discovering 0-day vulnerabilities in agent logic before adversaries do.

### 4. Parallel Taint Analysis (Cold-Start Latency < 50 ms)

In 2026, latency is everything. If the gateway adds more than 50 ms to a tool call, developers will disable it.

- **Plan:** Run taint sink checking **concurrently** with code execution rather than sequentially — analyze while the sandbox is running, abort only if a violation is detected, keeping the hot path near zero additional latency.

### 5. Context Minimization as a Cost Weapon

Security matters, but **saving money sells faster**. The `context/` module already prunes tokens via TF-IDF + AST analysis.

- **Plan:** Productize context minimization to deliver **≥ 30 % token reduction** while maintaining safety guarantees. When the gateway pays for itself in reduced LLM costs, adoption becomes a no-brainer.

---

## Competitive Landscape

MCPKernel is a **runtime security gateway** — it sits in the live request path intercepting every tool call. This is fundamentally different from the scanners and config auditors in the ecosystem:

| Project | What It Does | How MCPKernel Differs |
|---------|-------------|---------------------|
| [SaravanaGuhan/mcp-guard](https://github.com/SaravanaGuhan/mcp-guard) | Static/dynamic **vulnerability scanner** for MCP servers (CVSS v4.0 + AIVSS) | Scanner finds bugs *before* deployment; MCPKernel enforces policy *at runtime*. Complementary — run mcp-guard in CI, MCPKernel in prod. |
| [aryanjp1/mcpguard](https://github.com/aryanjp1/mcpguard) (PyPI `mcpguard`) | MCP config **static scanner** — audits `claude_desktop_config.json` for OWASP MCP Top 10 | Config linter, no runtime component. Internally uses `mcpshield` package. |
| [kriskimmerle/mcpguard](https://github.com/kriskimmerle/mcpguard) | MCP config **auditor** — secrets, unpinned packages, Docker access. Zero deps. **Archived Feb 2026.** | Single-file config checker. Archived. No overlap. |
| [mcpshield](https://pypi.org/project/mcpshield/) (PyPI) | Database security gateway for AI agents (Postgres, MySQL, Redis, MongoDB) with cloud dashboard | DB-only scope with SaaS dependency. MCPKernel is infrastructure-agnostic, self-hosted, and covers any MCP tool call. |
| [mcp-proxy](https://pypi.org/project/mcp-proxy/) | Transport bridge (stdio ↔ SSE/StreamableHTTP) | Pure transport, zero security features. |

**Bottom line:** No existing project provides the full runtime stack MCPKernel delivers — policy engine + taint tracking + sandboxing + deterministic envelopes + Sigstore audit + eBPF, all in one gateway.

---

## Contributing — You're Welcome Here

MCPKernel is built in the open and we actively welcome contributions of all kinds — bug reports, feature ideas, documentation improvements, policy templates, and code.

**Ways to contribute:**

| What | How |
|------|-----|
| Report a bug | [Open an issue](https://github.com/piyushptiwari1/mcpkernel/issues/new) with steps to reproduce |
| Suggest a feature | [Open an issue](https://github.com/piyushptiwari1/mcpkernel/issues/new) describing your use case |
| Add a policy template | Create a YAML file in `policies/` for your domain (healthcare, fintech, etc.) |
| Add a framework example | Add to `examples/` — we'd love OpenAI Agents SDK, Semantic Kernel, etc. |
| Improve documentation | Docs, README, and inline comments always need help |
| Write tests | We target >90% coverage — every new test helps |
| Fix a bug or add a feature | Fork → branch → test → PR (see below) |

**Getting started in 60 seconds:**

```bash
git clone https://github.com/piyushptiwari1/mcpkernel.git
cd mcpkernel
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev,all]"
pytest  # 443 tests, all should pass
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for the full development workflow, commit conventions, and PR process.

Not sure where to start? Look for issues labeled **`good first issue`** or **`help wanted`**, or just open a discussion — we're happy to point you to something that fits your interest.

---

## License

Apache 2.0 — see [LICENSE](LICENSE).

# MCPKernel — The Security Kernel for AI Agents

> **Open-source MCP/A2A security gateway that stops tool poisoning, data exfiltration, prompt injection, and rug-pull attacks — with policy enforcement, taint tracking, sandboxed execution, deterministic envelopes, skill auditing, and Sigstore audit for every AI agent tool call. Works with Claude Desktop, Cursor, VS Code, Windsurf, OpenClaw, and any MCP client. OWASP ASI 2026 compliant.**

[![CI](https://github.com/piyushptiwari1/mcpkernel/actions/workflows/ci.yml/badge.svg)](https://github.com/piyushptiwari1/mcpkernel/actions/workflows/ci.yml)
[![PyPI version](https://img.shields.io/pypi/v/mcpkernel.svg)](https://pypi.org/project/mcpkernel/)
[![Tests](https://img.shields.io/badge/tests-718%20passed-brightgreen.svg)](https://github.com/piyushptiwari1/mcpkernel)
[![Coverage](https://img.shields.io/badge/coverage-86%25-brightgreen.svg)](https://github.com/piyushptiwari1/mcpkernel)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://python.org)
[![Downloads](https://img.shields.io/pypi/dm/mcpkernel.svg)](https://pypi.org/project/mcpkernel/)
[![Docs](https://img.shields.io/badge/docs-live-brightgreen.svg)](https://piyushptiwari1.github.io/mcpkernel/)

> **[Read the full documentation →](https://piyushptiwari1.github.io/mcpkernel/)**

---

## Quick Start

### Option A: Security Gateway (proxy mode)

```bash
pip install "mcpkernel[all]"
mcpkernel serve --host 127.0.0.1 --port 8000
```

Point your MCP client to `http://localhost:8000/mcp` instead of targeting tool servers directly. Every tool call is now policy-checked, taint-scanned, sandboxed, and audit-logged.

### Option B: MCP Server (tool mode — one command)

```bash
pip install mcpkernel
mcpkernel install claude    # or: cursor, vscode, windsurf, zed, openclaw, goose
```

This adds MCPKernel as an MCP server in your IDE. Your agent can now call `mcpkernel_scan_tool`, `mcpkernel_check_taint`, `mcpkernel_validate_policy`, and more — natively.

### Option C: Python API

```python
from mcpkernel import MCPKernelProxy

async with MCPKernelProxy(
    upstream=["http://localhost:3000/mcp"],
    policy="strict",
    taint=True,
) as proxy:
    result = await proxy.call_tool("read_file", {"path": "data.csv"})
```

Or secure any function with one decorator:

```python
from mcpkernel import protect

@protect(policy="strict", taint=True)
async def read_data(path: str) -> str:
    return Path(path).read_text()
```

---

## Why MCPKernel?

AI agents (LangChain, CrewAI, AutoGen, Copilot, OpenClaw) call tools autonomously — reading files, executing code, making HTTP requests. The MCP ecosystem has **344+ reported security advisories** in projects like OpenClaw alone, with critical vulnerabilities including tool poisoning attacks, privilege escalation, data exfiltration, and rug-pull exploits.

**MCPKernel is the missing chokepoint.** It sits between your agent and MCP tool servers, enforcing security policies on every single call:

```
┌─────────────┐     ┌──────────────────────────┐     ┌─────────────┐
│  AI Agent    │────▶│       MCPKernel           │────▶│  MCP Tool   │
│ (LangChain,  │◀────│  Security Gateway        │◀────│  Server     │
│ CrewAI,      │     └──────────────────────────┘     └─────────────┘
│ OpenClaw,    │      │ Policy │ Taint │ Sandbox │
│ Cursor, etc) │      │  DEE   │ Audit │ eBPF    │
└─────────────┘      │ Skills │ DLP   │ Doctor  │
```

### What happens to every tool call:

| Step | What MCPKernel Does |
|------|-------------------|
| **1. Policy Check** | Evaluates against YAML rules with OWASP ASI 2026 mappings — blocks or allows |
| **2. Taint Scan** | Detects secrets (AWS keys, JWTs), PII (SSN, credit cards), and user input in arguments |
| **3. DLP Guard** | Prevents multi-hop data leaks across tool boundaries (PII in → HTTP out = blocked) |
| **4. Sandbox Execution** | Runs code in Docker, Firecracker, WASM, or Microsandbox — never on bare metal |
| **5. Deterministic Envelope** | Hashes inputs/outputs, Sigstore-signs the trace — fully replayable |
| **6. Audit Log** | Writes to tamper-proof append-only log with SIEM export (CEF, JSONL, CSV, SARIF) |

---

---

## The MCP Security Problem

The MCP ecosystem is growing fast — but security hasn't kept pace. Here are the real-world threats MCPKernel defends against:

| Threat | How It Works | Real-World Impact | MCPKernel Defense |
|--------|-------------|-------------------|-------------------|
| **Tool Poisoning** | Hidden `<IMPORTANT>` instructions in tool descriptions trick agents into reading SSH keys, `.env` files, credentials | Cursor, Claude Desktop, any MCP client — credentials exfiltrated silently | **Poisoning Scanner** detects hidden instructions, Unicode obfuscation, `<IMPORTANT>` blocks |
| **Tool Shadowing** | Malicious MCP server injects behavior that overrides trusted servers (e.g., redirects all emails to attacker) | Agent sends data to attacker while appearing to use trusted tools | **Cross-server policy isolation** + taint labels block data from flowing to untrusted sinks |
| **MCP Rug Pulls** | Server changes tool descriptions after user approves installation | Trusted tool becomes malicious overnight — no detection | **DEE envelope hashing** pins tool descriptions; drift detection catches changes |
| **Privilege Escalation** | Auth reconnect self-claims `operator.admin`; plugins inherit full host trust | 2 critical CVEs in OpenClaw (GHSA-9hjh, GHSA-fqw4) — RCE via scope widening | **Policy engine** enforces least-privilege; no implicit admin escalation |
| **Data Exfiltration** | Agent reads secrets then passes them as hidden parameters to outbound tools | PII, API keys, SSH keys leaked via side-channel in tool arguments | **Taint tracking** + **DLP chain detection** blocks tainted data from reaching sinks |
| **Skill Supply Chain** | Malicious OpenClaw/ClawHub skills contain `curl\|bash`, `rm -rf`, exfiltration endpoints | User installs skill that backdoors their system | **Skill Scanner** audits SKILL.md for 25+ dangerous patterns before installation |
| **Sandbox Escape** | Exec runs on host when sandbox is off (OpenClaw default: `sandbox.mode=off`) | Agent code runs with full OS privileges | **4 sandbox backends** (Docker, Firecracker, WASM, Microsandbox) — sandbox-first by design |
| **No Audit Trail** | No tamper-proof record of what agents did, when, or why | Impossible to investigate incidents or prove compliance | **Sigstore-signed append-only logs** with SIEM export (CEF, JSONL, CSV, SARIF) |

> **OpenClaw has 344+ security advisories** including 2 critical RCE vulnerabilities, scope bypass issues, and webhook authentication gaps. MCPKernel is the security layer that platforms like OpenClaw need but don't have built in.

---

## Features

### Core Security Pipeline
- **YAML Policy Engine** — define allow/deny/audit/sandbox rules per tool, argument pattern, or taint label
- **Taint Tracking** — automatic detection of secrets, PII, API keys, JWTs in tool call arguments
- **DLP Chain Detection** — prevents multi-hop data leaks across tool boundaries (database → HTTP blocked)
- **4 Sandbox Backends** — Docker, Firecracker microVMs, WASM, Microsandbox
- **Deterministic Execution Envelopes (DEE)** — every execution is hashed and Sigstore-signed for replay
- **OWASP ASI 2026 Compliance** — built-in policy sets mapping to ASI-01 through ASI-08
- **Append-Only Audit Logs** — SQLite-backed, content-hashed, with CEF/JSONL/CSV/SARIF SIEM export

### Threat Detection & Scanning
- **Tool Poisoning Scanner** — detects hidden instructions, Unicode obfuscation, and prompt injection in MCP tool descriptions
- **Skill Scanner** — audits OpenClaw/ClawHub SKILL.md files for dangerous shell commands, exfiltration patterns, and hidden instructions
- **MCP Config Discovery** — auto-discovers MCP configurations across Claude, Cursor, VS Code, Windsurf, Zed, OpenClaw, Goose
- **Snyk Agent Scan Bridge** — run Snyk's `agent-scan` CLI and auto-generate policy rules from findings

### Multi-Client Integration
- **One-Command Install** — `mcpkernel install claude` adds security tools to any supported IDE
- **MCPKernel as MCP Server** — expose scan, validate, taint-check, and doctor as native agent tools
- **7 Supported Clients** — Claude Desktop, Cursor, VS Code, Windsurf, Zed, OpenClaw, Goose
- **OpenClaw Security Skill** — installable skill package for the OpenClaw/ClawHub ecosystem

### Developer Experience
- **Python API** — `MCPKernelProxy` class and `@protect` decorator for programmatic use
- **Policy Presets** — built-in `permissive`, `standard`, and `strict` presets — zero-config security
- **Doctor Diagnostics** — `mcpkernel doctor` checks Python, dependencies, config, exposed secrets, permissions
- **VS Code Extension** — TreeView for discovered servers, security findings panel, integrated commands

### Platform & Observability
- **Kong-Style Plugin Pipeline** — `pre_execution → execution → post_execution → log` with priorities
- **Rate Limiting** — per-identity token bucket with LRU eviction
- **Prometheus Metrics + OpenTelemetry** — full observability out of the box
- **Optional eBPF Probes** — kernel-level syscall monitoring at MCP boundaries
- **Agent Manifest Integration** — load `agent.yaml`, convert compliance (FINRA/SEC) to policy rules, block undeclared tools
- **Langfuse Observability Export** — async batched export to Langfuse for LLM-level analytics
- **Guardrails AI Validation** — enhanced PII, secret, and toxicity detection via Guardrails hub validators
- **MCP Server Registry** — discover, search, and validate upstream MCP servers from the official registry

### Causal Trust Graph (CTG) — *Novel Research Contribution*
- **Adaptive Trust Decay** — tool/server trust erodes exponentially: T(t) = T₀ · e^{-λ(t-t₀)} · Π w(vᵢ)
- **Retroactive Taint Invalidation** — when a source is compromised, all downstream data is retroactively tainted
- **Behavioral Fingerprinting** — detects anomalous tool-call patterns via graph topology z-scores
- **Minimum Privilege Computation** — derives provably minimal permissions from observed causal chains
- **Causal Chain Analysis** — trace any tool output back to its root data sources

### Security Protections (MCP Spec 2025-11-25)
- **Confused Deputy Defense** — prevents cross-server delegation attacks with tool/server allowlists
- **Token Passthrough Guard** — blocks credential leakage (OpenAI keys, GitHub PATs, AWS keys, JWTs) in args and results
- **SSRF Guard** — blocks private networks, cloud metadata (169.254.169.254), with domain allowlists
- **Session Hijacking Defense** — HMAC-bound sessions with client fingerprint verification and expiry
- **Memory Poisoning Defense** — detects self-reinforcing injection (Zombie Agents) with repetition scoring
- **Unified Security Pipeline** — run all checks in a single `pipeline.check_tool_call()` invocation

### Compliance Presets
- **One-Line Activation** — `apply_preset("hipaa", settings)` configures all security controls
- **5 Built-in Presets** — HIPAA, SOC 2, PCI DSS v4.0, GDPR Article 25, FedRAMP High
- **YAML Configurable** — set `compliance.preset: hipaa` in your config file

---

## Getting Started

```bash
# Install with all backends
pip install "mcpkernel[all]"

# Start the security gateway
mcpkernel serve --host 127.0.0.1 --port 8000
```

Point your MCP client to `http://localhost:8000/mcp` instead of targeting tool servers directly.

### Add MCPKernel as an MCP Server (agent-callable security tools)

```bash
# Install into your IDE — one command
mcpkernel install claude    # Claude Desktop
mcpkernel install cursor    # Cursor IDE
mcpkernel install vscode    # VS Code + Copilot
mcpkernel install windsurf  # Windsurf
mcpkernel install zed       # Zed
mcpkernel install openclaw  # OpenClaw
mcpkernel install goose     # Goose
```

Once installed, your agent can call these security tools natively:

| MCP Tool | What It Does |
|----------|-------------|
| `mcpkernel_scan_tool` | Scan a tool's description for poisoning, shadowing, and prompt injection |
| `mcpkernel_validate_policy` | Validate a YAML policy file for syntax and logic errors |
| `mcpkernel_discover_configs` | Find all MCP configurations on the system |
| `mcpkernel_check_taint` | Check text for leaked secrets, PII, and API keys |
| `mcpkernel_scan_skill` | Audit an OpenClaw/ClawHub SKILL.md for dangerous patterns |
| `mcpkernel_doctor` | Run health diagnostics on the MCPKernel installation |

### Run Health Diagnostics

```bash
mcpkernel doctor
```

Checks: Python version, dependencies, config file validity, exposed secrets in environment, tool availability, and file permissions.

### Scan Skills Before Installing

```bash
# Scan a single skill
mcpkernel scan-skill path/to/SKILL.md

# Scan a directory of skills
mcpkernel scan-skill skills/ --json
```

Detects: `curl|bash` pipes, `rm -rf`, exfiltration endpoints, hardcoded API keys, hidden instructions, undeclared environment variables, and more.

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
DISCOVER         SCAN              PROTECT          CONNECT           OBSERVE         TEST
discover ──▶ poison-scan ──▶    MCPKernel   ──▶  AI Agents   ──▶  Langfuse  ──▶ promptfoo
scan-skill   agent-scan      (runtime gate)    (LangChain,     (traces,     (prompt
doctor       Snyk CLI        mcp-serve         CrewAI, etc)     metrics)     testing)
                              install           OpenClaw,
                                                Cursor, etc...
```

### Built-in Integrations

| Integration | What It Does | CLI Command |
|------------|-------------|-------------|
| **Langfuse Export** | Ships audit entries + DEE traces to Langfuse for analytics | `mcpkernel langfuse-export` |
| **Guardrails AI** | Enhanced PII/secret/toxicity detection via Guardrails hub validators | Plugs into taint pipeline automatically |
| **MCP Server Registry** | Discover, search, validate upstream MCP servers | `mcpkernel registry-search <query>` |
| **Snyk Agent Scan** | Static security scan → auto-generated policy rules | `mcpkernel agent-scan <path>` |
| **Tool Poisoning Scanner** | Detect hidden instructions and shadowing in tool descriptions | `mcpkernel poison-scan` |
| **Skill Scanner** | Audit OpenClaw/ClawHub SKILL.md files for supply chain attacks | `mcpkernel scan-skill <path>` |
| **MCP Config Discovery** | Find all MCP configs across IDEs (Claude, Cursor, VS Code, etc.) | `mcpkernel discover` |
| **Multi-Client Installer** | Install MCPKernel as MCP server in any supported IDE | `mcpkernel install <target>` |
| **Doctor Diagnostics** | Health check: Python, deps, config, secrets, permissions | `mcpkernel doctor` |

### Example: Full Pipeline in 7 Commands

```bash
# 1. Install MCPKernel into your IDE
mcpkernel install claude

# 2. Run health diagnostics
mcpkernel doctor

# 3. Discover all MCP configurations on this system
mcpkernel discover

# 4. Scan for tool poisoning and shadowing attacks
mcpkernel poison-scan

# 5. Scan skills before installing them
mcpkernel scan-skill downloaded-skills/

# 6. Start the security gateway (PROTECT phase)
mcpkernel serve -c .mcpkernel/config.yaml

# 7. Export traces to Langfuse for analytics (OBSERVE phase)
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
├── proxy/          # FastAPI MCP/A2A gateway — auth (OAuth2, mTLS), rate limiting, plugin pipeline
├── policy/         # YAML rule engine with OWASP ASI 2026 mappings
├── taint/          # Source/sink taint tracking — secrets, PII, user input + DLP chain detection
├── sandbox/        # Docker, Firecracker, WASM, Microsandbox execution backends
├── dee/            # Deterministic Execution Envelopes — hash, sign, replay, drift detect
├── audit/          # Append-only Sigstore-signed audit logs + SIEM export (CEF, JSONL, CSV, SARIF)
├── context/        # Token-efficient context reduction via TF-IDF + AST pruning
├── ebpf/           # Optional kernel-level syscall monitoring (BCC probes)
├── observability/  # Prometheus metrics, OpenTelemetry tracing, health checks
├── agent_manifest/ # agent.yaml loader, compliance-to-policy bridge, tool schema validator
├── integrations/   # Third-party pipeline integrations
│   ├── langfuse.py       # Async audit/trace export to Langfuse
│   ├── guardrails.py     # Guardrails AI PII/secret/toxicity validators
│   ├── registry.py       # MCP Server Registry client
│   ├── agent_scan.py     # Snyk agent-scan bridge + policy rule generation
│   ├── discovery.py      # Auto-discover MCP configs across IDEs
│   ├── poisoning.py      # Tool poisoning & shadowing attack scanner
│   ├── skill_scanner.py  # OpenClaw/ClawHub SKILL.md security auditor
│   ├── installer.py      # Multi-client MCP server installer (7 IDE targets)
│   └── doctor.py         # Health diagnostics (deps, config, secrets, permissions)
├── mcp_server.py   # MCPKernel as MCP server — 6 security tools over stdio/HTTP
├── api.py          # Programmatic Python API — MCPKernelProxy, protect() decorator
├── presets.py      # Built-in policy presets (permissive, standard, strict)
├── config.py       # Pydantic v2 hierarchical config (YAML → env → CLI)
├── cli.py          # Typer CLI — 35+ commands for security, scanning, install, audit
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
| **Security Gateway** | |
| `mcpkernel serve` | Start the proxy gateway |
| `mcpkernel mcp-serve` | Run MCPKernel as an MCP server (agent-callable tools via stdio) |
| **Setup & Config** | |
| `mcpkernel init` | Initialize config and policies in a project |
| `mcpkernel install <target>` | Install MCPKernel as MCP server in Claude/Cursor/VS Code/Windsurf/Zed/OpenClaw/Goose |
| `mcpkernel uninstall <target>` | Remove MCPKernel from a target client |
| `mcpkernel doctor` | Run health diagnostics (Python, deps, config, secrets, permissions) |
| `mcpkernel config-show` | Show effective configuration |
| `mcpkernel quickstart` | One-command demo — init, show config, verify pipeline |
| `mcpkernel presets` | List available policy presets and their rules |
| `mcpkernel status` | Show current config, hooks, policy, and upstream servers |
| **Scanning & Detection** | |
| `mcpkernel scan <file>` | Static taint analysis on Python code |
| `mcpkernel poison-scan` | Scan MCP configs for tool poisoning and shadowing attacks |
| `mcpkernel scan-skill <path>` | Audit OpenClaw/ClawHub SKILL.md files for dangerous patterns |
| `mcpkernel discover` | Auto-discover all MCP configurations across installed IDEs |
| `mcpkernel agent-scan <path>` | Run Snyk agent-scan, generate policy rules from findings |
| **Policy & Compliance** | |
| `mcpkernel validate-policy <path>` | Validate policy YAML files |
| `mcpkernel manifest-import <path>` | Import agent.yaml, convert to policy rules |
| `mcpkernel manifest-validate <path>` | Validate agent.yaml + tool schemas, report compliance |
| **Tracing & Audit** | |
| `mcpkernel trace-list` | List recent execution traces |
| `mcpkernel trace-export <id>` | Export a trace as JSON |
| `mcpkernel replay <id>` | Replay a trace and check for drift |
| `mcpkernel audit-query` | Query audit logs with filters |
| `mcpkernel audit-verify` | Verify audit log integrity |
| **Integrations** | |
| `mcpkernel langfuse-export` | Export audit entries to Langfuse |
| `mcpkernel registry-search <query>` | Search the MCP Server Registry |
| `mcpkernel registry-list` | List available servers from the MCP Registry |

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

# Run tests (718 tests, ~86% coverage)
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

MCPKernel is a **runtime security gateway + agent-callable security toolkit** — it sits in the live request path intercepting every tool call AND exposes security tools that agents can call directly. This is fundamentally different from the scanners, config auditors, and personal AI assistants in the ecosystem:

| Project | What It Does | How MCPKernel Differs |
|---------|-------------|---------------------|
| [OpenClaw](https://github.com/openclaw/openclaw) (338k⭐) | Personal AI assistant with 25+ channel integrations, skills platform, Gateway WS control plane | OpenClaw is a **consumer** of MCP tools. MCPKernel is the **security layer** OpenClaw needs — it has 344+ security advisories, sandbox off by default, no taint tracking, no policy engine. MCPKernel plugs directly into OpenClaw as a security skill. |
| [kernel.sh](https://www.kernel.sh) | Cloud-hosted MCP server with browser automation, OAuth 2.1, multi-client setup | Cloud SaaS product. MCPKernel is self-hosted, open-source, and provides the security infrastructure kernel.sh doesn't — policy enforcement, taint tracking, sandboxing. |
| [Invariant Guardrails](https://invariantlabs.ai) | AI agent security scanning — discovered Tool Poisoning Attacks | Research + SaaS guardrails. MCPKernel is the self-hosted runtime enforcement layer that implements their recommended mitigations (tool pinning, cross-server isolation, taint control). |
| [MCP Market](https://mcpmarket.com) | Skill directory (72k+ skills) | Discovery platform. MCPKernel's **skill scanner** audits skills from any marketplace before installation. |
| [SaravanaGuhan/mcp-guard](https://github.com/SaravanaGuhan/mcp-guard) | Static/dynamic vulnerability scanner (CVSS v4.0 + AIVSS) | Scanner finds bugs *before* deployment; MCPKernel enforces policy *at runtime*. Complementary. |
| [aryanjp1/mcpguard](https://github.com/aryanjp1/mcpguard) (PyPI `mcpguard`) | MCP config static scanner — audits config for OWASP MCP Top 10 | Config linter, no runtime component. MCPKernel includes discovery + runtime enforcement. |
| [mcpshield](https://pypi.org/project/mcpshield/) | Database security gateway for AI agents (Postgres, MySQL, Redis) | DB-only scope with SaaS dependency. MCPKernel covers any MCP tool call, self-hosted. |
| [mcp-proxy](https://pypi.org/project/mcp-proxy/) | Transport bridge (stdio ↔ SSE/StreamableHTTP) | Pure transport, zero security features. |

**Bottom line:** No existing project provides the full stack MCPKernel delivers — policy engine + taint tracking + DLP + sandboxing + skill auditing + multi-client installer + agent-callable tools + deterministic envelopes + Sigstore audit + eBPF, all in one open-source package.

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
pytest  # 718 tests, all should pass
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for the full development workflow, commit conventions, and PR process.

Not sure where to start? Look for issues labeled **`good first issue`** or **`help wanted`**, or just open a discussion — we're happy to point you to something that fits your interest.

---

## License

Apache 2.0 — see [LICENSE](LICENSE).

---

## Documentation

Full tutorial-style documentation with examples, API reference, and guides:

**[https://piyushptiwari1.github.io/mcpkernel/](https://piyushptiwari1.github.io/mcpkernel/)**

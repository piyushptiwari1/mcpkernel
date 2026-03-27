---
title: "MCPKernel — The Missing Security Kernel for AI Agents"
published: true
description: "Every AI agent tool call should be policy-checked, taint-scanned, sandboxed, and audit-logged. MCPKernel makes it happen."
tags: ai, security, python, opensource
cover_image: 
canonical_url: https://github.com/piyushptiwari1/mcpkernel
---

## The Problem Nobody's Talking About

Your AI agent — LangChain, CrewAI, AutoGen, Copilot — calls tools autonomously. It reads files, executes code, makes HTTP requests. **One prompt injection and your secrets are gone.**

There's no firewall between your agent and your infrastructure. Until now.

## Introducing MCPKernel

MCPKernel is an open-source **MCP/A2A security gateway** that sits between your AI agent and MCP tool servers. Every single tool call passes through it:

```
┌─────────────┐     ┌──────────────────────────┐     ┌─────────────┐
│  AI Agent    │────▶│       MCPKernel           │────▶│  MCP Tool   │
│ (LangChain,  │◀────│  Security Gateway        │◀────│  Server     │
│ CrewAI, etc) │     └──────────────────────────┘     └─────────────┘
                       Policy │ Taint │ Sandbox
                        DEE   │ Audit │ eBPF
```

### What happens to every tool call:

| Step | What It Does |
|------|-------------|
| **1. Policy Check** | Evaluates against YAML rules with OWASP ASI 2026 mappings |
| **2. Taint Scan** | Detects secrets (AWS keys, JWTs), PII (SSN, credit cards) |
| **3. Sandbox Execution** | Runs in Docker, Firecracker, WASM, or Microsandbox |
| **4. Deterministic Envelope** | Hashes inputs/outputs, Sigstore-signs the trace |
| **5. Audit Log** | Tamper-proof append-only log with SIEM export |

## Get Started in 30 Seconds

```bash
pip install "mcpkernel[all]"
mcpkernel serve --host 127.0.0.1 --port 8000
```

Point your MCP client to `http://localhost:8000/mcp`. Done.

Or use the Python API:

```python
from mcpkernel import MCPKernelProxy

async with MCPKernelProxy(
    upstream=["http://localhost:3000/mcp"],
    policy="strict",
    taint=True,
) as proxy:
    result = await proxy.call_tool("read_file", {"path": "data.csv"})
```

## Real Use Cases

### 1. Secure Your Coding Assistant
Block Copilot/Cursor from reading `.env`, `.pem`, or credential files:

```yaml
rules:
  - id: CA-001
    name: Block secret file reads
    action: deny
    tool_patterns: ["read_file", "file_read"]
    arg_patterns:
      path: ".*\\.(env|pem|key|credentials)$"
```

### 2. Sandbox Agent Tool Calls
Every `execute_code` call runs in Docker — never on bare metal:

```yaml
sandbox:
  backend: docker
  timeout_seconds: 30
```

### 3. Cross-Tool Taint Tracking
If Agent A's database query returns SSNs, Agent B's HTTP POST is **automatically blocked** from sending them. Taint labels propagate across tool boundaries.

### 4. Deterministic Replay
Every execution is hashed and Sigstore-signed. Replay any tool call exactly for audit, compliance, or research reproducibility.

## The Full Stack

- **YAML Policy Engine** — OWASP ASI 2026 mappings (ASI-01 through ASI-08)
- **Taint Tracking** — secrets, PII, API keys, JWTs, user input
- **4 Sandbox Backends** — Docker, Firecracker microVMs, WASM, Microsandbox
- **Deterministic Execution Envelopes** — Sigstore-signed, replayable
- **Append-Only Audit Logs** — SQLite-backed, CEF/JSONL/CSV SIEM export
- **Prometheus + OpenTelemetry** — full observability
- **eBPF Probes** — kernel-level syscall monitoring
- **Langfuse Integration** — trace export for LLM analytics
- **Guardrails AI** — enhanced PII/toxicity detection
- **MCP Server Registry** — discover and validate upstream servers
- **Snyk Agent Scan** — static scan → auto-generated policy rules

## Numbers

- **695 tests**, ~86% coverage
- Python 3.12+ (async-first)
- Apache 2.0 license
- OWASP ASI 2026 compliant

## Links

- **GitHub**: [github.com/piyushptiwari1/mcpkernel](https://github.com/piyushptiwari1/mcpkernel)
- **PyPI**: [pypi.org/project/mcpkernel](https://pypi.org/project/mcpkernel/)
- **Docs**: [Usage Guide](https://github.com/piyushptiwari1/mcpkernel/blob/main/docs/USAGE.md)

---

MCPKernel is the chokepoint your agent stack is missing. Star the repo if this is useful — and PRs are welcome. 🔒

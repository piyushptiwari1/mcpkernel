# MCPKernel — The Missing Security Kernel for AI Agents

*Every AI agent tool call should be policy-checked, taint-scanned, sandboxed, and audit-logged.*

---

## The Problem

AI agents are calling tools autonomously — reading files, executing code, making HTTP requests. LangChain, CrewAI, AutoGen, Copilot, Cursor — they all do it. And there's **no security layer** between the agent and your infrastructure.

One prompt injection. That's all it takes. Your AWS keys, database credentials, customer PII — exfiltrated through a tool call the agent thought was legitimate.

The MCP (Model Context Protocol) ecosystem is growing fast, but security hasn't kept up. There are config scanners and static analyzers, but **nothing sits in the live request path** enforcing policy at runtime.

## The Solution: MCPKernel

I built [MCPKernel](https://github.com/piyushptiwari1/mcpkernel) — an open-source security gateway that transparently proxies every MCP/A2A tool call through a full security pipeline:

1. **Policy Check** — YAML rules with OWASP ASI 2026 mappings
2. **Taint Scan** — Detects secrets, PII, API keys in arguments
3. **Sandbox Execution** — Docker, Firecracker, WASM, or Microsandbox
4. **Deterministic Envelope** — Hashes + Sigstore-signs every execution
5. **Audit Log** — Tamper-proof, append-only, SIEM-exportable

### How it works

```
Agent (LangChain/CrewAI/etc) → MCPKernel Gateway → MCP Tool Server
                                 ↕
                    Policy | Taint | Sandbox | DEE | Audit
```

You install it, point your agent to it instead of the tool server directly, and every call is now secured:

```bash
pip install "mcpkernel[all]"
mcpkernel serve --host 127.0.0.1 --port 8000
```

### What makes it different

The existing MCP security tools are either:
- **Static scanners** (find bugs before deployment) — complementary to MCPKernel
- **Config auditors** (check your MCP config for issues) — single-file checkers
- **Database-only gateways** (Postgres/MySQL scope only, SaaS-dependent)

MCPKernel is the **only runtime gateway** that provides the full stack: policy + taint + sandbox + deterministic envelopes + Sigstore audit + eBPF, all in one self-hosted package.

## Key Features

- **YAML Policy Engine** with OWASP ASI 2026 compliance (ASI-01 → ASI-08)
- **Taint Tracking** across tool boundaries — if one agent returns PII, another agent's outbound call is blocked
- **4 Sandbox Backends** — Docker, Firecracker microVMs, WASM, Microsandbox
- **Deterministic Execution Envelopes** — every execution is replayable for audit/compliance
- **Langfuse Integration** — export traces for LLM analytics
- **Guardrails AI** — enhanced PII/toxicity detection
- **Snyk Agent Scan Bridge** — static scan → auto-generated policy rules
- **Agent Manifest** (`agent.yaml`) — FINRA/SEC/Federal Reserve compliance declarations → policy rules

## Use Cases

1. **Secure coding assistants** — Block Copilot from reading `.env` files or sending secrets outbound
2. **Sandbox autonomous agents** — Every `execute_code` runs in Docker, not on your machine
3. **Enterprise compliance** — OWASP ASI 2026, FINRA, SEC audit trails
4. **Research reproducibility** — Replay any experiment exactly with Sigstore verification
5. **Multi-agent PII isolation** — Taint labels prevent data leaking across tool boundaries

## Current State

- **695 tests**, ~86% coverage
- Python 3.12+ (async-first, fully typed)
- Apache 2.0 license
- Published on [PyPI](https://pypi.org/project/mcpkernel/)
- CI: ruff + mypy + pytest + pip-audit

## What I'm Looking For

- **Feedback** on the architecture and approach
- **Contributors** — especially for sandbox backends, policy templates for specific industries, and framework integration examples
- **Production stories** — if you try it, I want to hear what works and what doesn't

---

**GitHub**: [github.com/piyushptiwari1/mcpkernel](https://github.com/piyushptiwari1/mcpkernel)

**PyPI**: `pip install mcpkernel`

**Docs**: [Usage Guide](https://github.com/piyushptiwari1/mcpkernel/blob/main/docs/USAGE.md)

Happy to answer any questions in the comments.

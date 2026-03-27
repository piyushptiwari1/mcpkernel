## Reddit Post Templates for MCPKernel

---

### r/Python — Show & Tell

**Title**: MCPKernel — Open-source security gateway for AI agent tool calls (MCP/A2A)

I built MCPKernel, an async Python security gateway that sits between AI agents and MCP tool servers. Every tool call gets:

- Policy checked (YAML rules, OWASP ASI 2026)
- Taint scanned (secrets, PII, API keys)
- Sandboxed (Docker, Firecracker, WASM, Microsandbox)
- Hashed + Sigstore-signed (deterministic replay)
- Audit logged (tamper-proof, SIEM export)

```bash
pip install "mcpkernel[all]"
mcpkernel serve --host 127.0.0.1 --port 8000
```

695 tests, ~86% coverage, Python 3.12+, Apache 2.0. Fully async, typed, structlog throughout.

GitHub: https://github.com/piyushptiwari1/mcpkernel
PyPI: https://pypi.org/project/mcpkernel/

Looking for feedback on the architecture and contributors for sandbox backends + industry-specific policy templates.

---

### r/MachineLearning — [P] Project

**Title**: [P] MCPKernel: Runtime security gateway for AI agent tool calls — policy, taint tracking, sandboxing, deterministic replay

AI agents (LangChain, CrewAI, AutoGen) call tools autonomously. There's no security layer between the agent and your infrastructure. MCPKernel is an open-source MCP/A2A security gateway that enforces policy on every tool call at runtime.

Key features:
- YAML policy engine with OWASP ASI 2026 mappings
- Cross-tool taint tracking (if Agent A returns PII, Agent B can't send it outbound)
- 4 sandbox backends (Docker, Firecracker, WASM, Microsandbox)
- Deterministic Execution Envelopes — every call is hashed and Sigstore-signed
- Langfuse + Guardrails AI integration

Paper-relevant: the DEE system ensures full experimental reproducibility — every tool call can be replayed and verified cryptographically.

GitHub: https://github.com/piyushptiwari1/mcpkernel

---

### r/LocalLLaMA

**Title**: Securing your local AI agent stack — MCPKernel blocks prompt injection at the tool call level

If you're running local agents that call tools (file read/write, code execution, HTTP requests), a single prompt injection can exfiltrate your data through a tool call.

MCPKernel sits between your agent and MCP tool servers, checking every call against YAML policies. It detects secrets and PII in arguments, sandboxes code execution, and creates tamper-proof audit logs.

```bash
pip install mcpkernel
mcpkernel serve
```

It's free, self-hosted, Apache 2.0. No cloud dependencies. Runs locally, adds minimal latency.

https://github.com/piyushptiwari1/mcpkernel

---

### r/cybersecurity

**Title**: MCPKernel — Runtime security gateway for AI agent tool calls (OWASP ASI 2026 compliant)

AI agents autonomously call tools via MCP (Model Context Protocol). Without a runtime security layer, prompt injection = data exfiltration.

MCPKernel is an open-source security gateway that intercepts every MCP/A2A tool call with:
- YAML policy engine (OWASP ASI 2026 mappings, ASI-01 through ASI-08)
- Taint tracking (secrets, PII, user input propagation across tool boundaries)
- Sandbox execution (Docker, Firecracker, WASM)
- Deterministic envelopes (hashed, Sigstore-signed, replayable)
- Tamper-proof audit logs (CEF/JSONL/CSV SIEM export)
- Optional eBPF syscall monitoring

No existing tool provides this full runtime stack. Static scanners and config auditors are complementary — they run in CI, MCPKernel runs in prod.

Apache 2.0, Python 3.12+, 695 tests.

https://github.com/piyushptiwari1/mcpkernel

---

### r/artificial

**Title**: How do you secure AI agents that call tools? Built an open-source security gateway.

AI agents call tools autonomously — reading files, executing code, making HTTP requests. If a prompt injection tricks the agent, your infrastructure is exposed.

I built MCPKernel, an open-source security gateway that enforces policies on every AI agent tool call. It detects secrets/PII in arguments, sandboxes execution, creates Sigstore-signed audit trails, and blocks tainted data from leaking across tool boundaries.

Works with LangChain, CrewAI, AutoGen, Copilot, and any MCP-compatible tool server.

https://github.com/piyushptiwari1/mcpkernel

Would love to hear how others are handling agent security.

---

### Hacker News (Show HN)

**Title**: Show HN: MCPKernel – Open-source security gateway for AI agent tool calls

**Text**:
MCPKernel is a transparent MCP/A2A proxy that sits between AI agents and tool servers, enforcing security policies on every call.

What it does: policy check → taint scan → sandbox → hash + Sigstore sign → audit log.

Why: AI agents call tools autonomously. One prompt injection = exfiltrated secrets. There's no iptables/nginx equivalent for agent tool calls. MCPKernel fills that gap.

Features: YAML policy engine (OWASP ASI 2026), cross-tool taint tracking, 4 sandbox backends (Docker/Firecracker/WASM/Microsandbox), deterministic execution envelopes, tamper-proof audit, eBPF syscall monitoring.

695 tests, ~86% coverage, async Python 3.12+, Apache 2.0.

https://github.com/piyushptiwari1/mcpkernel

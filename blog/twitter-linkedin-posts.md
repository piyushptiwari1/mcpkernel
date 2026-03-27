## Twitter/X Thread for MCPKernel Launch

---

**Tweet 1 (Hook)**:
AI agents call tools autonomously — reading files, executing code, making HTTP requests.

One prompt injection = your secrets exfiltrated through a tool call.

I built an open-source security kernel to fix this. 🧵

---

**Tweet 2 (What)**:
MCPKernel is a transparent gateway that sits between your AI agent and MCP tool servers.

Every tool call passes through:
✅ Policy check (OWASP ASI 2026)
✅ Taint scan (secrets, PII, API keys)
✅ Sandbox (Docker/Firecracker/WASM)
✅ Sigstore-signed audit trail

---

**Tweet 3 (Install)**:
Get started in 30 seconds:

pip install "mcpkernel[all]"
mcpkernel serve

Point your LangChain/CrewAI/AutoGen/Copilot to http://localhost:8000/mcp

Every call is now secured. Zero code changes to your agent.

---

**Tweet 4 (Taint Tracking)**:
The killer feature: cross-tool taint tracking.

If Agent A's database query returns SSNs, Agent B's HTTP POST is automatically BLOCKED from sending them.

Taint labels (secrets, PII, user_input) propagate across tool boundaries.

---

**Tweet 5 (Stack)**:
The full stack:
- YAML policy engine
- 4 sandbox backends
- Deterministic execution envelopes
- Tamper-proof audit logs
- eBPF syscall monitoring
- Langfuse + Guardrails AI integration
- Snyk agent-scan bridge

695 tests | ~86% coverage | Python 3.12+ | Apache 2.0

---

**Tweet 6 (CTA)**:
GitHub: github.com/piyushptiwari1/mcpkernel
PyPI: pip install mcpkernel

Star it if it's useful. PRs welcome — especially for policy templates, sandbox backends, and framework examples.

The era of unsecured agent tool calls is over. 🔒

---

## LinkedIn Post

---

**Announcing MCPKernel — The Security Kernel for AI Agents**

AI agents are calling tools autonomously. LangChain reads files. CrewAI executes code. AutoGen makes HTTP requests. Copilot modifies your codebase.

And there is no security layer between the agent and your infrastructure.

One prompt injection — one manipulated tool call — and your secrets, customer data, or production systems are compromised.

I built MCPKernel to solve this.

MCPKernel is an open-source MCP/A2A security gateway. It sits transparently between your AI agent and MCP tool servers. Every single tool call passes through a five-stage security pipeline:

1️⃣ Policy Check — YAML rules with OWASP ASI 2026 mappings
2️⃣ Taint Scan — Detects secrets, PII, API keys in arguments
3️⃣ Sandbox Execution — Docker, Firecracker, WASM isolation
4️⃣ Deterministic Envelope — Hashes and Sigstore-signs every execution
5️⃣ Audit Log — Tamper-proof, append-only, SIEM-exportable

Key differentiator: cross-tool taint tracking. If one agent's tool call returns credit card numbers, another agent's outbound HTTP request is automatically blocked from sending them. Taint labels propagate across tool boundaries.

For enterprises: built-in OWASP ASI 2026 compliance (ASI-01 through ASI-08), FINRA/SEC/Federal Reserve agent manifest support, and tamper-proof audit trails with integrity verification.

The project has 695 tests at ~86% coverage, is fully async Python 3.12+, and is Apache 2.0 licensed.

No existing project provides this full runtime stack — policy engine + taint tracking + sandboxing + deterministic envelopes + Sigstore audit + eBPF, all in one self-hosted gateway.

🔗 GitHub: https://github.com/piyushptiwari1/mcpkernel
📦 PyPI: pip install mcpkernel

Looking for feedback, contributors, and early adopters. If you're building with AI agents, I'd love to hear your security challenges.

#AIAgents #Security #OpenSource #Python #MCP #LLMSecurity #OWASP #AIGovernance

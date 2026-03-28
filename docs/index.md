# MCPKernel — The Security Kernel for AI Agents

**Open-source MCP/A2A security gateway that stops tool poisoning, data exfiltration, prompt injection, and rug-pull attacks.**

MCPKernel sits between your AI agent (Claude Desktop, Cursor, VS Code, Windsurf) and MCP tool servers. Every tool call flows through a security pipeline: policy check → taint scan → sandbox → audit log → deterministic envelope.

[:material-github: GitHub](https://github.com/piyushptiwari1/mcpkernel){ .md-button } [:material-package: PyPI](https://pypi.org/project/mcpkernel/){ .md-button .md-button--primary }

---

## What Problems Does MCPKernel Solve?

| Problem | What Happens | MCPKernel Defense |
|---------|-------------|-------------------|
| **Tool Poisoning** | A malicious MCP server injects instructions into tool descriptions | Policy engine blocks + skill scanner detects |
| **Data Exfiltration** | Agent leaks your API keys, PII, or secrets through tool calls | Taint tracking detects and blocks secrets/PII |
| **Prompt Injection** | Tool output tricks the agent into running unauthorized actions | Memory poisoning guard + taint labels |
| **Confused Deputy** | One tool tricks the proxy into calling another with elevated privileges | Cross-server delegation checks |
| **SSRF** | Tool arguments contain URLs targeting internal networks | SSRF guard + domain allowlists |
| **Session Hijacking** | Session tokens stolen or replayed | HMAC-bound sessions with expiry |

---

## Quick Start

### Option A: Security Gateway (proxy mode)

```bash
pip install "mcpkernel[all]"
mcpkernel serve --host 127.0.0.1 --port 8000
```

Point your MCP client to `http://localhost:8000/mcp`. Every tool call is now secured.

### Option B: MCP Server (tool mode)

```bash
pip install mcpkernel
mcpkernel install claude    # or: cursor, vscode, windsurf
```

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

---

## Architecture Overview

```
┌──────────────────────────────────────────────────┐
│  MCP Client (Claude Desktop, Cursor, VS Code)    │
└─────────────────────┬────────────────────────────┘
                      │ MCP protocol (HTTP/SSE/stdio)
                      ▼
┌──────────────────────────────────────────────────┐
│                  MCPKernel Proxy                  │
│                                                  │
│  ┌────────┐ ┌──────┐ ┌───────┐ ┌─────┐ ┌─────┐ │
│  │ Policy │→│Taint │→│Sandbox│→│ DEE │→│Audit│ │
│  │ Engine │ │Track │ │(Docker│ │Trace│ │ Log │ │
│  └────────┘ └──────┘ │ WASM) │ └─────┘ └─────┘ │
│                      └───────┘                   │
│  ┌─────────────────────┐  ┌───────────────────┐  │
│  │  Trust Framework    │  │  Security Guards  │  │
│  │  (CTG + Decay +     │  │  (Deputy, Token,  │  │
│  │   Behavioral)       │  │   SSRF, Session,  │  │
│  └─────────────────────┘  │   Memory Poison)  │  │
│                           └───────────────────┘  │
└─────────────────────┬────────────────────────────┘
                      │
                      ▼
┌──────────────────────────────────────────────────┐
│  Upstream MCP Servers (filesystem, github, etc.) │
└──────────────────────────────────────────────────┘
```

---

## Key Features

- **Policy Engine** — YAML rules with OWASP ASI 2026 mappings, presets (permissive/standard/strict)
- **Taint Tracking** — Labels data as `secret`, `pii`, `user_input`, `llm_output` and blocks leakage
- **Sandbox Execution** — Docker, Firecracker, WASM, Microsandbox backends
- **Deterministic Envelopes (DEE)** — Hash + Sigstore-sign every execution for replay
- **Causal Trust Graph** — Novel trust framework with exponential decay and retroactive invalidation
- **Security Guards** — Defenses against confused deputy, token passthrough, SSRF, session hijacking, memory poisoning
- **Compliance Presets** — One-line HIPAA, SOC 2, PCI DSS, GDPR, FedRAMP activation
- **22+ CLI Commands** — `serve`, `init`, `scan`, `doctor`, `discover`, and more

---

## Next Steps

<div class="grid cards" markdown>

-   :material-download:{ .lg .middle } **Installation**

    ---

    Install MCPKernel and set up your first project

    [:octicons-arrow-right-24: Getting Started](getting-started/installation.md)

-   :material-shield-lock:{ .lg .middle } **Policy Engine**

    ---

    Write YAML rules to control what tools can do

    [:octicons-arrow-right-24: Policy Engine](core/policy-engine.md)

-   :material-graph:{ .lg .middle } **Causal Trust Graph**

    ---

    Novel trust framework with decay and retroactive invalidation

    [:octicons-arrow-right-24: Trust Framework](trust/causal-trust-graph.md)

-   :material-security:{ .lg .middle } **Security Protections**

    ---

    Defenses against the 6 named MCP attacks

    [:octicons-arrow-right-24: Security Guards](security/overview.md)

</div>

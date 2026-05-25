# OWASP LLM Top-10 (2025) — MCPKernel Mapping

This document maps each item in the
[OWASP Top 10 for Large Language Model Applications (2025)](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
to the concrete MCPKernel control(s) that mitigate it.

MCPKernel is positioned **between** the agent host (Copilot, Cursor,
Claude Desktop, LangGraph, etc.) and the downstream MCP servers, so most
controls are enforced at the proxy boundary without touching agent code.

| Code   | Risk                                | Status | Primary controls |
| ------ | ----------------------------------- | ------ | ---------------- |
| LLM01  | Prompt Injection                    | ✅ Full | Taint tracker, policy `block_on_taint`, trust-decay |
| LLM02  | Sensitive Information Disclosure    | ✅ Full | Secret/PII detectors, sink-blocking, audit redaction |
| LLM03  | Supply Chain                        | ✅ Full | CycloneDX SBOM, `uv.lock`, Sigstore-signed DEEs |
| LLM04  | Data & Model Poisoning              | 🟡 Partial | Context drift detection, retroactive taint |
| LLM05  | Improper Output Handling            | ✅ Full | Post-execution taint scan, structured-content redaction |
| LLM06  | Excessive Agency                    | ✅ Full | Per-tool allow-list, sandbox backends, agent.yaml validator |
| LLM07  | System Prompt Leakage               | ✅ Full | Taint label `SYSTEM_PROMPT`, exfil sinks, audit |
| LLM08  | Vector & Embedding Weaknesses       | 🟡 Partial | Policy hooks for retrieval tools (RAG-aware rules) |
| LLM09  | Misinformation                      | ⚪ Out of scope | (model-side) |
| LLM10  | Unbounded Consumption               | ✅ Full | Rate-limit, RU budgets, sandbox CPU/RAM caps |

Legend: **✅ Full** — enforced by default. **🟡 Partial** — primitives
present, opt-in policy required. **⚪ Out of scope** — model-layer
concern; MCPKernel cannot mitigate at the protocol boundary.

---

## LLM01 — Prompt Injection

**Threat.** Malicious instructions arrive via tool output, retrieved
documents, or user input and override the agent's system prompt.

**MCPKernel controls.**

- `mcpkernel.taint.TaintTracker` labels every string flowing into the
  agent with its provenance (`USER_INPUT`, `TOOL_RESULT`,
  `EXTERNAL_DOC`, `SYSTEM_PROMPT`).
- `TaintHook.post_execution` (since v0.2 advances) scans **both**
  `content` and `structuredContent` returned by upstream tools so the
  agent never sees laundered taint.
- Elicitation responses are auto-tainted as `USER_INPUT`.
- Policy rule `block_on_taint: [USER_INPUT]` on sensitive sinks (shell,
  file-system, network egress) breaks the inject → exec chain.
- Trust-decay model in `docs/trust/` reduces a tool's effective trust
  after suspicious payloads, fail-closed for high-impact actions.

**Policy snippet.**

```yaml
rules:
  - id: block_user_input_to_shell
    when:
      tool: { matches: "shell.*|run_command" }
      taint: { contains: [USER_INPUT] }
    action: deny
    owasp:
      - LLM01
```

## LLM02 — Sensitive Information Disclosure

**Threat.** API keys, PII, or internal secrets leak through tool calls
or responses.

**MCPKernel controls.**

- `mcpkernel.taint.sources` ships detectors for OpenAI/Anthropic/AWS
  keys, JWTs, private SSH keys, emails, SSNs, credit cards.
- `taint.sinks` flags outbound HTTP, file writes outside `/tmp`,
  clipboard, and Slack/Teams tool families as sensitive sinks.
- Audit log fields are redacted by default (`AuditLogger.redact=True`).
- Policy `deny_on_taint: [SECRET, PII]` against any external sink.

## LLM03 — Supply Chain

**Threat.** Compromised dependency, model weight, or MCP server.

**MCPKernel controls.**

- **CycloneDX 1.6 SBOM** attached to every tagged release
  (`release.yml`, Section E).
- **`uv.lock`** committed — 131 transitive packages pinned with hashes;
  `uv sync --frozen` is used in CI.
- **Sigstore-signed DEEs** — every replayable trace carries a
  `bundle.v0.3` attestation, optionally with in-toto DSSE
  audit-batch statements (`mcpkernel.audit.attest_audit_batch`).
- **CodeQL** + `pip-audit` + `dependency-review-action` gate every PR
  and weekly schedule.

## LLM04 — Data & Model Poisoning

**Threat.** Long-running agent has its memory or retrieved corpus
poisoned over many sessions.

**MCPKernel controls.**

- `mcpkernel.dee.drift` detects environment drift between recorded and
  replayed executions.
- Retroactive taint (`docs/trust/retroactive.md`) re-labels prior
  records when a source is later marked compromised.
- *Gap:* corpus-level integrity scanning is delegated to the host's
  vector store; MCPKernel exposes hook points but no built-in
  detector. Tracked for v0.4.

## LLM05 — Improper Output Handling

**Threat.** Unescaped tool output passed downstream (HTML/SQL/shell).

**MCPKernel controls.**

- `TaintHook.post_execution` scans tool results before the host sees
  them and attaches labels for downstream policies.
- `transform.py` provides redaction and structured-content rewriters
  invoked by hooks.
- Policies can require `escape=true` on specific
  tool→destination edges.

## LLM06 — Excessive Agency

**Threat.** Agent has unnecessary tool, network, or filesystem
permissions.

**MCPKernel controls.**

- Agent manifest (`agent.yaml`) enumerates exactly the tools an agent
  may call; the proxy denies anything outside the list (`tool_validator`).
- Sandbox backends (Docker, Firecracker, WASM, Microsandbox) execute
  tools with the minimum required syscalls; eBPF probe (Linux) filters
  at the kernel boundary.
- HelM chart ships with `runAsNonRoot`, `readOnlyRootFilesystem`,
  `capabilities.drop: [ALL]`, `seccomp: RuntimeDefault` (Section D).

## LLM07 — System Prompt Leakage

**Threat.** A tool answer or error message exposes the agent's hidden
system prompt or developer instructions.

**MCPKernel controls.**

- `SYSTEM_PROMPT` is a first-class taint label.
- Built-in rule set `policies/owasp_asi_2026_strict.yaml` includes
  `deny_on_taint: [SYSTEM_PROMPT]` against every network egress sink.
- Audit log captures the original prompt + redaction marker.

## LLM08 — Vector & Embedding Weaknesses

**Threat.** Adversarial documents in a RAG store, embedding inversion,
cross-tenant leakage in shared indexes.

**MCPKernel controls.**

- Policy hooks fire on retrieval-style tool names (`*.search`,
  `*.query`, `rag.*`) — operators can enforce tenant scoping and result
  taint propagation.
- *Gap:* embedding-similarity outlier detection is not built in.
  Recommended pattern documented in `docs/security/attack-defenses.md`.

## LLM09 — Misinformation

Out of scope. MCPKernel does not inspect model outputs for factual
correctness. Recommend pairing with an evaluation harness
(promptfoo, DeepEval, etc.).

## LLM10 — Unbounded Consumption

**Threat.** Token-flooding, denial-of-wallet, infinite tool loops.

**MCPKernel controls.**

- `mcpkernel.proxy.rate_limit` — per-agent, per-tool, per-tenant token
  buckets with Prometheus `mcpkernel_rate_limit_hits_total` counter.
- Sandbox CPU and memory limits enforced by every backend.
- DEE replay budgets cap re-execution storms.

---

## Cross-reference

| Policy preset | LLM coverage |
| --- | --- |
| `policies/minimal.yaml` | LLM01, LLM02 (basic) |
| `policies/owasp_asi_2026_strict.yaml` | LLM01, LLM02, LLM05, LLM06, LLM07, LLM10 |
| `policies/custom_template.yaml` | template — adapt for LLM03, LLM04, LLM08 |

For the OWASP **Agentic Security Initiative (ASI) 2026** mapping see
`docs/compliance/presets.md`.

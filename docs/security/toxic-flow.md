# Toxic Flow Analysis — the "Lethal Trifecta"

MCPKernel ships a static analyzer (`mcpkernel.taint.ToxicFlowAnalyzer`)
that scans an MCP tool manifest for the **lethal trifecta** — the
combination of capabilities Simon Willison coined to describe agents that
are one prompt-injection away from data exfiltration:

| # | Category          | Examples                                                |
|---|-------------------|---------------------------------------------------------|
| 1 | Untrusted input   | `web_search`, `fetch_url`, `read_email`, MCP resources  |
| 2 | Sensitive data    | secrets, env vars, vaults, PII, internal APIs, DBs      |
| 3 | Exfil sink        | `http_post`, `send_email`, `slack_post`, webhooks       |

When a single agent has access to a tool from each category, a prompt
injection in (1) can coerce the model into reading (2) and transmitting
it via (3) — **with no human in the loop**.

The analyzer enumerates every (untrusted, sensitive, sink) triple
*before runtime* and emits findings in SARIF 2.1.0, ready for GitHub
code-scanning, Microsoft Defender for Cloud, or Snyk.

## Quick start

```python
from mcpkernel.taint import analyze_tool_manifest

findings = analyze_tool_manifest(
    [
        {"name": "web_search",  "description": "Search the web"},
        {"name": "read_secret", "description": "Read API key from vault"},
        {"name": "http_post",   "description": "POST JSON to an arbitrary URL"},
    ]
)
for f in findings:
    print(f.severity, f.description)
```

## Output formats

* **Python objects** — `FlowFinding` dataclasses (sortable by severity).
* **SARIF 2.1.0** — `analyzer.to_sarif(findings)` → ingestible by GitHub
  Advanced Security, Defender for Cloud, Snyk Code, SonarQube.
* **Markdown summary** — `analyzer.summary(findings)` for PR review
  comments.

## Severity model

| Severity | Trigger                                                          |
|----------|------------------------------------------------------------------|
| CRITICAL | A single tool plays all three roles (no model mediation needed) |
| HIGH     | Three high-confidence (≥ 0.9) distinct tools form the trifecta  |
| MEDIUM   | Confidence ≥ 0.5                                                 |
| LOW      | Below 0.5 — flagged but unlikely to be exploitable               |

## Remediation

When a trifecta is detected, you have three options — pick the one that
preserves the most utility:

1. **Remove a leg.** Split the offending tool out of this agent's manifest.
2. **Isolate.** Move the sensitive-data tool to a separate, sandboxed agent
   that does not have an exfil sink.
3. **Mediate at runtime.** Configure a MCPKernel `TaintHook` that denies
   tainted data from reaching the sink tool. This is the option taken by
   the bundled `policies/owasp_llm_top10_2025.yaml` preset (rule LLM02-001).

## References

* Simon Willison — [The lethal trifecta for AI agents](https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/)
* Invariant Labs — [Toxic Flow Analysis](https://invariantlabs.ai/blog/toxic-flow-analysis)
* OWASP — [LLM02: Sensitive Information Disclosure](https://genai.owasp.org/llmrisk/llm02-sensitive-information-disclosure/)

# MCPGuard — Project Kanban

> Last updated: 2026-03-21

---

## Blocked / Pending

| ID | Task | Blocker | ETA | Notes |
|----|------|---------|-----|-------|
| K-001 | **Publish to PyPI** as `mcpguard-gateway` | Email not working — cannot confirm PyPI account | 5–20 days from 2026-03-21 | Publish name: `mcpguard-gateway` (import name stays `mcpguard`). The PyPI name `mcpguard` is taken by `aryanjp1/mcpguard` (config scanner, 0 stars). Consider PEP 541 claim later. |
| K-002 | **List on libraries.io** | Blocked by K-001 — auto-indexes from PyPI | After K-001 | libraries.io automatically picks up packages once published on PyPI. No manual action needed. |
| K-003 | **List on piwheels** | Blocked by K-001 — auto-builds from PyPI for Raspberry Pi | After K-001 | piwheels.org builds ARM wheels automatically from PyPI. Ensure pure-Python or add ARM build matrix. |
| K-004 | **Set GitHub repo About & Topics** | `gh` CLI not authenticated on this machine | User action | See instructions below. |

### K-004 Instructions — GitHub About & Topics

Run once after authenticating with `gh auth login`:

```bash
# Authenticate (one-time)
gh auth login

# Set repository description
gh repo edit piyushptiwari1/mcpguard \
  --description "Open-source MCP/A2A security gateway — policy enforcement, taint tracking, sandboxed execution, deterministic envelopes, and Sigstore audit for every AI agent tool call. OWASP ASI 2026 compliant."

# Set topics (hashtags)
gh repo edit piyushptiwari1/mcpguard \
  --add-topic mcp \
  --add-topic a2a \
  --add-topic ai-security \
  --add-topic agent-security \
  --add-topic owasp \
  --add-topic sandbox \
  --add-topic taint-tracking \
  --add-topic policy-engine \
  --add-topic deterministic-execution \
  --add-topic sigstore \
  --add-topic mcp-gateway \
  --add-topic ai-agent \
  --add-topic model-context-protocol \
  --add-topic llm-security \
  --add-topic genai-security \
  --add-topic agent-sovereignty
```

---

## In Progress

| ID | Task | Owner | Notes |
|----|------|-------|-------|
| — | (nothing currently in progress) | | |

---

## Done (recent)

| ID | Task | Date | Notes |
|----|------|------|-------|
| D-001 | CI mypy fix | 2026-03-21 | Fixed `docker_backend.py` unused-ignore error. Commit `a44506c`. |
| D-002 | 54 integration tests | 2026-03-21 | Full e2e tests for dev/prod configs. Coverage 81.83% → 86.16%. Commit `689c7a5`. |
| D-003 | Planned roadmap in README | 2026-03-21 | ZK tooling, robotic safety, red-teaming, parallel taint, context cost. Commit `4e429a1`. |
| D-004 | Competitive landscape in README | 2026-03-21 | Analyzed 5 competing projects, added comparison table + PyPI naming strategy. |
| D-005 | Kanban created | 2026-03-21 | This file. |

---

## Backlog

| ID | Task | Priority | Notes |
|----|------|----------|-------|
| B-001 | PEP 541 claim for `mcpguard` PyPI name | Low | Only if `mcpguard-gateway` gains traction and rename is desired. |
| B-002 | Parallel taint analysis (< 50 ms) | High | Roadmap item #4. |
| B-003 | Context minimization productization | Medium | Roadmap item #5 — cost weapon. |
| B-004 | ZK-Policy module prototype | Low | Roadmap item #1. |
| B-005 | Physics-aware sandbox (Robotic MCP) | Low | Roadmap item #2. |
| B-006 | Automated red-teaming module | Medium | Roadmap item #3. |
| B-007 | GitHub Actions badge for coverage | Medium | Add codecov or coveralls integration. |
| B-008 | Docker Hub / GHCR publish | Medium | Publish container images after PyPI. |

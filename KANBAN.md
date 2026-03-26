# MCPKernel — Project Kanban

> Last updated: 2026-03-23

---

## Blocked / Pending

| ID | Task | Blocker | ETA | Notes |
|----|------|---------|-----|-------|
| K-002 | **List on libraries.io** | Auto-indexes from PyPI (may take 24-48h) | Auto | libraries.io automatically picks up packages once published on PyPI. No manual action needed. |
| K-003 | **List on piwheels** | Auto-builds from PyPI for Raspberry Pi | Auto | piwheels.org builds ARM wheels automatically from PyPI. Pure-Python wheel — should work on all platforms. |
| K-004 | **Set GitHub repo About & Topics** | `gh` CLI not authenticated on this machine | User action | See instructions below. |

### K-004 Instructions — GitHub About & Topics

Run once after authenticating with `gh auth login`:

```bash
# Authenticate (one-time)
gh auth login

# Set repository description
gh repo edit piyushptiwari1/mcpkernel \
  --description "The security kernel for AI agents — policy enforcement, taint tracking, sandboxed execution, deterministic envelopes, and Sigstore audit for every MCP/A2A tool call. OWASP ASI 2026 compliant."

# Set topics (hashtags)
gh repo edit piyushptiwari1/mcpkernel \
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
  --add-topic agent-sovereignty \
  --add-topic mcp-security \
  --add-topic agent-gateway
```

---

## 1-Week Milestones (Sprint: 2026-03-21 → 2026-03-28)

| # | Task | Priority | Status | Notes |
|---|------|----------|--------|-------|
| M-1 | ~~Confirm email + publish `mcpkernel` v0.1.0 to PyPI~~ | **P0** | **Done** ✅ | Published 2026-03-23. https://pypi.org/project/mcpkernel/0.1.0/ |
| M-2 | ~~Add CI badges (PyPI version, coverage, tests) to README~~ | P1 | **Done** ✅ | PyPI, tests (666), coverage (81%), downloads badges added 2026-03-26. |
| M-3 | Record 5-minute YouTube demo | P1 | Not started | "The security kernel for AI agents." |
| M-4 | Post to Reddit r/MachineLearning, r/LocalLLaMA | P1 | After M-1 | "Stop your code from leaking into any LLM — one command." |
| M-5 | Post to Hacker News (Show HN) | P1 | After M-1 | Focus on the simple protect command + sovereignty gateway. |
| M-6 | Create GitHub Release v0.1.2 with changelog | P1 | Not started | Use `gh release create v0.1.2`. Needs `gh auth login`. |
| M-7 | Harden eBPF/Firecracker backend stubs | P2 | Not started | Ensure graceful fallback when deps missing. |

---

## In Progress

| ID | Task | Owner | Notes |
|----|------|-------|-------|
| K-002 | libraries.io auto-indexing | Auto | Waiting for PyPI crawl (24-48h) |
| K-003 | piwheels auto-build | Auto | Waiting for PyPI crawl |

---

## Done (recent)

| ID | Task | Date | Notes |
|----|------|------|-------|
| D-012 | **Badges added to README** | 2026-03-26 | PyPI version, tests (666), coverage (81%), downloads badges. |
| D-011 | **Merged feature/python-api-and-preset-fixes → main** | 2026-03-26 | 16 files changed, +2449/−351 lines. Full pipeline pass (666 tests). |
| D-010 | **Python API + presets + 11 bug fixes** | 2026-03-26 | MCPKernelProxy, protect() decorator, built-in presets, quickstart/status/presets CLI. 3 CRITICAL + 3 HIGH bugs fixed. |
| D-009b | **Published v0.1.2 to PyPI** | 2026-03-25 | `mcpkernel` v0.1.2 — https://pypi.org/project/mcpkernel/0.1.2/ |
| D-007 | **Published to PyPI** | 2026-03-23 | `mcpkernel` v0.1.0 — https://pypi.org/project/mcpkernel/0.1.0/ |
| D-008 | Agent manifest module | 2026-03-23 | 5 source files, 98 new tests (443 total), 89.38% coverage. Full 16-agent pipeline pass. |
| D-006 | Rename to MCPKernel | 2026-03-22 | Full codebase rename mcpguard → mcpseal → mcpkernel. |
| D-009 | 1-week milestones added to kanban | 2026-03-21 | PyPI, badges, YouTube, Reddit, HN posting plan. |
| D-001 | CI mypy fix | 2026-03-21 | Fixed `docker_backend.py` unused-ignore error. Commit `a44506c`. |
| D-002 | 54 integration tests | 2026-03-21 | Full e2e tests for dev/prod configs. Coverage 81.83% → 86.16%. Commit `689c7a5`. |
| D-003 | Planned roadmap in README | 2026-03-21 | ZK tooling, robotic safety, red-teaming, parallel taint, context cost. Commit `4e429a1`. |
| D-004 | Competitive landscape in README | 2026-03-21 | Analyzed 5 competing projects, added comparison table + PyPI naming strategy. |
| D-005 | Kanban created | 2026-03-21 | This file. |

---

## Backlog

| ID | Task | Priority | Notes |
|----|------|----------|-------|
| B-001 | PEP 541 claim for `mcpkernel` PyPI name | Low | Only if `mcpkernel` gains traction and rename is desired. |
| B-002 | Parallel taint analysis (< 50 ms) | High | Roadmap item #4. |
| B-003 | Context minimization productization | Medium | Roadmap item #5 — cost weapon. |
| B-004 | ZK-Policy module prototype | Low | Roadmap item #1. |
| B-005 | Physics-aware sandbox (Robotic MCP) | Low | Roadmap item #2. |
| B-006 | Automated red-teaming module | Medium | Roadmap item #3. |
| B-007 | GitHub Actions badge for coverage | Medium | Add codecov or coveralls integration. |
| B-008 | Docker Hub / GHCR publish | Medium | Publish container images after PyPI. |

| B-010 | Kubernetes operator for mcpkernel | Low | Enterprise deployment: CRD-based policy injection. |
| B-011 | Paid dashboard (SaaS) | Low | Enterprise: centralized policy + audit + multi-tenant. |
| B-012 | Public website + docs (mcpkernel.dev) | Medium | Landing page, docs, demo. |
| B-013 | **Advanced community agent — multi-platform content** | High | See story below. |

---

## Story: B-013 — Advanced Community Agent (Multi-Platform Content)

**As** a project maintainer,
**I want** the contributor-booster agent to generate platform-specific content for LinkedIn, X/Twitter, and blog platforms,
**So that** MCPKernel gets maximum visibility, reach, and community engagement across all channels.

### Acceptance Criteria

1. **LinkedIn posts** — Professional, long-form posts (1300 char max) targeting:
   - Enterprise security engineers, CISOs, compliance officers
   - AI/ML platform teams evaluating agent security
   - Tone: authoritative, insight-driven, hashtags like `#AISecurity #OWASP #AgentSovereignty`
   - Include a clear CTA (try it, star the repo, contribute)

2. **X/Twitter threads** — Punchy, high-engagement threads (280 char/tweet, 5-8 tweets):
   - Hook tweet with a bold claim or surprising stat
   - Thread format: problem → solution → demo/proof → CTA
   - Target: AI developers, security researchers, open-source community
   - Use tags: `#MCP #AIAgents #OpenSource #GenAISecurity`

3. **Blog posts** — Long-form technical articles for:
   - **Dev.to / Hashnode** — developer tutorials ("How to secure your LangChain agent in 5 minutes")
   - **Medium** — thought leadership ("Why every AI agent needs a security kernel")
   - **Company/personal blog** — deep dives on architecture, benchmarks, compliance
   - Each post should include: code snippets, architecture diagrams (Mermaid), and a call to contribute

4. **Content calendar** — Agent should produce a 4-week rolling content plan:
   | Week | LinkedIn | X/Twitter | Blog |
   |------|----------|-----------|------|
   | 1 | Launch announcement | Thread: "Your AI agent calls tools. Who's watching?" | Dev.to: "Secure your MCP agents in 5 min" |
   | 2 | Use case: regulated industries | Thread: "FINRA compliance for AI agents" | Medium: "Why AI agents need a security kernel" |
   | 3 | Contributor spotlight / welcome | Thread: "We just hit X stars — here's what's next" | Hashnode: "Building taint tracking for AI agents" |
   | 4 | Comparison: MCPKernel vs alternatives | Thread: "Sandboxing AI tool calls: Docker vs WASM vs Firecracker" | Deep dive: "DEE — deterministic execution envelopes" |

5. **Platform-specific formatting**:
   - LinkedIn: paragraph breaks, bullet points, emojis sparingly, professional tone
   - X/Twitter: numbered thread format (1/N), punchy language, memes/visuals welcome
   - Blogs: H2/H3 headers, code blocks, TL;DR at top, "Getting Started" section at bottom

6. **Collaboration hooks** — every post must include at least one of:
   - Link to `good-first-issue` labels
   - "Contributors welcome" callout
   - "Star the repo" CTA
   - Mention of the Apache 2.0 license

### Technical Notes
- Extend `contributor-booster` agent definition in `.github/agents/`
- Agent should accept a `--platform` flag: `linkedin`, `twitter`, `blog-devto`, `blog-medium`, `blog-hashnode`
- Agent should accept `--topic` to generate content around a specific feature or announcement
- Output should be ready-to-post (no manual formatting needed)
- Consider adding a `--schedule` mode that outputs the full 4-week content calendar


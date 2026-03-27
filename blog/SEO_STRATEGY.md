# MCPKernel SEO & Discoverability Strategy

## What's Already Done ✅

### GitHub Repository
- [x] **Description set**: "The Security Kernel for AI Agents — MCP/A2A gateway with policy enforcement, taint tracking, sandboxed execution, deterministic envelopes, and Sigstore audit. OWASP ASI 2026 compliant."
- [x] **Homepage URL**: https://pypi.org/project/mcpkernel/
- [x] **20 Topics added**: mcp, mcp-security, ai-security, agent-security, llm-security, model-context-protocol, taint-tracking, sandbox, policy-engine, owasp, a2a, ai-agent, genai, deterministic-execution, sigstore, python, security-gateway, mcp-gateway, prompt-injection, audit-logging
- [x] **GitHub Release v0.1.3** created with release notes + dist artifacts
- [x] **README badges**: CI, PyPI version, tests, coverage, license, Python, downloads

### PyPI
- [x] **Published** (currently showing v0.1.2 — v0.1.3 needs API token to upload)
- [x] **Keywords in pyproject.toml**: 17 keywords covering MCP, security, AI, agents
- [x] **Classifiers**: Development Status, Audience, License, OS, Python versions, Security topic
- [x] **Project URLs**: Homepage, Documentation, Repository, Issues, Changelog

---

## Action Items — Immediate (Do Now)

### 1. Publish v0.1.3 to PyPI
- Need API token from https://pypi.org/manage/account/token/
- Run: `twine upload dist/*`

### 2. Submit to Awesome Lists
Submit PRs to these curated lists for backlinks and discoverability:

| List | URL | Why |
|------|-----|-----|
| awesome-mcp-servers | https://github.com/punkpeye/awesome-mcp-servers | Primary MCP ecosystem list |
| awesome-mcp | https://github.com/wong2/awesome-mcp-servers | Another major MCP list |
| awesome-ai-agents | https://github.com/e2b-dev/awesome-ai-agents | AI agent ecosystem |
| awesome-llm-security | https://github.com/corca-ai/awesome-llm-security | LLM security tools |
| awesome-python-security | https://github.com/guardrails-ai/awesome-python-security | Python security tools |
| awesome-python | https://github.com/vinta/awesome-python | General Python — Security section |

### 3. Post on Social Platforms
Ready-to-post content is in `blog/`:
- **Dev.to**: `blog/dev-to-announcement.md` → Post at https://dev.to/new
- **Medium**: `blog/medium-article.md` → Post at https://medium.com/new-story
- **Reddit**: `blog/reddit-hackernews-posts.md` → Post to r/Python, r/MachineLearning, r/cybersecurity, r/LocalLLaMA, r/artificial
- **Hacker News**: `blog/reddit-hackernews-posts.md` → Submit as Show HN
- **Twitter/X**: `blog/twitter-linkedin-posts.md` → Post as thread
- **LinkedIn**: `blog/twitter-linkedin-posts.md` → Post as article

### 4. GitHub Issues for Contributor Attraction
Create these labeled issues to attract contributors:

```bash
# Good first issues
gh issue create --title "Add healthcare-specific policy template" --label "good first issue,help wanted" --body "Create a YAML policy template in policies/ for healthcare (HIPAA) with PII/PHI rules."
gh issue create --title "Add OpenAI Agents SDK example" --label "good first issue,help wanted" --body "Create an example in examples/ showing MCPKernel integration with OpenAI Agents SDK."
gh issue create --title "Add Semantic Kernel example" --label "good first issue,help wanted" --body "Create an example in examples/ showing MCPKernel integration with Microsoft Semantic Kernel."
gh issue create --title "Improve inline code documentation" --label "good first issue,help wanted" --body "Add docstrings to public functions in src/mcpkernel/ modules."

# Feature requests
gh issue create --title "Add fintech-specific policy template (SOX, PCI-DSS)" --label "enhancement,help wanted" --body "Create YAML policy templates for financial compliance."
gh issue create --title "Kubernetes Helm chart" --label "enhancement,help wanted" --body "Create a Helm chart for deploying MCPKernel in Kubernetes clusters."
gh issue create --title "VS Code extension for policy editing" --label "enhancement" --body "Create VS Code extension with YAML schema validation for MCPKernel policy files."
```

---

## Action Items — Short Term (This Week)

### 5. Google Indexing
- **Google Search Console**: Add and verify the GitHub repo URL
  - Go to https://search.google.com/search-console
  - Add property: `https://github.com/piyushptiwari1/mcpkernel`
  - Request indexing for the README page
- **Sitemap**: GitHub repos are auto-indexed, but description + topics + README quality all feed into ranking
- The description, topics, and release we just added will significantly help

### 6. Create GitHub Discussions
Enable Discussions on the repo for community engagement:
```bash
gh repo edit piyushptiwari1/mcpkernel --enable-discussions
```
Create initial discussion posts:
- "Introduce yourself — what's your agent security challenge?"
- "RFC: Which sandbox backend should we prioritize next?"
- "Policy template requests — what industry/use case do you need?"

### 7. Cross-Linking
- Link from PyPI description to GitHub, blog posts, docs
- Link from blog posts back to GitHub and PyPI
- Add "Featured in" section to README as coverage grows

---

## Action Items — Medium Term (This Month)

### 8. Content Marketing
- **YouTube**: Create a 5-minute demo video showing MCPKernel blocking prompt injection
- **Blog series** on Dev.to/Medium:
  - "How AI Agents Leak Your Secrets (And How to Stop It)"
  - "OWASP ASI 2026: What It Means for AI Agent Security"
  - "Cross-Tool Taint Tracking: Preventing PII Leaks in Multi-Agent Systems"
  - "Deterministic Execution: Making AI Agent Calls Reproducible"

### 9. Community Engagement
- **Discord/Slack**: Join MCP community channels, answer questions, share the project
- **Stack Overflow**: Answer questions about MCP security, link to MCPKernel where relevant
- **GitHub Sponsors**: Set up to accept sponsorship for sustainability

### 10. Conference/Meetup Submissions
- Submit talks to Python conferences (PyCon, EuroPython)
- Submit to AI/security conferences (DEF CON AI Village, BSides)
- Present at local Python/AI meetups

---

## Why the Repo Wasn't Showing on Google

1. **No description** — Google uses the repo description as the meta description
2. **No topics** — Topics are indexed as keywords by Google
3. **No releases** — Releases generate additional indexed pages
4. **No website URL** — Missing homepage link reduces link authority
5. **Low backlinks** — No external sites linking to the repo

All of items 1-4 are now fixed. Item 5 requires the social/blog posting strategy above.

---

## SEO Keywords to Target

Primary: `mcp security`, `mcp gateway`, `ai agent security`, `model context protocol security`
Secondary: `llm security python`, `ai agent sandbox`, `mcp taint tracking`, `owasp asi 2026`
Long-tail: `how to secure ai agent tool calls`, `prevent prompt injection mcp`, `sandbox ai agent code execution`, `audit ai agent tool calls`

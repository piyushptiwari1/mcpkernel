---
name: search-and-fix
description: 'Multi-step workflow to discover issues in MCPGuard and similar repos, implement fixes, and validate with tests. Use when finding and fixing bugs, addressing security gaps, or implementing improvements discovered from issue analysis.'
---

# Search and Fix Workflow

## When to Use
- Finding and fixing bugs from GitHub issues
- Addressing security vulnerabilities discovered in similar projects
- Implementing improvements from issue analysis

## Procedure

### Step 1: Discover Issues
1. Use web search to find open issues in `piyushptiwari1/mcpguard`
2. Search similar MCP/security projects for resolved issues that may affect MCPGuard
3. Analyze the codebase with `search` for patterns matching known bugs

### Step 2: Triage and Plan
1. Prioritize findings: Critical > High > Medium > Low
2. For each issue, identify the affected files in `src/mcpguard/`
3. Create a brief implementation plan

### Step 3: Implement Fix
1. Read the target source files to understand current behavior
2. Write a failing test in `tests/` that reproduces the issue
3. Implement the minimal fix in `src/mcpguard/`
4. Run: `python -m pytest tests/ -v --tb=short`

### Step 4: Validate
1. Ensure all 106+ tests pass (including the new one)
2. Run `ruff check src/ tests/` for lint compliance
3. Document the change for the changelog

### Step 5: Report
Return a summary of what was found, fixed, and validated.

## References
- MCPGuard source: `src/mcpguard/`
- Tests: `tests/`
- Policies: `policies/`

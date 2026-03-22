---
name: research-and-improve
description: 'Multi-step workflow to research latest MCP security techniques, async Python patterns, sandboxing approaches, and implement improvements to MCPKernel. Use when upgrading architecture, adding new security features, or optimizing performance based on latest research.'
---

# Research and Improve Workflow

## When to Use
- Discovering and implementing latest security techniques
- Optimizing performance based on current best practices
- Upgrading protocol support (MCP, A2A)
- Adding new sandboxing or taint tracking capabilities

## Procedure

### Step 1: Research
1. Search for latest MCP protocol specification updates
2. Research current security approaches for:
   - Taint analysis and information flow control
   - Container sandboxing advancements
   - eBPF security monitoring
   - Policy engine improvements
3. Look for Python async optimization techniques
4. Check for new OWASP ASI guidelines

### Step 2: Evaluate Applicability
1. Read current MCPKernel implementation in `src/mcpkernel/`
2. Compare with researched techniques
3. Identify improvements that:
   - Fit MCPKernel's async Python architecture
   - Don't break existing APIs
   - Have measurable impact

### Step 3: Implement
1. Create a feature branch: `feature/<improvement-name>`
2. Write tests first for the new behavior
3. Implement the improvement with minimal changes
4. Run full test suite: `python -m pytest tests/ -v --tb=short`

### Step 4: Document
1. Update `docs/USAGE.md` if usage changes
2. Update `CHANGELOG.md` with the improvement
3. Update `README.md` if it's a notable feature

### Step 5: Report
Return research findings, what was implemented, and validation results.

## References
- MCPKernel architecture: `src/mcpkernel/`
- Configuration: `src/mcpkernel/config.py`
- Proxy layer: `src/mcpkernel/proxy/`
- Policy engine: `src/mcpkernel/policy/`
- Taint tracking: `src/mcpkernel/taint/`

---
description: "Use when working with MCPGuard YAML policy files. Covers policy syntax, rule structure, OWASP ASI mappings, and best practices for writing security policies."
applyTo: "policies/**/*.yaml"
---

# MCPGuard Policy Writing Guide

## Policy Structure
```yaml
version: "1.0"
rules:
  - id: "rule-unique-id"
    description: "What this rule does"
    tool: "tool_name"         # or "*" for all tools
    action: "allow|deny|audit"
    conditions:
      - field: "argument_name"
        operator: "equals|contains|matches|not_contains"
        value: "match_value"
    owasp_asi: "ASI-XX"      # Optional OWASP mapping
```

## Best Practices
- Use specific tool names over wildcards when possible
- Always include `description` for audit trail clarity
- Map rules to OWASP ASI categories for compliance reporting
- Test policies with: `python -m pytest tests/test_policy.py -v`

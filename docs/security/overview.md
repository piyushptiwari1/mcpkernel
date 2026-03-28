# Security Protections Overview

MCPKernel includes dedicated guards against the 6 named attacks from the MCP Security Best Practices specification (2025-11-25) plus additional research-based defenses.

---

## The 6 Attacks

| # | Attack | Guard Class | Risk |
|---|--------|-------------|------|
| 1 | Confused Deputy | `ConfusedDeputyGuard` | Tool X tricks proxy into calling tool Y with elevated privileges |
| 2 | Token Passthrough | `TokenPassthroughGuard` | Credentials leak through tool args/results |
| 3 | SSRF | `SSRFGuard` | Tool calls bypass network restrictions via proxy |
| 4 | Session Hijacking | `SessionGuard` | Session tokens stolen or replayed |
| 5 | Local Server Compromise | (Trust Framework) | Local MCP server is malicious |
| 6 | Memory Poisoning | `MemoryPoisoningGuard` | Self-reinforcing injection in agent memory |

---

## The Security Pipeline

All guards can be combined into a single pipeline:

```python
from mcpkernel.security import SecurityPipeline

pipeline = SecurityPipeline()

# Check a tool call (runs all pre-execution guards)
verdicts = pipeline.check_tool_call(
    tool_name="read_file",
    server_name="filesystem",
    arguments={"path": "/home/user/data.csv"},
)

# Check if all guards passed
if all(v.allowed for v in verdicts):
    print("✓ All security checks passed")
else:
    for v in verdicts:
        if not v.allowed:
            print(f"✗ [{v.check_name}] {v.reason} (severity: {v.severity})")

# Check tool results (runs all post-execution guards)
result_verdicts = pipeline.check_tool_result(
    tool_name="read_file",
    content="File contents here...",
)
```

---

## SecurityVerdict

Every guard returns a `SecurityVerdict`:

```python
from mcpkernel.security import SecurityVerdict

# Example verdict
verdict = SecurityVerdict(
    allowed=False,
    check_name="confused_deputy",
    reason="Cross-server delegation denied: 'filesystem' → 'deployment'",
    severity="critical",
    metadata={"source_server": "filesystem"},
)

print(f"Allowed: {verdict.allowed}")       # False
print(f"Check: {verdict.check_name}")      # confused_deputy
print(f"Severity: {verdict.severity}")     # critical
```

Severity levels:

| Level | Meaning |
|-------|---------|
| `info` | Informational, no action needed |
| `warning` | Suspicious but not blocked |
| `critical` | Blocked — this is an attack |

See [Attack Defenses](attack-defenses.md) for detailed examples of each guard.

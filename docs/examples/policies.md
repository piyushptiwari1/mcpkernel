# Policy Rules Examples

Learn to write MCPKernel policy rules from simple to advanced, with expected behavior for each.

---

## Example 1: Allow Everything (Development)

```python
from mcpkernel.policy.engine import PolicyEngine, PolicyAction

engine = PolicyEngine(default_action=PolicyAction.ALLOW)

# With no rules, everything is allowed
decision = engine.evaluate("read_file", {"path": "data.csv"})
print(f"Action: {decision.action}")
print(f"Allowed: {decision.allowed}")
print(f"Rules matched: {len(decision.matched_rules)}")
```

Output:

```
Action: allow
Allowed: True
Rules matched: 0
```

---

## Example 2: Deny by Default (Production)

```python
from mcpkernel.policy.engine import PolicyEngine, PolicyRule, PolicyAction

engine = PolicyEngine(default_action=PolicyAction.DENY)

# Add explicit allow for safe tools
engine.add_rule(PolicyRule(
    id="SAFE-001",
    name="Allow file reads",
    action=PolicyAction.ALLOW,
    priority=50,
    tool_patterns=["read_file", "list_dir"],
))

# Allowed tool
decision = engine.evaluate("read_file", {"path": "readme.txt"})
print(f"read_file: {decision.action} (allowed={decision.allowed})")
# Output: read_file: allow (allowed=True)

# Unknown tool — denied by default
decision = engine.evaluate("shell_exec", {"command": "ls"})
print(f"shell_exec: {decision.action} (allowed={decision.allowed})")
# Output: shell_exec: deny (allowed=False)
```

---

## Example 3: Block Sensitive File Patterns

```python
from mcpkernel.policy.engine import PolicyEngine, PolicyRule, PolicyAction

engine = PolicyEngine(default_action=PolicyAction.ALLOW)

engine.add_rule(PolicyRule(
    id="SEC-001",
    name="Block secret file reads",
    action=PolicyAction.DENY,
    priority=10,  # High priority — overrides allow
    tool_patterns=["read_file", "file_read"],
    argument_patterns={"path": r".*\.(env|pem|key|credentials)$"},
))

# Normal file — allowed
decision = engine.evaluate("read_file", {"path": "data.csv"})
print(f"data.csv: {decision.action}")
# Output: data.csv: allow

# Secret file — blocked
decision = engine.evaluate("read_file", {"path": "/home/user/.ssh/id_rsa.pem"})
print(f"id_rsa.pem: {decision.action}")
print(f"Reason: {decision.reasons[0]}")
# Output:
# id_rsa.pem: deny
# Reason: Matched rule SEC-001: Block secret file reads
```

---

## Example 4: Taint-Based Rules

Block outbound calls that carry sensitive data:

```python
from mcpkernel.policy.engine import PolicyEngine, PolicyRule, PolicyAction

engine = PolicyEngine(default_action=PolicyAction.ALLOW)

engine.add_rule(PolicyRule(
    id="TAINT-001",
    name="Block PII in outbound calls",
    action=PolicyAction.DENY,
    priority=10,
    tool_patterns=["http_post", "send_email", "slack_message"],
    taint_labels=["pii", "secret"],
))

# Outbound call without taint — allowed
decision = engine.evaluate(
    "http_post",
    {"url": "https://api.example.com", "body": "hello"},
)
print(f"No taint: {decision.action}")
# Output: No taint: allow

# Outbound call with PII taint — blocked
decision = engine.evaluate(
    "http_post",
    {"url": "https://api.example.com", "body": "SSN: 123-45-6789"},
    taint_labels={"pii"},
)
print(f"With PII: {decision.action}")
print(f"Reason: {decision.reasons[0]}")
# Output:
# With PII: deny
# Reason: Matched rule TAINT-001: Block PII in outbound calls
```

---

## Example 5: YAML Policy File

Create a policy file and load it programmatically:

```yaml
# policies/my_policy.yaml
rules:
  - id: MY-001
    name: Block dangerous commands
    action: deny
    priority: 10
    tool_patterns:
      - "shell_exec"
      - "execute_code"
      - "run_command"

  - id: MY-002
    name: Audit all file writes
    action: audit
    priority: 50
    tool_patterns:
      - "write_file"
      - "create_file"

  - id: MY-003
    name: Sandbox code execution
    action: sandbox
    priority: 30
    tool_patterns:
      - "execute_python"
      - "run_script"
```

Load and use:

```bash
# Validate the policy file first
mcpkernel validate-policy policies/my_policy.yaml
```

Output:

```
Validating policies/my_policy.yaml...
  Rule MY-001: ✓ valid
  Rule MY-002: ✓ valid
  Rule MY-003: ✓ valid

Policy file is valid (3 rules).
```

---

## Example 6: Priority and Precedence

When multiple rules match, MCPKernel uses **precedence**: DENY > SANDBOX > WARN > AUDIT > ALLOW. Within the same action type, lower priority number wins.

```python
from mcpkernel.policy.engine import PolicyEngine, PolicyRule, PolicyAction

engine = PolicyEngine(default_action=PolicyAction.ALLOW)

# Rule 1: Allow execute_python generally
engine.add_rule(PolicyRule(
    id="EX-001",
    name="Allow Python execution",
    action=PolicyAction.ALLOW,
    priority=100,
    tool_patterns=["execute_python"],
))

# Rule 2: But sandbox it (higher precedence action)
engine.add_rule(PolicyRule(
    id="EX-002",
    name="Sandbox Python execution",
    action=PolicyAction.SANDBOX,
    priority=50,
    tool_patterns=["execute_python"],
))

decision = engine.evaluate("execute_python", {"code": "print('hello')"})
print(f"Action: {decision.action}")
print(f"Matched rules: {len(decision.matched_rules)}")
for rule in decision.matched_rules:
    print(f"  {rule.id}: {rule.action} (priority {rule.priority})")
```

Output:

```
Action: sandbox
Matched rules: 2
  EX-002: sandbox (priority 50)
  EX-001: allow (priority 100)
```

!!! info "Precedence order"
    `DENY` always wins over `SANDBOX`, which wins over `WARN`, which wins over `AUDIT`, which wins over `ALLOW`. This ensures security rules cannot be overridden by permissive ones.

---

## Example 7: OWASP ASI 2026 Policy

Use the built-in strict OWASP policy:

```bash
# Copy the policy
cp policies/owasp_asi_2026_strict.yaml .mcpkernel/policies/

# Validate
mcpkernel validate-policy .mcpkernel/policies/owasp_asi_2026_strict.yaml
```

```yaml
# policies/owasp_asi_2026_strict.yaml (excerpt)
rules:
  - id: ASI-01-001
    name: Unauthorized tool invocation
    action: deny
    priority: 10
    owasp_asi_id: ASI-01
    tool_patterns:
      - ".*"
    conditions:
      require_auth: true

  - id: ASI-03-001
    name: Block PII in outbound calls
    action: deny
    priority: 10
    owasp_asi_id: ASI-03
    tool_patterns:
      - "http_post"
      - "send_email"
    taint_labels:
      - pii
      - secret
```

---

## Example 8: List Available Presets

```bash
mcpkernel presets
```

Output:

```
Available Policy Presets
========================

  permissive    All tools allowed, audit-only logging
  standard      Common dangerous tools denied, taint on
  strict        Deny-by-default, explicit allowlist required
```

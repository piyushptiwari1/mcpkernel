# Policy Engine

The policy engine is the first line of defense in MCPKernel. Every tool call is evaluated against a set of rules before execution. Rules are defined in YAML and support regex matching, taint label conditions, and OWASP ASI 2026 mappings.

---

## How It Works

```
Tool Call → Match Tool Pattern → Match Arguments → Check Taint Labels → Decision
```

Rules are evaluated by priority (lowest number = highest precedence). The most restrictive matching rule wins.

| Action | What Happens |
|--------|-------------|
| `deny` | Block the tool call immediately |
| `sandbox` | Execute in sandboxed environment |
| `warn` | Allow but log a warning |
| `audit` | Allow and log for review |
| `allow` | Allow silently |

---

## Tutorial: Your First Policy

### Step 1: Create a policy file

```yaml
# policies/my_policy.yaml
rules:
  - id: block-shell
    name: Block shell execution
    description: Prevent any tool from running shell commands
    action: deny
    priority: 10
    tool_patterns:
      - "shell_.*"
      - "os_command"
      - "subprocess_run"
```

### Step 2: Validate it

```bash
mcpkernel validate-policy policies/my_policy.yaml
```

Output:

```
✓ Loaded 1 valid rules from policies/my_policy.yaml
  [block-shell] Block shell execution → deny
```

### Step 3: Use it in Python

```python
from mcpkernel.policy.engine import PolicyEngine, PolicyRule, PolicyAction

# Create an engine with deny-by-default
engine = PolicyEngine(default_action=PolicyAction.DENY)

# Add a rule that allows file reading
engine.add_rule(PolicyRule(
    id="allow-read",
    name="Allow file reading",
    description="Permit read_file and list_dir tools",
    action=PolicyAction.ALLOW,
    priority=50,
    tool_patterns=["read_file", "list_dir"],
))

# Add a rule that blocks shell access
engine.add_rule(PolicyRule(
    id="block-shell",
    name="Block shell execution",
    action=PolicyAction.DENY,
    priority=10,
    tool_patterns=["shell_.*", "os_command"],
))

# Evaluate tool calls
result1 = engine.evaluate("read_file", {"path": "/tmp/data.csv"})
print(f"read_file: {result1.action}")    # Output: read_file: allow
print(f"Allowed: {result1.allowed}")     # Output: Allowed: True

result2 = engine.evaluate("shell_exec", {"command": "ls"})
print(f"shell_exec: {result2.action}")   # Output: shell_exec: deny
print(f"Reasons: {result2.reasons}")
# Output: Reasons: ['[block-shell] Block shell execution: ']

result3 = engine.evaluate("unknown_tool", {})
print(f"unknown_tool: {result3.action}") # Output: unknown_tool: deny
# (deny-by-default catches everything not explicitly allowed)
```

---

## Rule Matching in Detail

### Tool Name Patterns (regex)

Tool patterns use Python regex with `re.fullmatch()`:

```yaml
rules:
  - id: block-http
    name: Block outbound HTTP
    action: deny
    tool_patterns:
      - "http_.*"       # Matches http_get, http_post, etc.
      - "fetch_.*"      # Matches fetch_url, fetch_data
      - "api_call"      # Exact match
```

```python
# In Python
rule = PolicyRule(
    id="block-http",
    name="Block outbound HTTP",
    action=PolicyAction.DENY,
    tool_patterns=["http_.*", "fetch_.*", "api_call"],
)
```

### Argument Patterns (regex on values)

Match specific argument values:

```yaml
rules:
  - id: block-traversal
    name: Block path traversal
    action: deny
    priority: 10
    tool_patterns:
      - "file_read"
      - "file_write"
    argument_patterns:
      path: "\\.\\./|/etc/|/proc/"
```

```python
engine = PolicyEngine(default_action=PolicyAction.ALLOW)
engine.add_rule(PolicyRule(
    id="block-traversal",
    name="Block path traversal",
    action=PolicyAction.DENY,
    priority=10,
    tool_patterns=["file_read", "file_write"],
    argument_patterns={"path": r"\.\./|/etc/|/proc/"},
))

# Safe path — allowed
result = engine.evaluate("file_read", {"path": "/home/user/data.csv"})
print(f"Safe path: {result.action}")     # Output: Safe path: allow

# Traversal attempt — blocked
result = engine.evaluate("file_read", {"path": "../../etc/passwd"})
print(f"Traversal: {result.action}")     # Output: Traversal: deny
print(f"Reason: {result.reasons[0]}")
# Output: Reason: [block-traversal] Block path traversal: 
```

### Taint Label Conditions

Rules can trigger only when data carries specific taint labels:

```yaml
rules:
  - id: block-pii-exfil
    name: Block PII in outbound calls
    description: Prevent PII-tainted data from reaching HTTP sinks
    action: deny
    priority: 10
    tool_patterns:
      - "http_post"
      - "send_email"
      - "webhook_.*"
    taint_labels:
      - pii
      - secret
    owasp_asi_id: ASI-03
```

```python
engine = PolicyEngine(default_action=PolicyAction.ALLOW)
engine.add_rule(PolicyRule(
    id="block-pii-exfil",
    name="Block PII exfiltration",
    action=PolicyAction.DENY,
    tool_patterns=["http_post", "send_email"],
    taint_labels=["pii", "secret"],
))

# No taint — allowed
result = engine.evaluate("http_post", {"url": "https://api.example.com"})
print(f"No taint: {result.action}")      # Output: No taint: allow

# With PII taint — blocked
result = engine.evaluate(
    "http_post",
    {"url": "https://api.example.com"},
    taint_labels={"pii"},
)
print(f"With PII: {result.action}")      # Output: With PII: deny
```

---

## OWASP ASI 2026 Policy

MCPKernel ships with a complete OWASP ASI 2026 policy file:

```bash
mcpkernel validate-policy policies/owasp_asi_2026_strict.yaml
```

```yaml
# policies/owasp_asi_2026_strict.yaml (excerpt)
rules:
  # ASI-01: Prompt Injection
  - id: ASI-01-001
    name: Block untrusted input in eval
    action: deny
    priority: 10
    tool_patterns: [".*"]
    taint_labels: [user_input, llm_output, untrusted_external]
    owasp_asi_id: ASI-01

  # ASI-02: Tool Misuse
  - id: ASI-02-001
    name: Sandbox all code execution
    action: sandbox
    priority: 20
    tool_patterns: ["execute_.*", "run_.*", "shell_.*"]
    owasp_asi_id: ASI-02

  # ASI-03: Data Exfiltration
  - id: ASI-03-001
    name: Block PII in outbound calls
    action: deny
    priority: 10
    tool_patterns: ["http_post", "send_email", "webhook_.*"]
    taint_labels: [pii, secret]
    owasp_asi_id: ASI-03
```

### Use OWASP policy in code

```python
from mcpkernel import MCPKernelProxy

async with MCPKernelProxy(
    upstream=["http://localhost:3000/mcp"],
    policy="owasp-asi-2026",
) as proxy:
    # All calls enforced against OWASP ASI 2026 rules
    result = await proxy.call_tool("read_file", {"path": "data.csv"})
```

---

## Built-in Presets

```python
from mcpkernel.api import POLICY_PRESETS

for name, config in POLICY_PRESETS.items():
    print(f"{name}: {config['description']}")
```

Output:

```
permissive: Audit everything, block nothing. Good for development.
standard: Block known-dangerous patterns, audit the rest.
strict: Deny-by-default. Only explicitly allowed tools pass.
owasp-asi-2026: Full OWASP ASI 2026 compliance rule set.
```

---

## Advanced: Multiple Rules and Precedence

When multiple rules match, the most restrictive action wins:

```python
from mcpkernel.policy.engine import PolicyEngine, PolicyRule, PolicyAction

engine = PolicyEngine(default_action=PolicyAction.ALLOW)

# Lower priority number = higher precedence
engine.add_rule(PolicyRule(
    id="audit-all",
    name="Audit everything",
    action=PolicyAction.AUDIT,
    priority=100,
    tool_patterns=[".*"],
))

engine.add_rule(PolicyRule(
    id="block-shell",
    name="Block shell",
    action=PolicyAction.DENY,
    priority=10,
    tool_patterns=["shell_.*"],
))

# shell_exec matches both rules — DENY wins (more restrictive)
result = engine.evaluate("shell_exec", {})
print(f"shell_exec: {result.action}")        # Output: shell_exec: deny
print(f"Rules matched: {len(result.matched_rules)}")  # Output: Rules matched: 2

# read_file matches only audit rule
result = engine.evaluate("read_file", {})
print(f"read_file: {result.action}")         # Output: read_file: audit
```

### Rule precedence order (most to least restrictive):

1. `deny` — Block completely
2. `sandbox` — Execute in isolation
3. `warn` — Allow with warning
4. `audit` — Allow and log
5. `allow` — Allow silently

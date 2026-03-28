# Taint Tracking

Taint tracking labels data as it flows through tool calls — flagging secrets, PII, LLM output, and untrusted input. When tainted data reaches a sensitive sink (like an HTTP POST), MCPKernel blocks it.

---

## How It Works

```
Data Source → Label (secret/pii/user_input) → Propagate through tool chains → Block at sinks
```

Every piece of data gets a **taint label** that follows it through the pipeline:

| Label | What It Catches |
|-------|----------------|
| `secret` | API keys, tokens, passwords |
| `pii` | Names, emails, phone numbers, SSNs |
| `user_input` | Raw user-provided data |
| `llm_output` | LLM-generated content |
| `untrusted_external` | Data from external APIs |
| `custom` | Your own labels |

---

## Tutorial: Basic Taint Tracking

### Step 1: Mark data as tainted

```python
from mcpkernel.taint.tracker import TaintTracker, TaintLabel

tracker = TaintTracker()

# Mark a value as containing a secret
tv = tracker.mark(
    data="sk-abc123secretkey",
    label=TaintLabel.SECRET,
    source_id="openai-key",
)
print(f"Tainted: {tv.is_tainted}")           # Output: Tainted: True
print(f"Labels: {tv.labels}")                 # Output: Labels: {<TaintLabel.SECRET: 'secret'>}
print(f"Source: {tv.source_id}")              # Output: Source: openai-key
print(f"Provenance: {tv.provenance}")         # Output: Provenance: ['marked:secret']
```

### Step 2: Track multiple labels

```python
# Mark PII data
pii_data = tracker.mark(
    data="John Doe, john@example.com",
    label=TaintLabel.PII,
    source_id="user-profile",
)

# Mark user input
user_data = tracker.mark(
    data="Please delete all files",
    label=TaintLabel.USER_INPUT,
    source_id="chat-message-42",
)

# Check overall taint state
print(f"Total tracked: {tracker.summary()}")
```

Output:

```python
{
    'total_tracked': 3,
    'active_tainted': 3,
    'by_label': {'secret': 1, 'pii': 1, 'user_input': 1},
    'sanitizers': []
}
```

### Step 3: Query tainted values

```python
# Get all values with a specific label
secrets = tracker.get_by_label(TaintLabel.SECRET)
print(f"Secrets found: {len(secrets)}")       # Output: Secrets found: 1
for s in secrets:
    print(f"  Source: {s.source_id}, Labels: {[l.value for l in s.labels]}")
    # Output:   Source: openai-key, Labels: ['secret']

# Get all tainted values
all_tainted = tracker.get_all_tainted()
print(f"Total tainted: {len(all_tainted)}")   # Output: Total tainted: 3
```

---

## Tutorial: Clearing Taint (Sanitization)

Taint can only be cleared with an explicit sanitizer — this creates an audit trail:

```python
from mcpkernel.taint.tracker import TaintTracker, TaintLabel

tracker = TaintTracker()

# Register a known sanitizer
tracker.register_sanitizer("pii_redactor_v2")
print(f"Known sanitizer: {tracker.is_known_sanitizer('pii_redactor_v2')}")
# Output: Known sanitizer: True

# Mark data as PII
tv = tracker.mark("SSN: 123-45-6789", TaintLabel.PII, source_id="form-data")
print(f"Before: {tv.labels}")  # Output: Before: {<TaintLabel.PII: 'pii'>}

# Clear the taint with sanitizer justification
tracker.clear("form-data", TaintLabel.PII, sanitizer="pii_redactor_v2")

tv = tracker.get("form-data")
print(f"After: {tv.labels}")       # Output: After: set()
print(f"Provenance: {tv.provenance}")
# Output: Provenance: ['marked:pii', 'cleared:pii:by:pii_redactor_v2']
```

!!! warning "Audit Trail"
    Every `clear()` operation records which sanitizer was used and when. This is critical for compliance — you can prove that PII was properly handled.

---

## Tutorial: Taint in the Security Pipeline

When you use `MCPKernelProxy`, taint tracking is automatic:

```python
import asyncio
from mcpkernel import MCPKernelProxy, PolicyViolation

async def demo():
    async with MCPKernelProxy(
        policy="strict",
        taint=True,       # Enable taint tracking
        audit=True,
    ) as proxy:
        # This tool call has its arguments scanned for secrets
        try:
            result = await proxy.call_tool("http_post", {
                "url": "https://api.example.com",
                "body": "API key: sk-abc123secretkey",  # Secret detected!
            })
        except PolicyViolation as e:
            print(f"Blocked: {e}")
            # Output: Blocked: [policy-deny] Taint violation: secret detected

asyncio.run(demo())
```

### Configuration

```yaml
# config.yaml
taint:
  mode: full              # full | light | off
  block_on_violation: true
  pii_patterns_enabled: true
  static_analysis_enabled: true
```

| Mode | Behavior |
|------|----------|
| `full` | Every argument and result scanned; blocks on violation |
| `light` | Scan arguments only; log but don't block |
| `off` | Taint tracking disabled |

---

## Available Taint Labels

```python
from mcpkernel.taint.tracker import TaintLabel

# All available labels
for label in TaintLabel:
    print(f"  {label.value}")
```

Output:

```
  secret
  pii
  llm_output
  user_input
  untrusted_external
  custom
```

---

## Advanced: Building a TaintedValue Manually

```python
from mcpkernel.taint.tracker import TaintedValue, TaintLabel

# Create a value with multiple taint labels
tv = TaintedValue(
    value="User said: my SSN is 123-45-6789",
    labels={TaintLabel.USER_INPUT, TaintLabel.PII},
    source_id="chat-msg-99",
    provenance=["marked:user_input", "marked:pii"],
    metadata={"session_id": "abc123", "agent": "assistant"},
)

print(f"Value tainted: {tv.is_tainted}")             # True
print(f"Labels: {sorted(l.value for l in tv.labels)}")  # ['pii', 'user_input']

# Add another label
tv.add_label(TaintLabel.UNTRUSTED_EXTERNAL)
print(f"Labels now: {sorted(l.value for l in tv.labels)}")
# Output: ['pii', 'untrusted_external', 'user_input']
```

---

## Pattern: Taint + Policy Engine Together

The most powerful pattern is combining taint labels with policy rules:

```python
from mcpkernel.taint.tracker import TaintTracker, TaintLabel
from mcpkernel.policy.engine import PolicyEngine, PolicyRule, PolicyAction

# Set up taint tracking
tracker = TaintTracker()
tracker.mark("user query", TaintLabel.USER_INPUT, source_id="msg-1")

# Set up policy with taint-aware rules
engine = PolicyEngine(default_action=PolicyAction.ALLOW)
engine.add_rule(PolicyRule(
    id="block-user-input-in-exec",
    name="Block user input in code execution",
    action=PolicyAction.DENY,
    priority=10,
    tool_patterns=["execute_.*", "run_.*"],
    taint_labels=["user_input"],
))

# Evaluate with taint context
result = engine.evaluate(
    "execute_code",
    {"code": "print('hello')"},
    taint_labels={"user_input"},
)
print(f"Action: {result.action}")          # Output: Action: deny
print(f"OWASP: {result.metadata}")
# Output: OWASP: {'owasp_asi_ids': []}
```

This is exactly how MCPKernel detects data exfiltration (ASI-03) — PII-tainted data reaching an HTTP sink triggers a deny.

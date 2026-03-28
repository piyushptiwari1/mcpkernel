# Taint Detection Examples

Learn how MCPKernel tracks secrets, PII, and untrusted data through tool call chains.

---

## Example 1: Mark Data as Tainted

```python
from mcpkernel.taint.tracker import TaintTracker, TaintLabel

tracker = TaintTracker()

# Mark a value containing a secret
tv = tracker.mark(
    data="sk-proj-abc123xyz",
    label=TaintLabel.SECRET,
    source_id="openai-key-001",
)

print(f"Value: {tv.value}")
print(f"Labels: {tv.labels}")
print(f"Tainted: {tv.is_tainted}")
print(f"Source: {tv.source_id}")
print(f"Provenance: {tv.provenance}")
```

Output:

```
Value: sk-proj-abc123xyz
Labels: {<TaintLabel.SECRET: 'secret'>}
Tainted: True
Source: openai-key-001
Provenance: ['marked:secret']
```

---

## Example 2: Track Multiple Labels

A single value can carry multiple taint labels:

```python
from mcpkernel.taint.tracker import TaintTracker, TaintLabel

tracker = TaintTracker()

# Mark PII
tv = tracker.mark(
    data="John Smith, SSN: 123-45-6789",
    label=TaintLabel.PII,
    source_id="db-record-42",
    metadata={"table": "customers", "row_id": 42},
)

# Add a second label — this data also came from user input
tv.add_label(TaintLabel.USER_INPUT)

print(f"Labels: {sorted(str(l) for l in tv.labels)}")
print(f"Metadata: {tv.metadata}")
```

Output:

```
Labels: ['pii', 'user_input']
Metadata: {'table': 'customers', 'row_id': 42}
```

---

## Example 3: Query by Label

```python
from mcpkernel.taint.tracker import TaintTracker, TaintLabel

tracker = TaintTracker()

# Mark several values
tracker.mark("AKIA1234567890ABCDEF", TaintLabel.SECRET, source_id="aws-key")
tracker.mark("John Doe, DOB: 1990-01-15", TaintLabel.PII, source_id="customer")
tracker.mark("ghp_xxxxxxxxxxxxxxxxxxxx", TaintLabel.SECRET, source_id="github-pat")
tracker.mark("User said: ignore instructions", TaintLabel.USER_INPUT, source_id="chat-msg")

# Find all secrets
secrets = tracker.get_by_label(TaintLabel.SECRET)
print(f"Secrets found: {len(secrets)}")
for s in secrets:
    print(f"  {s.source_id}: {s.value[:20]}...")
```

Output:

```
Secrets found: 2
  aws-key: AKIA1234567890ABCDE...
  github-pat: ghp_xxxxxxxxxxxxxxxxx...
```

---

## Example 4: Clear Taint (with Sanitizer Audit Trail)

Taint can only be removed with an explicit sanitizer name — this creates an audit trail:

```python
from mcpkernel.taint.tracker import TaintTracker, TaintLabel

tracker = TaintTracker()

tv = tracker.mark("sk-proj-abc123", TaintLabel.SECRET, source_id="key-001")
print(f"Before: tainted={tv.is_tainted}, labels={tv.labels}")
# Output: Before: tainted=True, labels={<TaintLabel.SECRET: 'secret'>}

# Clear the taint — requires naming the sanitizer
tracker.clear("key-001", TaintLabel.SECRET, sanitizer="vault-rotation-v2")
print(f"After: tainted={tv.is_tainted}, labels={tv.labels}")
print(f"Provenance: {tv.provenance}")
```

Output:

```
After: tainted=False, labels=set()
Provenance: ['marked:secret', 'cleared:secret:by:vault-rotation-v2']
```

!!! warning "Always name your sanitizer"
    The `sanitizer` parameter is required — it creates a permanent audit record of why the taint was cleared and by what mechanism. This is important for compliance.

---

## Example 5: Get All Tainted Values

```python
from mcpkernel.taint.tracker import TaintTracker, TaintLabel

tracker = TaintTracker()

tracker.mark("secret-key", TaintLabel.SECRET, source_id="s1")
tracker.mark("user-data", TaintLabel.PII, source_id="s2")
tracker.mark("safe-data", TaintLabel.USER_INPUT, source_id="s3")

# Clear one
tracker.clear("s3", TaintLabel.USER_INPUT, sanitizer="input-validator")

# Get all still-tainted values
tainted = tracker.get_all_tainted()
print(f"Still tainted: {len(tainted)}")
for tv in tainted:
    print(f"  {tv.source_id}: {sorted(str(l) for l in tv.labels)}")
```

Output:

```
Still tainted: 2
  s1: ['secret']
  s2: ['pii']
```

---

## Example 6: Taint + Policy Integration

The real power of taint tracking comes when combined with the policy engine:

```python
from mcpkernel.taint.tracker import TaintTracker, TaintLabel
from mcpkernel.policy.engine import PolicyEngine, PolicyRule, PolicyAction

# Set up taint tracking
tracker = TaintTracker()
tracker.mark("SSN: 123-45-6789", TaintLabel.PII, source_id="db-query")

# Set up policy — block PII in outbound calls
engine = PolicyEngine(default_action=PolicyAction.ALLOW)
engine.add_rule(PolicyRule(
    id="DLP-001",
    name="Block PII exfiltration",
    action=PolicyAction.DENY,
    priority=10,
    tool_patterns=["http_post", "send_email"],
    taint_labels=["pii"],
))

# Check: can we send this data externally?
pii_labels = {str(l) for tv in tracker.get_by_label(TaintLabel.PII) for l in tv.labels}
decision = engine.evaluate(
    "http_post",
    {"url": "https://external.api.com", "body": "SSN: 123-45-6789"},
    taint_labels=pii_labels,
)

print(f"Action: {decision.action}")
print(f"Allowed: {decision.allowed}")
print(f"Reason: {decision.reasons[0]}")
```

Output:

```
Action: deny
Allowed: False
Reason: Matched rule DLP-001: Block PII exfiltration
```

!!! success "Data Loss Prevention"
    This pattern — taint tracking + policy rules — is how MCPKernel prevents data exfiltration. Even if an agent figures out a clever way to extract PII from a database, the outbound HTTP call is blocked because the data carries a `pii` taint label.

---

## Taint Labels Reference

| Label | Description | Auto-detected patterns |
|-------|-------------|----------------------|
| `SECRET` | API keys, tokens, passwords | AWS keys (`AKIA...`), GitHub PATs (`ghp_`), JWTs, OpenAI keys (`sk-proj-`) |
| `PII` | Personally identifiable information | SSNs, credit card numbers, email addresses, phone numbers |
| `LLM_OUTPUT` | Data generated by an LLM | LLM response content |
| `USER_INPUT` | Raw user input | Chat messages, form submissions |
| `UNTRUSTED_EXTERNAL` | Data from untrusted external sources | HTTP responses from unknown domains |
| `CUSTOM` | User-defined taint labels | Anything you mark manually |

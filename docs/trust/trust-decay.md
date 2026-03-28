# Trust Decay Engine

The Trust Decay Engine manages trust profiles for all entities (servers, tools, agents) in the system. Trust erodes automatically over time and recovers through verification events.

---

## Why Trust Decays

In traditional security, a server that passed verification once is trusted forever. But in agentic systems:

- Server code can change between verifications
- Dependencies can be compromised (supply chain attacks)
- Behavioral drift happens gradually

MCPKernel's trust decay model ensures **nothing stays trusted without continuous verification**.

---

## Tutorial: Basic Trust Management

### Step 1: Create the engine and register entities

```python
from mcpkernel.trust.trust_decay import TrustDecayEngine

engine = TrustDecayEngine(
    server_decay_rate=0.0005,   # Servers decay slowly
    tool_decay_rate=0.001,      # Tools decay moderately
    agent_decay_rate=0.002,     # Agents decay faster
    alert_threshold=0.3,        # Alert when trust < 0.3
)

# Register a server
server = engine.register(
    "filesystem-server",
    entity_type="server",
    initial_trust=1.0,
)
print(f"Registered: {server.entity_id} ({server.entity_type})")
print(f"Decay rate: {server.decay_rate}")
# Output:
# Registered: filesystem-server (server)
# Decay rate: 0.0005

# Register a tool
tool = engine.register(
    "read_file",
    entity_type="tool",
    initial_trust=0.9,  # Start with slightly lower trust
)

# Register an agent
agent = engine.register(
    "coding-assistant",
    entity_type="agent",
    initial_trust=1.0,
)
```

### Step 2: Check trust scores (they decay over time)

```python
import time

# Right after registration
print(f"Server trust: {engine.get_trust('filesystem-server'):.4f}")
# Output: Server trust: 1.0000

# Simulate time passing
time.sleep(5)
print(f"Server after 5s: {engine.get_trust('filesystem-server'):.4f}")
# Output: Server after 5s: ~0.9975 (slow decay)

print(f"Tool after 5s: {engine.get_trust('read_file'):.4f}")
# Output: Tool after 5s: ~0.8955 (moderate decay, started at 0.9)

print(f"Agent after 5s: {engine.get_trust('coding-assistant'):.4f}")
# Output: Agent after 5s: ~0.9900 (fast decay)
```

### Step 3: Verify to restore trust

```python
# Verification resets the decay timer
success = engine.verify(
    "filesystem-server",
    event_type="audit_pass",
    weight=1.0,
    details={"auditor": "security-scan", "version": "2.1.0"},
)
print(f"Verification recorded: {success}")
# Output: Verification recorded: True

# Trust resets based on the new timer
print(f"After verify: {engine.get_trust('filesystem-server'):.4f}")
# Output: After verify: ~1.0000
```

### Step 4: Penalize for violations

```python
# Tool violated a policy — apply a trust penalty
engine.penalize(
    "read_file",
    factor=0.5,        # Multiply trust by 0.5
    reason="policy_violation",
)

print(f"After penalty: {engine.get_trust('read_file'):.4f}")
# Output: After penalty: ~0.4478 (0.9 * 0.5 * decay)

# Multiple penalties stack (multiplicative)
engine.penalize("read_file", factor=0.3, reason="repeated_violation")
print(f"After 2nd penalty: {engine.get_trust('read_file'):.4f}")
# Output: After 2nd penalty: ~0.1343 (very low trust)
```

---

## Tutorial: Monitoring and Alerts

### Check entities below threshold

```python
# Find all entities with trust below 0.3
low_trust = engine.get_all_below_threshold()
print(f"Entities below threshold ({engine._alert_threshold}):")
for entity_id, score in low_trust:
    print(f"  {entity_id}: {score:.4f}")
```

Output:

```
Entities below threshold (0.3):
  read_file: 0.1343
```

### View alerts

```python
alerts = engine.alerts
for alert in alerts:
    print(f"ALERT: {alert['entity_id']} score={alert['score']:.4f} — {alert['reason']}")
```

Output:

```
ALERT: read_file score=0.1343 — trust_below_threshold
```

### Get a summary

```python
summary = engine.summary()
print(summary)
```

Output:

```python
{
    'total_entities': 3,
    'average_trust_by_type': {
        'server': 0.9998,
        'tool': 0.1343,
        'agent': 0.9900
    },
    'below_threshold': 1,
    'active_alerts': 1
}
```

---

## Tutorial: Verification Events and History

Each verification event is recorded with full details:

```python
# Verify with different event types
engine.verify("coding-assistant", "signature_verified", weight=1.0)
engine.verify("coding-assistant", "policy_compliant", weight=0.95)
engine.verify("coding-assistant", "audit_pass", weight=0.9)

# Check verification history
profile = engine.get_profile("coding-assistant")
print(f"Verification events: {len(profile.verification_history)}")
for event in profile.verification_history:
    print(f"  [{event.event_type}] weight={event.weight}")
```

Output:

```
Verification events: 3
  [signature_verified] weight=1.0
  [policy_compliant] weight=0.95
  [audit_pass] weight=0.9
```

!!! info "Verification Weights Multiply"
    Each verification adds a weight to the product. A weight of 0.95 means "95% confidence". Multiple verifications multiply: 1.0 × 0.95 × 0.9 = 0.855 × decay.

---

## Configuration

```yaml
trust:
  enabled: true
  decay_rate: 0.001           # Default λ (per-second)
  server_decay_rate: 0.0005   # Servers decay slowly
  tool_decay_rate: 0.001      # Tools decay moderately
  agent_decay_rate: 0.002     # Agents decay faster
  alert_threshold: 0.3        # Alert below this score
  compromise_threshold: 0.1   # Mark compromised below this
```

---

## Full Working Example

```python
"""Trust decay demo: register, decay, verify, penalize, monitor."""

import time
from mcpkernel.trust.trust_decay import TrustDecayEngine

def main():
    engine = TrustDecayEngine(
        server_decay_rate=0.0005,
        tool_decay_rate=0.001,
        agent_decay_rate=0.002,
        alert_threshold=0.3,
    )

    # Register entities
    engine.register("github-mcp", "server")
    engine.register("write_file", "tool")
    engine.register("agent-alpha", "agent")

    # Simulate time passing
    print("=== Initial Trust ===")
    for eid in ["github-mcp", "write_file", "agent-alpha"]:
        print(f"  {eid}: {engine.get_trust(eid):.4f}")

    time.sleep(2)
    print("\n=== After 2 seconds ===")
    for eid in ["github-mcp", "write_file", "agent-alpha"]:
        print(f"  {eid}: {engine.get_trust(eid):.4f}")

    # Verify the server
    engine.verify("github-mcp", "audit_pass", weight=1.0)
    print(f"\n  github-mcp after verify: {engine.get_trust('github-mcp'):.4f}")

    # Penalize the tool
    engine.penalize("write_file", factor=0.2, reason="unauthorized_write")
    print(f"  write_file after penalty: {engine.get_trust('write_file'):.4f}")

    # Summary
    print(f"\n=== Summary ===")
    print(engine.summary())

main()
```

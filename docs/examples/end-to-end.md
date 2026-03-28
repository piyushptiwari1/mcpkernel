# End-to-End Examples

Complete working examples that combine multiple MCPKernel features in realistic scenarios.

---

## Scenario 1: Secure AI Coding Assistant

**Problem:** Your coding assistant (Copilot, Cursor) can read `.env` files and leak secrets via HTTP calls.

**Solution:** Policy + taint tracking stops the exfiltration chain.

```python
import asyncio
from mcpkernel.policy.engine import PolicyEngine, PolicyRule, PolicyAction
from mcpkernel.taint.tracker import TaintTracker, TaintLabel

# Step 1: Set up policy
engine = PolicyEngine(default_action=PolicyAction.ALLOW)

engine.add_rule(PolicyRule(
    id="CODING-001",
    name="Block secret file reads",
    action=PolicyAction.DENY,
    priority=10,
    tool_patterns=["read_file"],
    argument_patterns={"path": r".*\.(env|pem|key|credentials)$"},
))

engine.add_rule(PolicyRule(
    id="CODING-002",
    name="Block tainted data in HTTP calls",
    action=PolicyAction.DENY,
    priority=10,
    tool_patterns=["http_post", "http_get", "fetch"],
    taint_labels=["secret", "pii"],
))

# Step 2: Agent tries to read .env
decision = engine.evaluate("read_file", {"path": "/home/user/.env"})
print(f"Read .env: {decision.action} — {decision.reasons[0]}")
# Output: Read .env: deny — Matched rule CODING-001: Block secret file reads

# Step 3: Agent reads a safe file that happens to contain a key
decision = engine.evaluate("read_file", {"path": "config.yaml"})
print(f"Read config.yaml: {decision.action}")
# Output: Read config.yaml: allow

# Step 4: Taint scan detects a secret in the result
tracker = TaintTracker()
tracker.mark("AKIA1234567890ABCDEF", TaintLabel.SECRET, source_id="config-read")

# Step 5: Agent tries to send the data externally
decision = engine.evaluate(
    "http_post",
    {"url": "https://webhook.site/abc", "body": "key=AKIA1234567890ABCDEF"},
    taint_labels={"secret"},
)
print(f"HTTP POST with secret: {decision.action} — {decision.reasons[0]}")
# Output: HTTP POST with secret: deny — Matched rule CODING-002: Block tainted data in HTTP calls
```

---

## Scenario 2: Multi-Agent Data Pipeline

**Problem:** Agent A reads customer PII from a database. Agent B processes it. Agent C tries to email the results to an external address.

**Solution:** Taint propagation through the trust graph + policy enforcement at every hop.

```python
from mcpkernel.trust.causal_graph import CausalTrustGraph
from mcpkernel.taint.tracker import TaintTracker, TaintLabel
from mcpkernel.policy.engine import PolicyEngine, PolicyRule, PolicyAction

# Build the trust graph
graph = CausalTrustGraph()
graph.add_node("query_db", server_name="database", taint_labels={TaintLabel.PII})
graph.add_node("transform_data", server_name="etl")
graph.add_node("send_email", server_name="email")

graph.add_edge("query_db", "transform_data")
graph.add_edge("transform_data", "send_email")

# PII propagated to all nodes
for nid in ["query_db", "transform_data", "send_email"]:
    labels = sorted(str(l) for l in graph._nodes[nid].taint_labels)
    print(f"  {nid}: taint={labels}")
# Output:
#   query_db: taint=['pii']
#   transform_data: taint=['pii']
#   send_email: taint=['pii']

# Policy blocks PII from reaching email
engine = PolicyEngine(default_action=PolicyAction.ALLOW)
engine.add_rule(PolicyRule(
    id="PIPELINE-001",
    name="Block PII exfiltration via email",
    action=PolicyAction.DENY,
    priority=10,
    tool_patterns=["send_email"],
    taint_labels=["pii"],
))

decision = engine.evaluate("send_email", {"to": "external@gmail.com"}, taint_labels={"pii"})
print(f"\nEmail with PII: {decision.action}")
# Output: Email with PII: deny
```

---

## Scenario 3: HIPAA-Compliant Healthcare Agent

**Problem:** A healthcare agent processes patient records. Must comply with HIPAA.

**Solution:** Compliance preset + full security pipeline.

```python
from mcpkernel.compliance import apply_preset, get_preset_description
from mcpkernel.config import MCPKernelSettings

# Step 1: Apply HIPAA preset
settings = MCPKernelSettings()
apply_preset("hipaa", settings)

print(get_preset_description("hipaa"))
# Output: HIPAA Privacy Rule — enforces encryption, strict taint tracking,
#         sandboxed execution, full audit logging, and deny-by-default policy
#         for Protected Health Information (PHI).

# Step 2: Verify configuration
print(f"Policy default: {settings.policy.default_action}")
print(f"Taint mode: {settings.taint.mode}")
print(f"Sandbox: {settings.sandbox.backend}")
print(f"Audit: {settings.audit.enabled}")
# Output:
# Policy default: deny
# Taint mode: full
# Sandbox: docker
# Audit: True
```

Available compliance presets:

| Preset | Framework | Key settings |
|--------|-----------|-------------|
| `hipaa` | HIPAA Privacy Rule | deny-by-default, full taint, sandbox, audit |
| `soc2` | SOC 2 Type II | strict taint, audit with integrity verification |
| `pci_dss` | PCI DSS v4.0 | deny-by-default, full taint, sandbox |
| `gdpr` | GDPR Article 25 | full taint (PII focus), retroactive invalidation |
| `fedramp` | FedRAMP High | deny-by-default, full taint, sandbox, eBPF monitoring |

---

## Scenario 4: Incident Response — Retroactive Invalidation

**Problem:** You discover that a data source was compromised 2 hours ago. All data derived since then is untrustworthy.

**Solution:** Retroactive taint invalidation cascades through the trust graph.

```python
from mcpkernel.trust.causal_graph import CausalTrustGraph
from mcpkernel.trust.retroactive import RetroactiveTaintEngine
from mcpkernel.taint.tracker import TaintTracker, TaintLabel

# Build the graph of what happened
graph = CausalTrustGraph()
graph.add_node("compromised_api", server_name="external")
graph.add_node("cache_result", server_name="cache")
graph.add_node("generate_report", server_name="reporting")
graph.add_node("email_report", server_name="email")

graph.add_edge("compromised_api", "cache_result")
graph.add_edge("cache_result", "generate_report")
graph.add_edge("generate_report", "email_report")

# Retroactive invalidation
taint_tracker = TaintTracker()
retroactive = RetroactiveTaintEngine(graph=graph, taint_tracker=taint_tracker)

event = retroactive.invalidate_source(
    "compromised_api",
    reason="API key leaked — data may be poisoned",
    taint_label=TaintLabel.UNTRUSTED_EXTERNAL,
    penalize=True,
    penalty_factor=0.0,
)

print(f"Invalidated: {event.affected_nodes}")
# Output: Invalidated: ['cache_result', 'generate_report', 'email_report']

# Check the damage
for nid in ["compromised_api", "cache_result", "generate_report", "email_report"]:
    node = graph._nodes[nid]
    print(f"  {nid}: status={node.status.value}, trust={node.trust.current():.2f}")
# Output:
#   compromised_api: status=invalidated, trust=0.00
#   cache_result: status=invalidated, trust=0.00
#   generate_report: status=invalidated, trust=0.00
#   email_report: status=invalidated, trust=0.00

# Trace the contamination chain
chain = retroactive.get_contamination_chain("email_report")
print(f"\nContamination chain: {chain}")
# Output: Contamination chain: ['generate_report', 'cache_result', 'compromised_api']
```

---

## Scenario 5: Behavioral Anomaly Detection

**Problem:** A tool starts behaving differently — calling more frequently, with larger payloads.

**Solution:** Behavioral fingerprinting detects the anomaly.

```python
from mcpkernel.trust.behavioral import (
    AnomalyDetector,
    ToolCallFeatures,
)

detector = AnomalyDetector(sigma_threshold=2.0)

# Register the entity
detector.register_entity("filesystem-read")

# Train baseline (normal behavior)
for i in range(20):
    normal = ToolCallFeatures(
        call_count=1,
        avg_latency=0.05 + (i * 0.001),
        error_rate=0.0,
        unique_tools=1,
        avg_args_size=50 + i,
        max_args_size=100,
        unique_arg_keys=3,
        taint_ratio=0.0,
        cross_server_calls=0,
        time_span_seconds=1.0,
    )
    alerts = detector.observe("filesystem-read", normal)

# Anomalous behavior — huge payload, high error rate
anomalous = ToolCallFeatures(
    call_count=50,          # 50x normal
    avg_latency=2.5,        # 50x normal
    error_rate=0.8,         # 80% errors
    unique_tools=1,
    avg_args_size=50000,    # 1000x normal
    max_args_size=100000,
    unique_arg_keys=3,
    taint_ratio=0.9,        # 90% tainted
    cross_server_calls=10,  # new cross-server calls
    time_span_seconds=1.0,
)
alerts = detector.observe("filesystem-read", anomalous)

print(f"Anomaly alerts: {len(alerts)}")
for alert in alerts:
    print(f"  {alert}")
# Output:
# Anomaly alerts: 5
#   call_count: z=48.2 (threshold: 2.0)
#   avg_latency: z=47.5 (threshold: 2.0)
#   error_rate: z=16.0 (threshold: 2.0)
#   avg_args_size: z=970.1 (threshold: 2.0)
#   taint_ratio: z=18.0 (threshold: 2.0)
```

!!! tip "Connect to the Trust Graph"
    When the `AnomalyDetector` fires alerts, you can automatically penalize the corresponding trust graph node:
    
    ```python
    if alerts:
        graph.penalize_node("read_file", factor=0.3, reason="Behavioral anomaly detected")
    ```

# Retroactive Taint Invalidation

Standard taint analysis propagates *forward* at call time. Retroactive taint propagates *backward in time* — when you discover a source was compromised, all data derived since that compromise is marked as suspect.

---

## The Problem

```
Time 0: Agent reads config from MCP server → passes validation → deploys app
Time 1: You discover the MCP server was compromised at Time 0
```

Normal taint tracking can't help — the data already flowed through. Retroactive invalidation solves this by:

1. Tracing all downstream nodes in the Causal Trust Graph
2. Applying taint labels to every node that consumed the bad data
3. Recording the invalidation event for audit

---

## Tutorial: Basic Retroactive Invalidation

### Step 1: Build a causal graph with a hidden compromise

```python
from mcpkernel.trust.causal_graph import CausalTrustGraph
from mcpkernel.trust.retroactive import RetroactiveTaintEngine

# Build the graph
graph = CausalTrustGraph(decay_rate=0.01)

# Simulate a workflow that already happened
source = graph.add_node(
    "fetch_config",
    "external-server",
    output_hash="abc123",
)
parser = graph.add_node(
    "parse_config",
    "data-tools",
    output_hash="def456",
)
deployer = graph.add_node(
    "deploy_app",
    "k8s-server",
    output_hash="ghi789",
)

graph.add_edge(source.node_id, parser.node_id, edge_type="data_flow")
graph.add_edge(parser.node_id, deployer.node_id, edge_type="data_flow")

print("Before invalidation:")
for nid in [source.node_id, parser.node_id, deployer.node_id]:
    node = graph.get_node(nid)
    print(f"  {node.tool_name}: status={node.status}, taint={node.taint_labels}")
```

Output:

```
Before invalidation:
  fetch_config: status=trusted, taint=set()
  parse_config: status=trusted, taint=set()
  deploy_app: status=trusted, taint=set()
```

### Step 2: Discover the compromise and retroactively invalidate

```python
from mcpkernel.taint.tracker import TaintLabel

# Create the retroactive engine
retro = RetroactiveTaintEngine(graph)

# Discover that fetch_config was compromised!
event = retro.invalidate_source(
    source.node_id,
    reason="server_compromised_via_supply_chain",
    taint_label=TaintLabel.UNTRUSTED_EXTERNAL,
    penalize=True,
    penalty_factor=0.1,
)

print(f"\nInvalidation event:")
print(f"  Source: {event.source_node_id[:12]}…")
print(f"  Affected nodes: {len(event.affected_node_ids)}")
print(f"  Reason: {event.reason}")
print(f"  Labels applied: {len(event.taint_labels_applied)}")
```

Output:

```
Invalidation event:
  Source: req_a1b2c3d4…
  Affected nodes: 2
  Reason: server_compromised_via_supply_chain
  Labels applied: 3
```

### Step 3: Check the damage

```python
print("\nAfter invalidation:")
for nid in [source.node_id, parser.node_id, deployer.node_id]:
    node = graph.get_node(nid)
    print(f"  {node.tool_name}:")
    print(f"    status={node.status}")
    print(f"    taint={node.taint_labels}")
    print(f"    trust={node.trust.current():.4f}")
```

Output:

```
After invalidation:
  fetch_config:
    status=invalidated
    taint={'untrusted_external', 'retroactive_invalidation'}
    trust=0.9900
  parse_config:
    status=invalidated
    taint={'retroactive_invalidation', 'untrusted_external'}
    trust=0.0990
  deploy_app:
    status=invalidated
    taint={'retroactive_invalidation', 'untrusted_external'}
    trust=0.0990
```

All three nodes are now invalidated, tainted, and their trust scores penalized.

---

## Tutorial: Trace the Contamination Chain

After invalidation, trace how taint reached a specific node:

```python
chain = retro.get_contamination_chain(deployer.node_id)
print(f"Contamination chain for deploy_app ({len(chain)} nodes):")
for entry in chain:
    print(f"  {entry['tool_name']} [{entry['server_name']}]")
    print(f"    trust: {entry['trust']:.4f}")
    print(f"    status: {entry['status']}")
    print(f"    taint: {entry['taint_labels']}")
```

Output:

```
Contamination chain for deploy_app (3 nodes):
  deploy_app [k8s-server]
    trust: 0.0990
    status: compromised
    taint: ['retroactive_invalidation', 'untrusted_external']
  parse_config [data-tools]
    trust: 0.0990
    status: compromised
    taint: ['retroactive_invalidation', 'untrusted_external']
  fetch_config [external-server]
    trust: 0.9900
    status: compromised
    taint: ['retroactive_invalidation', 'untrusted_external']
```

---

## Tutorial: Integration with TaintTracker

The retroactive engine can work with MCPKernel's `TaintTracker` to mark data in the taint tracking system:

```python
from mcpkernel.taint.tracker import TaintTracker, TaintLabel
from mcpkernel.trust.causal_graph import CausalTrustGraph
from mcpkernel.trust.retroactive import RetroactiveTaintEngine

# Create tracker and graph
tracker = TaintTracker()
graph = CausalTrustGraph()

source = graph.add_node("read_secret", "vault", output_hash="vault-data-001")
consumer = graph.add_node("send_email", "email-server", output_hash="email-out-001")
graph.add_edge(source.node_id, consumer.node_id)

# Retroactive engine with tracker integration
retro = RetroactiveTaintEngine(graph, taint_tracker=tracker)

# Invalidate the source
event = retro.invalidate_source(
    source.node_id,
    reason="vault_key_leaked",
    taint_label=TaintLabel.SECRET,
)

# The taint tracker now has entries for the compromised data
print(f"Taint tracker summary: {tracker.summary()}")
```

Output:

```python
{
    'total_tracked': 2,
    'active_tainted': 2,
    'by_label': {'secret': 2},
    'sanitizers': []
}
```

---

## Summary

```python
summary = retro.summary()
print(summary)
```

Output:

```python
{
    'invalidation_events': 1,
    'total_affected_nodes': 1,
    'taint_tracker': {
        'total_tracked': 2,
        'active_tainted': 2,
        'by_label': {'secret': 2},
        'sanitizers': []
    }
}
```

---

## When to Use Retroactive Invalidation

| Scenario | Action |
|----------|--------|
| MCP server was compromised | Invalidate all its nodes |
| API key was leaked | Invalidate nodes that used it |
| Supply chain attack on dependency | Invalidate all runs using that dependency |
| Data source found to contain PII | Retroactively taint all derived data |
| Compliance audit (right to erasure) | Trace and invalidate all data derived from a user's input |

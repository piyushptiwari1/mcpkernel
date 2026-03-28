# Causal Trust Graph (CTG)

The Causal Trust Graph is MCPKernel's novel trust framework. It models tool-call causality as a directed graph where each node is a tool invocation and edges encode data-flow dependencies. Trust scores decay exponentially over time and can be retroactively invalidated.

---

## The Core Idea

Traditional security treats each tool call independently. But in agentic workflows, **tool outputs become inputs to other tools** — creating causal chains:

```
Agent asks: "Read config.json, then deploy based on its contents"

read_file("config.json") → parse_json(output) → deploy_service(parsed_config)
     Node A ─────────────────→ Node B ──────────────→ Node C
```

If `read_file` was compromised (returned malicious config), then `parse_json` processed bad data, and `deploy_service` deployed a compromised service. **All three nodes are tainted.**

The CTG tracks this causality so you can:

1. **Forward propagate** — taint from Node A automatically flows to B and C
2. **Retroactive invalidate** — if you discover A was bad *after the fact*, cascade invalidation to B and C
3. **Compute minimum privileges** — observe what permissions tools actually used

---

## Trust Decay Formula

Trust follows an exponential decay model:

$$T(t) = T_0 \cdot e^{-\lambda(t - t_0)} \cdot \prod w(v_i)$$

Where:

| Symbol | Meaning | Default |
|--------|---------|---------|
| $T_0$ | Initial trust (0.0 to 1.0) | 1.0 |
| $\lambda$ | Decay rate (per-second) | 0.01 |
| $t_0$ | Last verification time | now |
| $w(v_i)$ | Verification event weights | 1.0 each |

**Verification events** (like successful audits) reset the decay timer. **Penalties** (like policy violations) add low-weight events that reduce trust immediately.

---

## Tutorial: Building Your First Trust Graph

### Step 1: Create the graph

```python
from mcpkernel.trust.causal_graph import CausalTrustGraph

# Create a graph with 1% per-second decay
graph = CausalTrustGraph(decay_rate=0.01)

# Add tool invocation nodes
node_a = graph.add_node(
    tool_name="read_file",
    server_name="filesystem",
    permissions={"fs:read"},
)
print(f"Node A: {node_a.node_id[:12]}…")
print(f"  Tool: {node_a.tool_name}")
print(f"  Trust: {node_a.trust.current():.4f}")
print(f"  Status: {node_a.status}")
```

Output:

```
Node A: req_a1b2c3d4…
  Tool: read_file
  Trust: 1.0000
  Status: trusted
```

### Step 2: Add more nodes and connect them

```python
node_b = graph.add_node(
    tool_name="parse_json",
    server_name="data-tools",
    permissions={"data:parse"},
)

node_c = graph.add_node(
    tool_name="deploy_service",
    server_name="deployment",
    permissions={"deploy:write", "deploy:restart"},
)

# Connect the causal chain: A → B → C
edge_ab = graph.add_edge(
    node_a.node_id,
    node_b.node_id,
    edge_type="data_flow",
    data_fields=["file_content"],
)
edge_bc = graph.add_edge(
    node_b.node_id,
    node_c.node_id,
    edge_type="data_flow",
    data_fields=["parsed_config"],
)

print(f"Graph: {graph.node_count} nodes, {graph.edge_count} edges")
# Output: Graph: 3 nodes, 2 edges
```

### Step 3: Add taint and see it propagate

```python
# Add a node with taint labels
tainted_node = graph.add_node(
    tool_name="fetch_url",
    server_name="http-client",
    taint_labels={"untrusted_external"},
)

clean_node = graph.add_node(
    tool_name="process_response",
    server_name="data-tools",
)

# When you add an edge FROM a tainted node, taint propagates forward
graph.add_edge(tainted_node.node_id, clean_node.node_id, edge_type="data_flow")

print(f"clean_node taint: {clean_node.taint_labels}")
# Output: clean_node taint: {'untrusted_external'}
# ^^^ Taint propagated automatically!
```

---

## Tutorial: Trust Verification and Penalties

### Verify a node (resets decay timer)

```python
import time

# Initially trust is 1.0
print(f"Before: {node_a.trust.current():.4f}")  # Output: Before: 1.0000

# Simulate time passing (trust decays)
time.sleep(2)
print(f"After 2s: {node_a.trust.current():.4f}")  # Output: After 2s: ~0.9802

# Verify the node — resets the decay timer
graph.verify_node(node_a.node_id, weight=1.0)
print(f"After verify: {node_a.trust.current():.4f}")  # Output: After verify: ~0.9802
# (Score stays the same, but timer is reset — future decay starts from now)
```

### Penalize a node

```python
# Apply a penalty (reduces trust immediately)
graph.penalize_node(node_c.node_id, factor=0.3)  # Multiply trust by 0.3

print(f"deploy_service trust: {node_c.trust.current():.4f}")
# Output: deploy_service trust: ~0.2941
print(f"deploy_service status: {node_c.trust.status()}")
# Output: deploy_service status: suspicious
```

### Trust status thresholds

| Score Range | Status |
|-------------|--------|
| ≥ 0.7 | `trusted` |
| 0.3 – 0.7 | `degraded` |
| 0.1 – 0.3 | `suspicious` |
| < 0.1 | `compromised` |

---

## Tutorial: Retroactive Invalidation

**The novel part**: When you discover a node was compromised *after the fact*, invalidate it and automatically cascade to all downstream nodes.

```python
from mcpkernel.trust.causal_graph import CausalTrustGraph, NodeStatus

graph = CausalTrustGraph(decay_rate=0.01)

# Build a chain: A → B → C → D
a = graph.add_node("fetch_config", "config-server")
b = graph.add_node("validate_config", "validator")
c = graph.add_node("apply_config", "deployer")
d = graph.add_node("restart_service", "deployer")

graph.add_edge(a.node_id, b.node_id)
graph.add_edge(b.node_id, c.node_id)
graph.add_edge(c.node_id, d.node_id)

# Later: discover that fetch_config was serving malicious data
invalidated = graph.invalidate_node(a.node_id)

print(f"Invalidated {len(invalidated)} nodes:")
for nid in invalidated:
    node = graph.get_node(nid)
    print(f"  {node.tool_name}: status={node.status}, taint={node.taint_labels}")
```

Output:

```
Invalidated 4 nodes:
  fetch_config: status=invalidated, taint={'retroactive_invalidation'}
  validate_config: status=invalidated, taint={'retroactive_invalidation'}
  apply_config: status=invalidated, taint={'retroactive_invalidation'}
  restart_service: status=invalidated, taint={'retroactive_invalidation'}
```

!!! warning "Invalidation is Permanent"
    Once a node is invalidated, it stays invalidated. Even `verify_node()` won't restore it. This is by design — you can't un-compromise data.

---

## Tutorial: Causal Chain Analysis

### Get the full ancestry of a node (backward traversal)

```python
# What caused node D?
chain = graph.get_causal_chain(d.node_id)
print(f"Causal chain for restart_service ({len(chain)} nodes):")
for nid in chain:
    node = graph.get_node(nid)
    print(f"  {node.tool_name} [{node.server_name}]")
```

Output:

```
Causal chain for restart_service (4 nodes):
  restart_service [deployer]
  apply_config [deployer]
  validate_config [validator]
  fetch_config [config-server]
```

### Get all downstream nodes

```python
# What depends on node A's output?
downstream = graph.get_downstream(a.node_id)
print(f"Downstream from fetch_config: {len(downstream)} nodes")
for nid in downstream:
    node = graph.get_node(nid)
    print(f"  {node.tool_name}")
```

Output:

```
Downstream from fetch_config: 3 nodes
  validate_config
  apply_config
  restart_service
```

---

## Tutorial: Minimum Privilege Computation

MCPKernel observes what permissions tools *actually use* and computes the provably minimal permission set:

```python
graph = CausalTrustGraph()

# Simulate a server making multiple calls with different permissions
graph.add_node("fs_read", "filesystem", permissions={"fs:read"})
graph.add_node("fs_list", "filesystem", permissions={"fs:read", "fs:list"})
graph.add_node("fs_write", "filesystem", permissions={"fs:write"})
graph.add_node("fs_delete", "filesystem", permissions={"fs:delete"})

# Compute: what permissions did "filesystem" server actually use?
min_perms = graph.compute_minimum_privileges("filesystem")
print(f"Minimum privileges for 'filesystem': {sorted(min_perms)}")
```

Output:

```
Minimum privileges for 'filesystem': ['fs:delete', 'fs:list', 'fs:read', 'fs:write']
```

Then compare against what was *granted* to find over-provisioning.

---

## Tutorial: Graph Summary and Export

### Get a trust summary

```python
summary = graph.get_trust_summary()
print(summary)
```

Output:

```python
{
    'total_nodes': 4,
    'total_edges': 0,
    'invalidated': 0,
    'status_distribution': {'trusted': 4},
    'low_trust_nodes': []
}
```

### Export the graph as JSON

```python
import json

data = graph.to_dict()
print(json.dumps(data, indent=2))
```

Output:

```json
{
  "nodes": {
    "req_abc123": {
      "tool": "fs_read",
      "server": "filesystem",
      "status": "trusted",
      "trust_score": 0.9998,
      "taint_labels": [],
      "permissions": ["fs:read"],
      "timestamp": 1711612800.0
    }
  },
  "edges": [],
  "summary": {
    "total_nodes": 4,
    "total_edges": 0,
    "invalidated": 0,
    "status_distribution": {"trusted": 4},
    "low_trust_nodes": []
  }
}
```

---

## Full Working Example

```python
"""Complete CTG example: build graph, track trust, invalidate, analyze."""

import time
from mcpkernel.trust.causal_graph import CausalTrustGraph, NodeStatus

def main():
    # 1. Create graph
    graph = CausalTrustGraph(decay_rate=0.01)

    # 2. Build a realistic agent workflow
    read = graph.add_node("read_config", "fs-server", permissions={"fs:read"})
    parse = graph.add_node("parse_yaml", "data-tools", permissions={"data:parse"})
    validate = graph.add_node("validate_schema", "validator", permissions={"schema:validate"})
    deploy = graph.add_node("deploy_app", "k8s-server",
                            permissions={"k8s:deploy", "k8s:restart"})

    graph.add_edge(read.node_id, parse.node_id, edge_type="data_flow")
    graph.add_edge(parse.node_id, validate.node_id, edge_type="data_flow")
    graph.add_edge(validate.node_id, deploy.node_id, edge_type="control_flow")

    print(f"Graph: {graph.node_count} nodes, {graph.edge_count} edges")

    # 3. Verify trusted nodes
    graph.verify_node(read.node_id, weight=1.0)
    graph.verify_node(parse.node_id, weight=0.9)

    # 4. Penalize suspicious node
    graph.penalize_node(validate.node_id, factor=0.5)

    # 5. Check statuses
    statuses = graph.update_all_statuses()
    for nid, status in statuses.items():
        node = graph.get_node(nid)
        score = node.trust.current()
        print(f"  {node.tool_name}: trust={score:.3f}, status={status}")

    # 6. Discover compromise — invalidate and cascade
    print("\n--- Discovering compromise in read_config ---")
    invalidated = graph.invalidate_node(read.node_id)
    print(f"Cascade invalidated {len(invalidated)} nodes")

    # 7. Final summary
    print(f"\nFinal summary: {graph.get_trust_summary()}")

main()
```

Output:

```
Graph: 4 nodes, 3 edges
  read_config: trust=1.000, status=trusted
  parse_yaml: trust=0.900, status=trusted
  validate_schema: trust=0.500, status=degraded
  deploy_app: trust=1.000, status=trusted

--- Discovering compromise in read_config ---
Cascade invalidated 4 nodes

Final summary: {'total_nodes': 4, 'total_edges': 3, 'invalidated': 4,
'status_distribution': {'invalidated': 4}, 'low_trust_nodes': [...]}
```

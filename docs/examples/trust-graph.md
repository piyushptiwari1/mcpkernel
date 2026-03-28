# Trust Graph Examples

Complete examples showing MCPKernel's Causal Trust Graph — from basic node creation to retroactive invalidation cascades.

---

## Example 1: Create a Trust Graph

```python
from mcpkernel.trust.causal_graph import CausalTrustGraph

graph = CausalTrustGraph()

# Add tool nodes
graph.add_node("read_file", server_name="filesystem")
graph.add_node("parse_csv", server_name="analytics")
graph.add_node("http_post", server_name="api-gateway")

print(f"Nodes: {len(graph._nodes)}")
for nid, node in graph._nodes.items():
    print(f"  {nid}: trust={node.trust.current():.2f}, status={node.status.value}")
```

Output:

```
Nodes: 3
  read_file: trust=1.00, status=trusted
  parse_csv: trust=1.00, status=trusted
  http_post: trust=1.00, status=trusted
```

---

## Example 2: Add Edges and Watch Taint Propagate

When you connect nodes with edges, taint labels propagate automatically along the data flow:

```python
from mcpkernel.trust.causal_graph import CausalTrustGraph
from mcpkernel.taint.tracker import TaintLabel

graph = CausalTrustGraph()

# Build a data pipeline
graph.add_node("read_db", server_name="database", taint_labels={TaintLabel.PII})
graph.add_node("transform", server_name="analytics")
graph.add_node("send_email", server_name="email")

# Connect: read_db → transform → send_email
graph.add_edge("read_db", "transform", edge_type="data_flow")
graph.add_edge("transform", "send_email", edge_type="data_flow")

# Check: did PII propagate?
for nid in ["read_db", "transform", "send_email"]:
    node = graph._nodes[nid]
    labels = sorted(str(l) for l in node.taint_labels)
    print(f"  {nid}: taint={labels}")
```

Output:

```
  read_db: taint=['pii']
  transform: taint=['pii']
  send_email: taint=['pii']
```

!!! warning "Automatic propagation"
    Taint propagates forward through edges. When `read_db` has PII and connects to `transform`, the PII label flows downstream automatically. This means `send_email` knows it's handling PII — the policy engine can block it.

---

## Example 3: Trust Decay Over Time

Trust scores decay exponentially. Nodes that aren't verified regularly lose trust:

```python
import time
from mcpkernel.trust.causal_graph import CausalTrustGraph

graph = CausalTrustGraph()
graph.add_node("api_tool", server_name="external-api")

node = graph._nodes["api_tool"]
print(f"Initial trust: {node.trust.current():.4f}")
# Output: Initial trust: 1.0000

# Simulate time passing (trust decays)
node.trust._last_verified = time.time() - 3600  # 1 hour ago
print(f"After 1 hour: {node.trust.current():.4f}")
# Output: After 1 hour: ~0.9950 (depends on decay rate)
```

---

## Example 4: Verify and Penalize

```python
from mcpkernel.trust.causal_graph import CausalTrustGraph

graph = CausalTrustGraph()
graph.add_node("read_file", server_name="filesystem")

# Verify — boosts trust back to 1.0
graph.verify_node("read_file")
node = graph._nodes["read_file"]
print(f"After verify: trust={node.trust.current():.2f}, status={node.status.value}")
# Output: After verify: trust=1.00, status=trusted

# Penalize — reduces trust
graph.penalize_node("read_file", factor=0.5, reason="suspicious activity")
print(f"After penalize: trust={node.trust.current():.2f}, status={node.status.value}")
# Output: After penalize: trust=0.50, status=degraded
```

Trust thresholds:

| Trust Score | Status |
|-------------|--------|
| >= 0.7 | `trusted` |
| 0.3 - 0.7 | `degraded` |
| 0.1 - 0.3 | `suspicious` |
| < 0.1 | `compromised` |

---

## Example 5: Retroactive Invalidation Cascade

When a source is compromised, MCPKernel invalidates all downstream nodes:

```python
from mcpkernel.trust.causal_graph import CausalTrustGraph

graph = CausalTrustGraph()

# Build a chain: source → process → output → report
graph.add_node("source_db", server_name="database")
graph.add_node("etl_process", server_name="analytics")
graph.add_node("generate_output", server_name="analytics")
graph.add_node("publish_report", server_name="reports")

graph.add_edge("source_db", "etl_process")
graph.add_edge("etl_process", "generate_output")
graph.add_edge("generate_output", "publish_report")

# Compromise the source!
graph.invalidate_node("source_db", reason="Data breach detected")

# Check: everything downstream is invalidated
for nid in ["source_db", "etl_process", "generate_output", "publish_report"]:
    node = graph._nodes[nid]
    print(f"  {nid}: status={node.status.value}, trust={node.trust.current():.2f}")
```

Output:

```
  source_db: status=invalidated, trust=0.00
  etl_process: status=invalidated, trust=0.00
  generate_output: status=invalidated, trust=0.00
  publish_report: status=invalidated, trust=0.00
```

!!! danger "Cascade is permanent"
    `invalidate_node()` uses BFS to mark all downstream nodes as `INVALIDATED` with trust 0.0. This is **permanent** — invalidated nodes cannot be re-verified. This models the real-world scenario where compromised data sources make all derived data untrustworthy.

---

## Example 6: Causal Chain Analysis

Trace a node back to its root data sources:

```python
from mcpkernel.trust.causal_graph import CausalTrustGraph

graph = CausalTrustGraph()

graph.add_node("user_input", server_name="chat")
graph.add_node("llm_call", server_name="openai")
graph.add_node("tool_call", server_name="tools")
graph.add_node("final_response", server_name="output")

graph.add_edge("user_input", "llm_call")
graph.add_edge("llm_call", "tool_call")
graph.add_edge("tool_call", "final_response")

# Trace backwards from final_response
chain = graph.get_causal_chain("final_response")
print(f"Causal chain: {chain}")
# Output: Causal chain: ['tool_call', 'llm_call', 'user_input']

# Trace forward from user_input
downstream = graph.get_downstream("user_input")
print(f"Downstream: {downstream}")
# Output: Downstream: ['llm_call', 'tool_call', 'final_response']
```

---

## Example 7: Minimum Privileges

Derive the minimal set of permissions a server needs based on its observed tool calls:

```python
from mcpkernel.trust.causal_graph import CausalTrustGraph

graph = CausalTrustGraph()

graph.add_node("read_file", server_name="filesystem", permissions={"fs:read"})
graph.add_node("list_dir", server_name="filesystem", permissions={"fs:list"})
graph.add_node("write_file", server_name="filesystem", permissions={"fs:write"})
graph.add_node("http_get", server_name="api", permissions={"net:outbound"})

min_privs = graph.compute_minimum_privileges("filesystem")
print(f"Minimum privileges for 'filesystem': {sorted(min_privs)}")
# Output: Minimum privileges for 'filesystem': ['fs:list', 'fs:read', 'fs:write']
```

---

## Example 8: Export Graph as JSON

```python
import json
from mcpkernel.trust.causal_graph import CausalTrustGraph

graph = CausalTrustGraph()
graph.add_node("read_file", server_name="filesystem")
graph.add_node("transform", server_name="analytics")
graph.add_edge("read_file", "transform")

data = graph.to_dict()
print(json.dumps(data, indent=2, default=str))
```

Output:

```json
{
  "read_file": {
    "tool_name": "read_file",
    "server_name": "filesystem",
    "status": "trusted",
    "trust": 1.0,
    "taint_labels": [],
    "permissions": []
  },
  "transform": {
    "tool_name": "transform",
    "server_name": "analytics",
    "status": "trusted",
    "trust": 1.0,
    "taint_labels": [],
    "permissions": []
  }
}
```

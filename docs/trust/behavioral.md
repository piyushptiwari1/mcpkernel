# Behavioral Fingerprinting

Behavioral fingerprinting builds a statistical profile of "normal" tool-call patterns for each agent or server, then flags deviations using z-score anomaly detection.

---

## What It Detects

| Feature | What It Measures | Example Anomaly |
|---------|-----------------|----------------|
| `total_calls` | Number of tool calls in a session | Agent suddenly makes 10x more calls |
| `unique_tools` | Distinct tools used | Agent uses tools it never used before |
| `max_fan_out` | Max children of any single node | One tool output fans to 20 downstream tools |
| `max_depth` | Longest causal chain | Call depth jumps from 3 to 15 |
| `delegation_count` | Tool→tool delegations | Unusual cross-tool delegation pattern |
| `call_rate` | Calls per second | Burst of calls after quiet period |
| `distinct_servers` | Unique servers contacted | Agent starts talking to unknown servers |
| `permission_diversity` | Unique permissions used | Agent suddenly uses admin permissions |

---

## Tutorial: Build a Behavioral Baseline

### Step 1: Create a fingerprint and record normal observations

```python
from mcpkernel.trust.behavioral import (
    AnomalyDetector,
    BehavioralFingerprint,
    ToolCallFeatures,
)

# Create a fingerprint for an agent
fp = BehavioralFingerprint(
    entity_id="coding-agent",
    entity_type="agent",
)

# Record 10 "normal" observations
for _ in range(10):
    normal_features = ToolCallFeatures(
        total_calls=5,
        unique_tools=3,
        max_fan_out=2,
        max_depth=2,
        delegation_count=0,
        data_flow_count=4,
        avg_trust_score=0.95,
        call_rate=1.0,
        distinct_servers=2,
        permission_diversity=3,
    )
    fp.record(normal_features)

print(f"Baseline observations: {len(fp.history)}")
# Output: Baseline observations: 10
```

### Step 2: Check z-scores against an anomalous observation

```python
# Create an anomalous observation — way more calls, tools, and servers
anomalous = ToolCallFeatures(
    total_calls=50,          # 10x normal!
    unique_tools=15,         # 5x normal!
    max_fan_out=10,          # 5x normal!
    max_depth=8,             # 4x normal!
    delegation_count=5,      # New delegations!
    data_flow_count=40,      # 10x normal!
    avg_trust_score=0.4,     # Much lower trust
    call_rate=10.0,          # 10x call rate!
    distinct_servers=8,      # 4x servers!
    permission_diversity=12, # 4x permissions!
)

z_scores = fp.z_scores(anomalous)
print("Z-scores for anomalous observation:")
for feature, z in sorted(z_scores.items(), key=lambda x: abs(x[1]), reverse=True):
    flag = " ⚠️ ANOMALY" if abs(z) > 2.5 else ""
    print(f"  {feature:25s}: z={z:+8.3f}{flag}")
```

Output:

```
Z-scores for anomalous observation:
  total_calls              : z= +45.000 ⚠️ ANOMALY
  data_flow_count          : z= +36.000 ⚠️ ANOMALY
  call_rate                : z=  +9.000 ⚠️ ANOMALY
  permission_diversity     : z=  +9.000 ⚠️ ANOMALY
  unique_tools             : z= +12.000 ⚠️ ANOMALY
  max_fan_out              : z=  +8.000 ⚠️ ANOMALY
  max_depth                : z=  +6.000 ⚠️ ANOMALY
  distinct_servers         : z=  +6.000 ⚠️ ANOMALY
  delegation_count         : z=  +5.000 ⚠️ ANOMALY
  avg_trust_score          : z=  -5.500 ⚠️ ANOMALY
```

---

## Tutorial: Using the AnomalyDetector

The `AnomalyDetector` automates baseline building and anomaly detection:

```python
from mcpkernel.trust.behavioral import AnomalyDetector, ToolCallFeatures

detector = AnomalyDetector(
    sigma_threshold=2.5,     # Flag if |z-score| > 2.5
    min_observations=5,      # Need at least 5 baseline observations
)

# Register an entity for monitoring
detector.register_entity("my-agent", entity_type="agent")

# Build baseline with 6 normal observations
for i in range(6):
    normal = ToolCallFeatures(
        total_calls=5,
        unique_tools=3,
        max_fan_out=2,
        max_depth=2,
        call_rate=1.0,
        distinct_servers=2,
    )
    anomalies = detector.observe("my-agent", normal)
    print(f"Observation {i+1}: {len(anomalies)} anomalies")
```

Output:

```
Observation 1: 0 anomalies
Observation 2: 0 anomalies
Observation 3: 0 anomalies
Observation 4: 0 anomalies
Observation 5: 0 anomalies
Observation 6: 0 anomalies
```

### Now submit an anomalous observation

```python
# Something suspicious: 50 calls to 10 servers
suspicious = ToolCallFeatures(
    total_calls=50,
    unique_tools=15,
    max_fan_out=10,
    max_depth=8,
    call_rate=10.0,
    distinct_servers=10,
)

anomalies = detector.observe("my-agent", suspicious)
print(f"\n🚨 Anomalies detected: {len(anomalies)}")
for a in anomalies:
    print(f"  Feature: {a['feature']}")
    print(f"  Z-score: {a['z_score']}")
    print(f"  Observed: {a['observed']}")
    print(f"  Threshold: {a['threshold']}")
    print()
```

Output:

```
🚨 Anomalies detected: 6
  Feature: total_calls
  Z-score: 45.0
  Observed: 50
  Threshold: 2.5

  Feature: unique_tools
  Z-score: 12.0
  Observed: 15
  Threshold: 2.5

  Feature: max_fan_out
  Z-score: 8.0
  Observed: 10
  Threshold: 2.5
  ...
```

### Check the anomaly log

```python
print(f"Total anomalies logged: {len(detector.anomaly_log)}")
print(f"Summary: {detector.summary()}")
```

Output:

```python
Total anomalies logged: 6
{
    'monitored_entities': 1,
    'total_anomalies': 6,
    'sigma_threshold': 2.5,
    'min_observations': 5
}
```

---

## Tutorial: Extract Features from a Causal Trust Graph

Instead of building features manually, extract them from an actual CTG:

```python
from mcpkernel.trust.causal_graph import CausalTrustGraph
from mcpkernel.trust.behavioral import extract_features

# Build a graph with some tool calls
graph = CausalTrustGraph(decay_rate=0.01)
a = graph.add_node("read_file", "filesystem", permissions={"fs:read"})
b = graph.add_node("parse_json", "data-tools", permissions={"data:parse"})
c = graph.add_node("http_post", "http-client", permissions={"net:write"})
graph.add_edge(a.node_id, b.node_id, edge_type="data_flow")
graph.add_edge(b.node_id, c.node_id, edge_type="data_flow")

# Extract behavioral features
features = extract_features(graph)
print(f"Total calls: {features.total_calls}")
print(f"Unique tools: {features.unique_tools}")
print(f"Max fan-out: {features.max_fan_out}")
print(f"Max depth: {features.max_depth}")
print(f"Distinct servers: {features.distinct_servers}")
print(f"Permission diversity: {features.permission_diversity}")
print(f"Data flow edges: {features.data_flow_count}")
print(f"Avg trust: {features.avg_trust_score:.4f}")
```

Output:

```
Total calls: 3
Unique tools: 3
Max fan-out: 1
Max depth: 2
Distinct servers: 3
Permission diversity: 3
Data flow edges: 2
Avg trust: 1.0000
```

### Full pipeline: Graph → Features → Anomaly Detection

```python
# Feed extracted features into the anomaly detector
anomalies = detector.observe("my-agent", features)
if anomalies:
    print("⚠️ Anomalous behavior detected!")
else:
    print("✓ Normal behavior")
```

---

## Configuration

```yaml
trust:
  anomaly_sigma: 2.5            # Z-score threshold for flagging
  anomaly_min_observations: 5   # Minimum baseline before alerting
```

### Monitor specific features only

```python
detector = AnomalyDetector(
    sigma_threshold=3.0,
    min_observations=10,
    monitored_features=["total_calls", "distinct_servers", "permission_diversity"],
)
```

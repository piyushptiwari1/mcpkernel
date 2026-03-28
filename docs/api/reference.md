# API Reference

Complete reference for all public Python APIs in MCPKernel.

---

## `mcpkernel` (top-level)

```python
from mcpkernel import (
    MCPKernelProxy,
    POLICY_PRESETS,
    protect,
    __version__,
    # Exceptions
    MCPKernelError,
    PolicyViolation,
    TaintViolation,
    AuthError,
    ConfigError,
    SandboxError,
)
```

---

## MCPKernelProxy

The primary Python API for routing tool calls through the security pipeline.

```python
from mcpkernel import MCPKernelProxy
```

### Constructor

```python
MCPKernelProxy(
    *,
    upstream: list[str | dict] | None = None,
    policy: str | Path | None = "standard",
    taint: bool = True,
    audit: bool = True,
    sandbox: bool = False,
    context_pruning: bool = False,
    config_path: Path | str | None = None,
    host: str = "127.0.0.1",
    port: int = 8080,
)
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `upstream` | list | None | Upstream MCP server URLs or config dicts |
| `policy` | str/Path | `"standard"` | Preset name or path to YAML policy |
| `taint` | bool | True | Enable taint detection |
| `audit` | bool | True | Enable audit logging |
| `sandbox` | bool | False | Enable sandbox execution |
| `context_pruning` | bool | False | Enable context minimization |
| `config_path` | Path | None | Path to YAML config (overrides kwargs) |
| `host` | str | `"127.0.0.1"` | HTTP bind address |
| `port` | int | 8080 | HTTP bind port |

### Methods

#### `await proxy.start() → None`

Initialize the security pipeline and connect to upstreams.

#### `await proxy.stop() → None`

Shut down the pipeline and disconnect.

#### `await proxy.call_tool(tool_name, arguments, *, agent_id="api") → dict`

Route a tool call through the security pipeline.

**Returns:** `{"content": [...], "is_error": bool, "trace_id": str, "metadata": dict}`

**Raises:** `PolicyViolation` if denied, `RuntimeError` if not started.

#### `await proxy.list_tools() → list[dict]`

List all tools from upstream servers.

**Returns:** List of `{"name": str, "description": str, "input_schema": dict}`

### Properties

| Property | Type | Description |
|----------|------|-------------|
| `started` | bool | Whether the proxy has been started |
| `policy_preset` | str | Active preset name |
| `hooks` | list[str] | Registered pipeline hook names |
| `tool_names` | set[str] | Tools available from upstream |

### Context Manager

```python
async with MCPKernelProxy(upstream=["http://..."]) as proxy:
    result = await proxy.call_tool("read_file", {"path": "x"})
```

---

## @protect Decorator

```python
from mcpkernel import protect

@protect(policy="strict", taint=True, audit=True, sandbox=False)
async def my_function(arg: str) -> str:
    return arg
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `policy` | str/Path | `"standard"` | Policy preset or YAML path |
| `taint` | bool | True | Enable taint detection |
| `audit` | bool | True | Enable audit logging |
| `sandbox` | bool | False | Enable sandbox execution |

---

## Policy Engine

```python
from mcpkernel.policy.engine import PolicyEngine, PolicyRule, PolicyAction, PolicyDecision
```

### PolicyAction (enum)

`ALLOW`, `DENY`, `AUDIT`, `SANDBOX`, `WARN`

### PolicyRule

```python
PolicyRule(
    id: str,
    name: str,
    description: str = "",
    action: PolicyAction = PolicyAction.DENY,
    priority: int = 100,
    tool_patterns: list[str] = [],
    argument_patterns: dict[str, str] = {},
    taint_labels: list[str] = [],
    owasp_asi_id: str = "",
    conditions: dict = {},
    enabled: bool = True,
)
```

### PolicyEngine

```python
engine = PolicyEngine(default_action=PolicyAction.ALLOW)
engine.add_rule(rule)
engine.add_rules([rule1, rule2])
engine.remove_rule("rule-id")
decision = engine.evaluate("tool_name", {"arg": "val"}, taint_labels={"pii"})
```

### PolicyDecision

| Property | Type | Description |
|----------|------|-------------|
| `action` | PolicyAction | Final action |
| `matched_rules` | list[PolicyRule] | Rules that matched |
| `reasons` | list[str] | Human-readable reasons |
| `allowed` | bool | Whether the action permits execution |
| `metadata` | dict | Includes `owasp_asi_ids` |

---

## Taint Tracker

```python
from mcpkernel.taint.tracker import TaintTracker, TaintLabel, TaintedValue
```

### TaintLabel (enum)

`SECRET`, `PII`, `LLM_OUTPUT`, `USER_INPUT`, `UNTRUSTED_EXTERNAL`, `CUSTOM`

### TaintTracker

```python
tracker = TaintTracker()
tv = tracker.mark(data, TaintLabel.SECRET, source_id="src")
tracker.get(source_id) → TaintedValue | None
tracker.get_all_tainted() → list[TaintedValue]
tracker.get_by_label(TaintLabel.PII) → list[TaintedValue]
tracker.clear(source_id, TaintLabel.PII, sanitizer="name")
tracker.register_sanitizer("name")
tracker.is_known_sanitizer("name") → bool
tracker.active_taint_count → int
tracker.summary() → dict
```

### TaintedValue

| Property | Type | Description |
|----------|------|-------------|
| `value` | Any | The tainted data |
| `labels` | set[TaintLabel] | Active taint labels |
| `source_id` | str | Unique identifier |
| `provenance` | list[str] | Audit trail |
| `is_tainted` | bool | Whether any labels remain |

---

## Causal Trust Graph

```python
from mcpkernel.trust.causal_graph import (
    CausalTrustGraph, TrustNode, TrustScore, CausalEdge, NodeStatus,
)
```

### CausalTrustGraph

```python
graph = CausalTrustGraph(decay_rate=0.01)
node = graph.add_node("tool", "server", permissions={"p"}, taint_labels={"t"})
graph.get_node(node_id) → TrustNode | None
edge = graph.add_edge(src_id, tgt_id, edge_type="data_flow")
graph.verify_node(node_id, weight=1.0) → bool
graph.penalize_node(node_id, factor=0.5) → bool
graph.invalidate_node(node_id) → list[str]  # cascade
graph.get_causal_chain(node_id) → list[str]  # backward
graph.get_downstream(node_id) → list[str]    # forward
graph.compute_minimum_privileges("server") → set[str]
graph.update_all_statuses() → dict[str, NodeStatus]
graph.get_trust_summary() → dict
graph.to_dict() → dict
```

### NodeStatus (enum)

`TRUSTED`, `DEGRADED`, `SUSPICIOUS`, `COMPROMISED`, `INVALIDATED`

### TrustScore

```python
score = TrustScore(initial=1.0, decay_rate=0.01)
score.current(now=None) → float
score.status(now=None) → NodeStatus
score.verify(weight=1.0)
score.penalize(factor=0.5)
```

---

## Trust Decay Engine

```python
from mcpkernel.trust.trust_decay import TrustDecayEngine, TrustProfile, VerificationEvent
```

```python
engine = TrustDecayEngine(
    server_decay_rate=0.0005,
    tool_decay_rate=0.001,
    agent_decay_rate=0.002,
    alert_threshold=0.3,
)
profile = engine.register("entity-id", "server", initial_trust=1.0)
engine.get_trust("entity-id") → float
engine.verify("entity-id", "audit_pass", weight=1.0)
engine.penalize("entity-id", factor=0.5, reason="violation")
engine.get_profile("entity-id") → TrustProfile | None
engine.get_all_below_threshold(threshold=0.3) → list[tuple[str, float]]
engine.alerts → list[dict]
engine.summary() → dict
```

---

## Behavioral Fingerprinting

```python
from mcpkernel.trust.behavioral import (
    AnomalyDetector, BehavioralFingerprint, ToolCallFeatures, extract_features,
)
```

```python
detector = AnomalyDetector(sigma_threshold=2.5, min_observations=5)
detector.register_entity("agent-id", "agent")
anomalies = detector.observe("agent-id", features) → list[dict]
detector.anomaly_log → list[dict]
detector.summary() → dict

features = extract_features(graph)  # from CausalTrustGraph
```

---

## Retroactive Taint Engine

```python
from mcpkernel.trust.retroactive import RetroactiveTaintEngine, InvalidationEvent
```

```python
retro = RetroactiveTaintEngine(graph, taint_tracker=tracker)
event = retro.invalidate_source(
    node_id, reason="compromised", taint_label=TaintLabel.UNTRUSTED_EXTERNAL,
    penalize=True, penalty_factor=0.1,
)
retro.get_contamination_chain(node_id) → list[dict]
retro.events → list[InvalidationEvent]
retro.summary() → dict
```

---

## Security Guards

```python
from mcpkernel.security import (
    SecurityPipeline, SecurityVerdict,
    ConfusedDeputyGuard, TokenPassthroughGuard, SSRFGuard,
    SessionGuard, MemoryPoisoningGuard,
)
```

### SecurityPipeline

```python
pipeline = SecurityPipeline(
    confused_deputy=ConfusedDeputyGuard(...),
    token_guard=TokenPassthroughGuard(...),
    ssrf_guard=SSRFGuard(...),
    session_guard=SessionGuard(...),
    memory_guard=MemoryPoisoningGuard(...),
)
verdicts = pipeline.check_tool_call("tool", "server", {"args": "val"})
verdicts = pipeline.check_tool_result("tool", "content string")
```

---

## Compliance

```python
from mcpkernel.compliance import apply_preset, get_preset_description, PRESETS, PRESET_NAMES
```

```python
apply_preset("hipaa", settings) → settings
get_preset_description("hipaa") → str
PRESET_NAMES → ["hipaa", "soc2", "pci_dss", "gdpr", "fedramp"]
```

---

## Configuration

```python
from mcpkernel.config import load_config, get_config, MCPKernelSettings
```

```python
settings = load_config(config_path=Path("config.yaml"), overrides={...})
settings = get_config()  # singleton
```

### Key config sections

| Section | Class | Key Fields |
|---------|-------|------------|
| `proxy` | `ProxyConfig` | host, port, workers, cors_origins |
| `policy` | `PolicyConfig` | policy_paths, default_action, hot_reload |
| `taint` | `TaintConfig` | mode, block_on_violation, pii_patterns_enabled |
| `sandbox` | `SandboxConfig` | backend, timeout, max_memory_mb, network_enabled |
| `dee` | `DEEConfig` | enabled, store_path, sign_traces |
| `audit` | `AuditConfig` | enabled, log_path, sign_entries |
| `trust` | `TrustConfig` | enabled, decay_rate, alert_threshold, anomaly_sigma |
| `compliance` | `ComplianceConfig` | preset, custom_rules |
| `auth` | `AuthConfig` | enabled, api_keys, oauth2_jwks_url |
| `upstream` | `list[UpstreamServerConfig]` | name, url, transport, command |

---

## Exceptions

| Exception | Base | When |
|-----------|------|------|
| `MCPKernelError` | Exception | Base for all MCPKernel errors |
| `PolicyViolation` | MCPKernelError | Policy engine denied a tool call |
| `TaintViolation` | MCPKernelError | Taint tracking detected a leak |
| `AuthError` | MCPKernelError | Authentication failed |
| `ConfigError` | MCPKernelError | Configuration is invalid |
| `SandboxError` | MCPKernelError | Sandbox execution failed |

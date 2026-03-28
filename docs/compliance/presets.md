# Compliance Presets

MCPKernel supports one-line regulatory compliance activation. Apply a preset to configure taint tracking, audit logging, trust monitoring, and policy enforcement for your compliance framework.

---

## Available Presets

| Preset | Standard | Key Features |
|--------|----------|-------------|
| `hipaa` | HIPAA Safe Harbor | PII blocking, full taint, signed audit, network isolation |
| `soc2` | SOC 2 Type II | Full audit, authentication, signed traces, observability |
| `pci_dss` | PCI DSS v4.0 | Secret blocking, network isolation, rate limiting, strict trust |
| `gdpr` | GDPR Article 25 | PII detection, data minimization, retroactive invalidation |
| `fedramp` | FedRAMP High | Maximum security — all features enabled |

---

## Tutorial: Apply a Preset

### In Python

```python
from mcpkernel.config import load_config
from mcpkernel.compliance import apply_preset, get_preset_description

# Load default config
settings = load_config()

# See what HIPAA does
print(get_preset_description("hipaa"))
# Output: HIPAA Safe Harbor: Full taint tracking with PII blocking,
#         signed audit logs, signed DEE traces, network isolation,
#         retroactive taint invalidation, deny-by-default policy.

# Apply the preset
settings = apply_preset("hipaa", settings)

# Check what changed
print(f"Taint mode: {settings.taint.mode}")         # full
print(f"Taint blocking: {settings.taint.block_on_violation}")  # True
print(f"PII patterns: {settings.taint.pii_patterns_enabled}")  # True
print(f"Audit enabled: {settings.audit.enabled}")    # True
print(f"Audit signed: {settings.audit.sign_entries}")  # True
print(f"DEE enabled: {settings.dee.enabled}")         # True
print(f"DEE signed: {settings.dee.sign_traces}")      # True
print(f"Trust enabled: {settings.trust.enabled}")     # True
print(f"Retroactive: {settings.trust.retroactive_invalidation}")  # True
print(f"Network: {settings.sandbox.network_enabled}") # False
print(f"Policy: {settings.policy.default_action}")    # deny
```

### In YAML config

```yaml
# config.yaml
compliance:
  preset: hipaa
```

### Via environment variable

```bash
MCPKERNEL__COMPLIANCE__PRESET=hipaa mcpkernel serve
```

---

## What Each Preset Configures

### HIPAA Safe Harbor

```python
from mcpkernel.compliance import PRESETS
import json
print(json.dumps(PRESETS["hipaa"], indent=2))
```

Output:

```json
{
  "taint": {
    "mode": "full",
    "block_on_violation": true,
    "pii_patterns_enabled": true,
    "static_analysis_enabled": true
  },
  "audit": {
    "enabled": true,
    "sign_entries": true
  },
  "dee": {
    "enabled": true,
    "sign_traces": true
  },
  "trust": {
    "enabled": true,
    "retroactive_invalidation": true,
    "alert_threshold": 0.4
  },
  "sandbox": {
    "network_enabled": false
  },
  "policy": {
    "default_action": "deny"
  }
}
```

### SOC 2 Type II

```json
{
  "taint": {"mode": "full", "block_on_violation": true},
  "audit": {"enabled": true, "sign_entries": true},
  "auth": {"enabled": true},
  "dee": {"enabled": true, "sign_traces": true},
  "observability": {"metrics_enabled": true, "tracing_enabled": true},
  "trust": {"enabled": true}
}
```

### PCI DSS v4.0

```json
{
  "taint": {"mode": "full", "block_on_violation": true, "pii_patterns_enabled": true},
  "audit": {"enabled": true, "sign_entries": true},
  "sandbox": {"network_enabled": false, "max_memory_mb": 128},
  "auth": {"enabled": true},
  "rate_limit": {"enabled": true},
  "trust": {"enabled": true, "compromise_threshold": 0.15},
  "policy": {"default_action": "deny"}
}
```

### GDPR Article 25

```json
{
  "taint": {"mode": "full", "block_on_violation": true, "pii_patterns_enabled": true},
  "context": {"enabled": true, "strategy": "aggressive", "max_context_tokens": 2048},
  "audit": {"enabled": true},
  "trust": {"enabled": true, "retroactive_invalidation": true}
}
```

!!! info "GDPR + Retroactive Invalidation"
    GDPR's "right to erasure" maps directly to MCPKernel's retroactive taint invalidation. When a user requests data deletion, you can retroactively invalidate all nodes that consumed their data.

### FedRAMP High

```json
{
  "taint": {"mode": "full", "block_on_violation": true, "pii_patterns_enabled": true, "static_analysis_enabled": true},
  "audit": {"enabled": true, "sign_entries": true},
  "auth": {"enabled": true},
  "sandbox": {"network_enabled": false},
  "ebpf": {"enabled": true},
  "dee": {"enabled": true, "sign_traces": true, "replay_on_drift": true},
  "trust": {"enabled": true, "retroactive_invalidation": true, "alert_threshold": 0.5, "anomaly_sigma": 2.0},
  "policy": {"default_action": "deny"}
}
```

FedRAMP High enables **everything** — including eBPF syscall monitoring, drift replay, and aggressive anomaly detection.

---

## Tutorial: List All Presets

```python
from mcpkernel.compliance import PRESET_NAMES, get_preset_description

for name in PRESET_NAMES:
    desc = get_preset_description(name)
    print(f"\n{name.upper()}")
    print(f"  {desc}")
```

Output:

```
HIPAA
  HIPAA Safe Harbor: Full taint tracking with PII blocking, signed audit
  logs, signed DEE traces, network isolation, retroactive taint
  invalidation, deny-by-default policy.

SOC2
  SOC 2 Type II: Full taint and audit logging, authentication required,
  signed traces, full observability (metrics + tracing), trust monitoring
  enabled.

PCI_DSS
  PCI DSS v4.0: Full taint with PII detection, signed audit, network
  isolation, memory restrictions, authentication and rate limiting,
  strict trust thresholds, deny-by-default.

GDPR
  GDPR Article 25 — Data Protection by Design: Full taint with PII
  detection, aggressive context minimization (2048 tokens), audit
  logging, retroactive taint invalidation for right to erasure.

FEDRAMP
  FedRAMP High: Maximum security — full taint, signed audit,
  authentication required, network isolation, eBPF syscall monitoring,
  signed DEE with drift replay, retroactive taint, aggressive anomaly
  detection (sigma=2.0), deny-by-default policy.
```

---

## Combining Presets with Custom Rules

```python
from mcpkernel.config import load_config
from mcpkernel.compliance import apply_preset

settings = load_config()
settings = apply_preset("hipaa", settings)

# Override specific values after preset
settings.trust.alert_threshold = 0.5  # More aggressive than HIPAA default
settings.sandbox.max_memory_mb = 128  # Tighter resource limits
```

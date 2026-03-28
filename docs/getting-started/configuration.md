# Configuration

MCPKernel uses a hierarchical configuration system. Values load in this order (last wins):

1. **Field defaults** — sensible defaults built in
2. **YAML config file** — `.mcpkernel/config.yaml`
3. **Environment variables** — prefixed `MCPKERNEL_`
4. **CLI overrides** — flags on the command line

---

## Full Config File Example

```yaml
# .mcpkernel/config.yaml

proxy:
  host: 127.0.0.1
  port: 8000
  workers: 1
  cors_origins: []
  max_request_size_bytes: 10485760  # 10 MB

# Upstream MCP servers to proxy to
upstream:
  - name: filesystem
    url: http://localhost:3000/mcp
    transport: streamable_http  # streamable_http | sse | stdio
    timeout_seconds: 30

  - name: github
    url: http://localhost:3001/mcp
    transport: streamable_http
    headers:
      Authorization: "Bearer ${GITHUB_TOKEN}"

  # stdio transport example (e.g., Claude Desktop style)
  - name: local-tools
    transport: stdio
    command: npx
    args: ["@mcp/server-filesystem", "/home/user/docs"]

policy:
  policy_paths:
    - .mcpkernel/policies/default.yaml
    - policies/owasp_asi_2026_strict.yaml
  default_action: deny    # deny | allow | audit
  hot_reload: true        # reload policies when files change

taint:
  mode: full              # full | light | off
  block_on_violation: true
  pii_patterns_enabled: true
  static_analysis_enabled: true
  custom_sources: []
  custom_sinks: []

dee:
  enabled: true
  store_path: .mcpkernel/traces.db
  sign_traces: true       # Sigstore signatures
  replay_on_drift: false

audit:
  enabled: true
  log_path: .mcpkernel/audit.db
  sign_entries: true
  export_format: json     # json | cef | csv

sandbox:
  backend: docker         # docker | firecracker | wasm | microsandbox
  default_timeout_seconds: 30
  max_cpu_cores: 1.0
  max_memory_mb: 256
  max_disk_mb: 512
  network_enabled: false
  docker_image: "python:3.12-slim"

context:
  enabled: true
  strategy: moderate      # aggressive | moderate | conservative
  max_context_tokens: 4096

auth:
  enabled: false
  api_keys: []
  # OAuth2 settings
  oauth2_jwks_url: null
  oauth2_issuer: null
  oauth2_audience: null

rate_limit:
  enabled: false
  requests_per_minute: 60
  burst_size: 10

observability:
  metrics_enabled: true
  metrics_port: 9090
  tracing_enabled: true
  otlp_endpoint: http://localhost:4317
  log_level: INFO
  json_logs: true

trust:
  enabled: true
  decay_rate: 0.001       # default λ (per-second)
  server_decay_rate: 0.0005
  tool_decay_rate: 0.001
  agent_decay_rate: 0.002
  alert_threshold: 0.3
  compromise_threshold: 0.1
  anomaly_sigma: 2.5      # z-score threshold
  anomaly_min_observations: 5
  retroactive_invalidation: true

compliance:
  preset: null            # hipaa | soc2 | pci_dss | gdpr | fedramp | null
  custom_rules: []

ebpf:
  enabled: false
  redirect_ports: [8080]
  monitored_syscalls: [connect, sendto, open, write, execve]
```

---

## Environment Variables

Every config key can be set via environment variables with the `MCPKERNEL_` prefix and `__` as the nesting separator.

```bash
# Set policy default action
export MCPKERNEL__POLICY__DEFAULT_ACTION=deny

# Enable full taint tracking
export MCPKERNEL__TAINT__MODE=full

# Set proxy port
export MCPKERNEL__PROXY__PORT=9000

# Enable HIPAA compliance preset
export MCPKERNEL__COMPLIANCE__PRESET=hipaa

# Set trust decay rate
export MCPKERNEL__TRUST__DECAY_RATE=0.002
```

### Example: Run with environment overrides

```bash
MCPKERNEL__TAINT__MODE=full \
MCPKERNEL__POLICY__DEFAULT_ACTION=deny \
mcpkernel serve -c .mcpkernel/config.yaml
```

---

## Configuration in Python

Load and inspect configuration programmatically:

```python
from mcpkernel.config import load_config, get_config
from pathlib import Path

# Load from a YAML file
settings = load_config(config_path=Path(".mcpkernel/config.yaml"))

# Inspect values
print(f"Proxy: {settings.proxy.host}:{settings.proxy.port}")
print(f"Policy: {settings.policy.default_action}")
print(f"Taint mode: {settings.taint.mode}")
print(f"Trust decay: {settings.trust.decay_rate}")
print(f"Compliance: {settings.compliance.preset}")
```

Output:

```
Proxy: 127.0.0.1:8000
Policy: deny
Taint mode: full
Trust decay: 0.001
Compliance: None
```

### Override programmatically

```python
from mcpkernel.config import load_config

settings = load_config(
    config_path=Path(".mcpkernel/config.yaml"),
    overrides={
        "taint": {"mode": "full", "block_on_violation": True},
        "policy": {"default_action": "deny"},
        "trust": {"decay_rate": 0.005, "alert_threshold": 0.4},
    },
)
print(f"Taint mode: {settings.taint.mode}")
# Output: Taint mode: full
```

---

## Adding Upstream Servers

### Via CLI

```bash
# HTTP transport (most common)
mcpkernel add-server filesystem http://localhost:3000/mcp

# With custom transport
mcpkernel add-server github http://localhost:3001/mcp --transport sse
```

### Via YAML

```yaml
upstream:
  - name: filesystem
    url: http://localhost:3000/mcp
    transport: streamable_http

  - name: github
    url: http://localhost:3001/mcp
    transport: sse
    headers:
      Authorization: "Bearer ghp_xxxx"

  - name: local-tools
    transport: stdio
    command: npx
    args: ["@mcp/server-filesystem", "/home/user"]
```

### Test connectivity

```bash
mcpkernel test-connection -c .mcpkernel/config.yaml
```

Output:

```
Testing upstream servers...
  ✓ filesystem (http://localhost:3000/mcp) — 12 tools available
  ✗ github (http://localhost:3001/mcp) — connection refused
```

---

## Show Effective Config

View the fully resolved configuration (defaults + YAML + env vars):

```bash
mcpkernel config-show -c .mcpkernel/config.yaml
```

This outputs the complete JSON structure with all resolved values.

# Troubleshooting

Common issues and solutions when using MCPKernel.

---

## Installation Issues

### `ModuleNotFoundError: No module named 'mcpkernel'`

**Cause**: MCPKernel is not installed in the active Python environment.

```bash
# Check which Python is active
which python
python --version

# Install MCPKernel
pip install mcpkernel
```

### `pip install` fails with dependency conflicts

```bash
# Use uv for faster, conflict-free installs
pip install uv
uv pip install mcpkernel
```

---

## Configuration Issues

### `Config file not found`

```bash
# Initialize MCPKernel first
mcpkernel init --preset standard

# Or specify the config path explicitly
mcpkernel serve -c /path/to/config.yaml
```

### `No upstream servers configured`

```bash
# Add a server
mcpkernel add-server filesystem http://localhost:3000/mcp

# Verify
mcpkernel status -c .mcpkernel/config.yaml
```

### Environment variables not working

Environment variables use double underscores (`__`) as separators:

```bash
# Correct
export MCPKERNEL__TAINT__MODE=full

# Wrong — single underscore
export MCPKERNEL_TAINT_MODE=full
```

---

## Runtime Issues

### `PolicyViolation: policy-deny`

Your tool call was blocked by a policy rule.

```python
try:
    result = await proxy.call_tool("shell_exec", {"cmd": "ls"})
except PolicyViolation as e:
    print(f"Blocked: {e}")
```

**Solutions**:

1. Check which rule blocked it: the error message includes the rule ID
2. Use `mcpkernel validate-policy` to inspect rules
3. Switch to a more permissive preset: `policy="standard"` instead of `"strict"`
4. Add an explicit allow rule for the tool

### `RuntimeError: MCPKernelProxy not started`

```python
# Wrong — forgot to start
proxy = MCPKernelProxy(upstream=["http://..."])
result = await proxy.call_tool("read_file", {"path": "x"})  # Error!

# Correct — use context manager
async with MCPKernelProxy(upstream=["http://..."]) as proxy:
    result = await proxy.call_tool("read_file", {"path": "x"})

# Or start manually
proxy = MCPKernelProxy(upstream=["http://..."])
await proxy.start()
result = await proxy.call_tool("read_file", {"path": "x"})
await proxy.stop()
```

### Connection refused to upstream server

```bash
# Test connectivity
mcpkernel test-connection -c .mcpkernel/config.yaml

# Check if the upstream server is running
curl http://localhost:3000/mcp
```

---

## Trust & Security Issues

### Trust scores are always decaying

This is by design. Trust decays exponentially over time to ensure nothing stays trusted without continuous verification.

```python
# Verify entities to reset decay
engine.verify("server-id", "audit_pass", weight=1.0)
```

### All nodes show as invalidated

Once a node is invalidated via `invalidate_node()`, the invalidation is permanent and cascades downstream. This is intentional — compromised data cannot be un-compromised.

### Anomaly detector not triggering

The detector needs at least `min_observations` baseline records before it can detect anomalies:

```python
detector = AnomalyDetector(
    min_observations=5,  # Need 5+ observations first
    sigma_threshold=2.5,
)
```

---

## Performance Issues

### Proxy is slow

1. Check if sandbox execution is enabled (adds container startup overhead)
2. Reduce taint mode: `taint.mode: light` instead of `full`
3. Disable unused features: `context.enabled: false`, `ebpf.enabled: false`
4. Check upstream server latency: `mcpkernel test-connection`

### High memory usage

```yaml
# Reduce sandbox memory
sandbox:
  max_memory_mb: 128  # Default is 256

# Reduce context window
context:
  max_context_tokens: 2048  # Default is 4096
```

---

## Getting Help

- **GitHub Issues**: [github.com/piyushptiwari1/mcpkernel/issues](https://github.com/piyushptiwari1/mcpkernel/issues)
- **Source Code**: [github.com/piyushptiwari1/mcpkernel](https://github.com/piyushptiwari1/mcpkernel)
- **PyPI**: [pypi.org/project/mcpkernel](https://pypi.org/project/mcpkernel/)

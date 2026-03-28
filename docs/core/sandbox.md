# Sandbox Execution

When policy rules return a `sandbox` action, MCPKernel executes the tool call in an isolated environment. Four backends are supported.

---

## Backends

| Backend | Isolation Level | Startup Time | Best For |
|---------|---------------|-------------|----------|
| **Docker** | Process-level | ~1s | General use, CI/CD |
| **Firecracker** | VM-level | ~125ms | High security, multi-tenant |
| **WASM** | Language-level | ~10ms | Fast, lightweight sandboxing |
| **Microsandbox** | Container-level | ~500ms | Fine-grained resource control |

---

## Configuration

```yaml
# config.yaml
sandbox:
  backend: docker           # docker | firecracker | wasm | microsandbox
  default_timeout_seconds: 30
  max_cpu_cores: 1.0
  max_memory_mb: 256
  max_disk_mb: 512
  network_enabled: false    # Block network access by default
  docker_image: "python:3.12-slim"
```

---

## Tutorial: Force Sandbox via Policy

Create a policy rule that sandboxes all code execution tools:

```yaml
# policies/sandbox_code.yaml
rules:
  - id: sandbox-exec
    name: Sandbox all code execution
    action: sandbox
    priority: 20
    tool_patterns:
      - "execute_.*"
      - "run_.*"
      - "code_.*"
    owasp_asi_id: ASI-02
```

When a tool call matches, MCPKernel:

1. Creates an isolated container/VM
2. Forwards the tool call inside the sandbox
3. Captures the output
4. Destroys the sandbox
5. Returns the result through the security pipeline

### Using sandbox with the Python API

```python
import asyncio
from mcpkernel import MCPKernelProxy

async def demo():
    proxy = MCPKernelProxy(
        upstream=["http://localhost:3000/mcp"],
        policy="strict",
        sandbox=True,    # Enable sandbox execution
    )
    await proxy.start()

    # Tool calls that match sandbox rules execute in isolation
    result = await proxy.call_tool("execute_python", {
        "code": "print('Hello from sandbox')",
    })
    print(result)
    # The code ran inside a Docker container with:
    # - No network access
    # - 256 MB memory limit
    # - 30 second timeout
    # - Read-only filesystem

    await proxy.stop()

asyncio.run(demo())
```

---

## Resource Limits

| Setting | Default | Description |
|---------|---------|-------------|
| `max_cpu_cores` | 1.0 | CPU cores allocated |
| `max_memory_mb` | 256 | Memory limit in MB |
| `max_disk_mb` | 512 | Disk space limit in MB |
| `default_timeout_seconds` | 30 | Execution timeout |
| `network_enabled` | `false` | Network access (disabled by default) |

### Firecracker-specific

```yaml
sandbox:
  backend: firecracker
  firecracker_kernel_path: /path/to/vmlinux
  firecracker_rootfs_path: /path/to/rootfs.ext4
```

### Network egress control

```yaml
sandbox:
  network_enabled: true
  allowed_egress_domains:
    - "api.github.com"
    - "pypi.org"
```

Only the listed domains will be reachable from inside the sandbox.

---

## How the Pipeline Decides

```
Tool Call → Policy Engine → returns "sandbox" action
                               ↓
                        Sandbox Backend creates container
                               ↓
                        Tool executes inside sandbox
                               ↓
                        Output captured and returned
                               ↓
                        Post-execution hooks (audit, DEE)
```

If the sandbox execution times out or crashes, the tool call result is marked with `is_error: true`.

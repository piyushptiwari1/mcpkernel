# Quick Start

This guide walks you through three ways to use MCPKernel — from a simple proxy to the full Python API. Each example includes real code you can copy-paste and expected output.

---

## 1. Proxy Gateway (Recommended)

The proxy sits between your MCP client and upstream servers. Every tool call passes through the security pipeline automatically.

### Step 1: Initialize and add a server

```bash
mcpkernel init --preset standard
mcpkernel add-server filesystem http://localhost:3000/mcp
```

Output:

```
✓ Initialized MCPKernel in .mcpkernel (preset: standard)
✓ Added server 'filesystem' (streamable_http) → http://localhost:3000/mcp
```

### Step 2: Start the proxy

```bash
mcpkernel serve -c .mcpkernel/config.yaml
```

Output:

```
INFO     MCPKernel proxy starting on http://127.0.0.1:8000
INFO     Transport: Streamable HTTP (POST /mcp)
INFO     Upstream servers: 1 connected
INFO     Hooks loaded: policy, taint, dee, audit, observability
INFO     Ready — all tool calls are now secured
```

### Step 3: Point your MCP client to the proxy

Instead of connecting directly to `http://localhost:3000/mcp`, point your client to:

```
http://localhost:8000/mcp
```

Every tool call now flows through: **Policy → Taint → DEE → Audit → Forward to upstream**.

### Step 4: Verify it's working

```bash
mcpkernel status -c .mcpkernel/config.yaml
```

Output:

```
MCPKernel v0.1.3 — Status
=============================================
  Proxy:   127.0.0.1:8000
  Policy:  default_action=audit
           .mcpkernel/policies/default.yaml [✓]
  Taint:   light
  Audit:   enabled
  DEE:     enabled
  Context: enabled
  Upstream (1):
    • filesystem: http://localhost:3000/mcp [streamable_http]
  Auth:    none

Run 'mcpkernel serve' to start the proxy.
```

---

## 2. Python API (Programmatic)

Use `MCPKernelProxy` directly in your Python code for full control.

### Basic Example: Secure a tool call

```python
import asyncio
from mcpkernel import MCPKernelProxy

async def main():
    # Create a proxy with strict policy and taint detection
    proxy = MCPKernelProxy(
        upstream=["http://localhost:3000/mcp"],
        policy="strict",
        taint=True,
        audit=True,
    )

    # Start the security pipeline
    await proxy.start()
    print(f"Hooks loaded: {proxy.hooks}")
    # Output: Hooks loaded: ['policy', 'context', 'taint', 'dee', 'audit', 'observability']

    # Call a tool — it passes through policy check, taint scan, and audit
    try:
        result = await proxy.call_tool("read_file", {"path": "data.csv"})
        print(f"Result: {result['content']}")
        print(f"Trace ID: {result['trace_id']}")
    except Exception as e:
        print(f"Blocked: {e}")

    # List available tools from upstream
    tools = await proxy.list_tools()
    for tool in tools:
        print(f"  Tool: {tool['name']} — {tool['description']}")

    await proxy.stop()

asyncio.run(main())
```

### Context Manager (recommended)

```python
import asyncio
from mcpkernel import MCPKernelProxy

async def main():
    async with MCPKernelProxy(
        upstream=["http://localhost:3000/mcp"],
        policy="standard",
        taint=True,
    ) as proxy:
        # proxy.start() is called automatically
        result = await proxy.call_tool("read_file", {"path": "notes.txt"})
        print(result)
        # proxy.stop() is called automatically on exit

asyncio.run(main())
```

### What Happens When a Call is Blocked

```python
import asyncio
from mcpkernel import MCPKernelProxy, PolicyViolation

async def main():
    async with MCPKernelProxy(policy="strict", taint=True) as proxy:
        try:
            # This will be blocked — "shell_exec" matches deny rules
            result = await proxy.call_tool(
                "shell_exec",
                {"command": "rm -rf /"},
            )
        except PolicyViolation as e:
            print(f"BLOCKED by policy: {e}")
            # Output: BLOCKED by policy: [policy-deny] ...

asyncio.run(main())
```

---

## 3. `@protect` Decorator (Fastest Integration)

Wrap any async function with `@protect` to add security checks without changing your code structure.

```python
import asyncio
from pathlib import Path
from mcpkernel import protect

@protect(policy="strict", taint=True, audit=True)
async def read_data(path: str) -> str:
    """Read a file — MCPKernel checks arguments before execution."""
    return Path(path).read_text()

@protect(policy="standard", taint=True)
async def send_message(recipient: str, body: str) -> dict:
    """Send a message — taint tracking catches PII/secrets in args."""
    return {"status": "sent", "to": recipient}

async def main():
    # Normal call — passes security checks
    content = await read_data("readme.txt")
    print(f"Read {len(content)} chars")

    # This call has arguments scanned for secrets/PII
    result = await send_message("user@example.com", "Hello!")
    print(result)
    # Output: {'status': 'sent', 'to': 'user@example.com'}

asyncio.run(main())
```

**How `@protect` works:**

1. First call lazy-initializes an `MCPKernelProxy` instance
2. Function arguments are converted into MCP tool call format
3. Pre-execution hooks run: policy check, taint scan
4. If allowed, the original function executes
5. Post-execution hooks run: audit logging, DEE trace
6. Result is returned normally

---

## 4. MCP Server Mode (IDE Integration)

Install MCPKernel as an MCP server in your IDE — your agent gets security tools natively.

```bash
# Install for Claude Desktop
mcpkernel install claude

# Install for Cursor
mcpkernel install cursor

# Install for VS Code
mcpkernel install vscode
```

After installation, your agent can call these tools:

| Tool | What It Does |
|------|-------------|
| `mcpkernel_scan_tool` | Scan a tool for poisoning attacks |
| `mcpkernel_check_taint` | Check if data contains secrets/PII |
| `mcpkernel_validate_policy` | Validate a YAML policy file |
| `mcpkernel_doctor` | Run health checks on the installation |
| `mcpkernel_discover` | Find MCP servers installed on the system |

---

## 5. Docker Deployment

```bash
docker run -p 8000:8000 \
  -v $(pwd)/policies:/app/policies \
  -e MCPKERNEL__POLICY__DEFAULT_ACTION=deny \
  ghcr.io/piyushptiwari1/mcpkernel:latest
```

Or use docker-compose:

```yaml
# docker-compose.yml
services:
  mcpkernel:
    image: ghcr.io/piyushptiwari1/mcpkernel:latest
    ports:
      - "8000:8000"
      - "9090:9090"  # Prometheus metrics
    volumes:
      - ./policies:/app/policies
      - ./dee_store:/app/dee_store
    environment:
      MCPKERNEL__POLICY__DEFAULT_ACTION: deny
      MCPKERNEL__TAINT__MODE: full
      MCPKERNEL__AUDIT__ENABLED: "true"
```

---

## What's Next?

Now that you have MCPKernel running, explore:

- [**Configuration**](configuration.md) — Full YAML config reference
- [**Policy Engine**](../core/policy-engine.md) — Write custom security rules
- [**Taint Tracking**](../core/taint-tracking.md) — Detect secrets and PII
- [**Trust Framework**](../trust/causal-trust-graph.md) — Novel trust scoring with decay
- [**Security Guards**](../security/overview.md) — Defenses against 6 named MCP attacks

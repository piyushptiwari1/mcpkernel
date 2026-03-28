# Basic Usage Examples

These examples show the most common MCPKernel operations. Each includes working code and expected output.

---

## Example 1: Initialize a Project

```bash
mcpkernel init --preset standard
```

Output:

```
✓ Initialized MCPKernel in .mcpkernel (preset: standard)
  Created: .mcpkernel/config.yaml
  Created: .mcpkernel/policies/default.yaml
```

Check what was created:

```bash
tree .mcpkernel/
```

```
.mcpkernel/
├── config.yaml
└── policies/
    └── default.yaml
```

---

## Example 2: Add an Upstream Server

```bash
mcpkernel add-server filesystem http://localhost:3000/mcp
```

Output:

```
✓ Added server 'filesystem' (streamable_http) → http://localhost:3000/mcp
```

---

## Example 3: Start the Proxy

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

---

## Example 4: Check Status

```bash
mcpkernel status -c .mcpkernel/config.yaml
```

Output:

```
MCPKernel v0.2.0 — Status
=============================================
  Proxy:   127.0.0.1:8000
  Policy:  default_action=audit
           .mcpkernel/policies/default.yaml [✓]
  Taint:   light
  Audit:   enabled
  DEE:     enabled
  Upstream (1):
    • filesystem: http://localhost:3000/mcp [streamable_http]
```

---

## Example 5: Python API — Secure a Tool Call

```python
import asyncio
from mcpkernel import MCPKernelProxy

async def main():
    proxy = MCPKernelProxy(
        upstream=["http://localhost:3000/mcp"],
        policy="strict",
        taint=True,
        audit=True,
    )
    await proxy.start()

    # Make a secured tool call
    result = await proxy.call_tool("read_file", {"path": "data.csv"})
    print(f"Content: {result['content'][:50]}...")
    print(f"Trace ID: {result['trace_id']}")
    # Output:
    # Content: id,name,email,score...
    # Trace ID: trace_a1b2c3d4

    await proxy.stop()

asyncio.run(main())
```

---

## Example 6: Context Manager (Recommended)

```python
import asyncio
from mcpkernel import MCPKernelProxy

async def main():
    async with MCPKernelProxy(
        upstream=["http://localhost:3000/mcp"],
        policy="standard",
        taint=True,
    ) as proxy:
        # start() called automatically
        tools = await proxy.list_tools()
        for tool in tools:
            print(f"  {tool['name']}: {tool['description']}")
        # Output:
        #   read_file: Read a file from the filesystem
        #   write_file: Write content to a file
        #   list_dir: List directory contents
        # stop() called automatically on exit

asyncio.run(main())
```

---

## Example 7: The `@protect` Decorator

The fastest way to add security to existing code — zero architecture change:

```python
import asyncio
from pathlib import Path
from mcpkernel import protect

@protect(policy="strict", taint=True, audit=True)
async def read_config(path: str) -> str:
    """Read a config file with MCPKernel security checks."""
    return Path(path).read_text()

@protect(policy="standard", taint=True)
async def send_report(recipient: str, body: str) -> dict:
    """Send a report — taint tracking catches PII/secrets."""
    return {"status": "sent", "to": recipient}

async def main():
    # Allowed — normal config file
    content = await read_config("app.toml")
    print(f"Read {len(content)} chars")
    # Output: Read 342 chars

    # Taint-scanned — PII in body would be flagged
    result = await send_report("admin@company.com", "Q4 metrics look great")
    print(result)
    # Output: {'status': 'sent', 'to': 'admin@company.com'}

asyncio.run(main())
```

**How `@protect` works under the hood:**

1. First call lazy-initializes an `MCPKernelProxy` instance
2. Function arguments are converted to MCP tool call format
3. Pre-execution hooks: policy check → taint scan
4. If allowed → your function executes normally
5. Post-execution hooks: audit log → DEE trace
6. Result returned to caller

---

## Example 8: Health Diagnostics

```bash
mcpkernel doctor
```

Output:

```
MCPKernel Doctor — Health Check
================================

  Python:          3.13.12 ✓
  MCPKernel:       0.2.0 ✓
  Dependencies:    all installed ✓
  Config:          .mcpkernel/config.yaml ✓
  Policies:        1 valid ✓
  Secrets in env:  none detected ✓
  Permissions:     .mcpkernel/ writable ✓

All checks passed.
```

---

## Example 9: Discover MCP Configurations

```bash
mcpkernel discover
```

Output:

```
Discovered MCP configurations:

  Claude Desktop
    Config: ~/.config/claude/claude_desktop_config.json
    Servers: 3 (filesystem, github, postgres)

  Cursor
    Config: ~/.config/cursor/mcp.json
    Servers: 1 (filesystem)

  VS Code
    Config: ~/.config/Code/User/settings.json
    Servers: 2 (filesystem, mcpkernel)

Total: 6 servers across 3 clients
```

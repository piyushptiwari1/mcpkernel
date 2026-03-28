# Framework Integration Examples

MCPKernel integrates with popular AI agent frameworks. Each example shows how to add security to your existing agent code.

---

## LangChain

```python
"""Secure a LangChain agent with MCPKernel."""

import asyncio
from mcpkernel import MCPKernelProxy

async def langchain_example():
    # MCPKernel proxy wraps your MCP servers
    async with MCPKernelProxy(
        upstream=["http://localhost:3000/mcp"],
        policy="strict",
        taint=True,
        audit=True,
    ) as proxy:
        # Route LangChain tool calls through the security pipeline
        result = await proxy.call_tool("search", {"query": "latest news"})

        if result["is_error"]:
            print(f"Error: {result['content']}")
        else:
            print(f"Result: {result['content']}")
            print(f"Trace: {result['trace_id']}")

asyncio.run(langchain_example())
```

---

## CrewAI

```python
"""Secure a CrewAI workflow with MCPKernel."""

import asyncio
from mcpkernel import MCPKernelProxy

async def crewai_example():
    proxy = MCPKernelProxy(
        upstream=["http://localhost:3000/mcp"],
        policy="standard",
        taint=True,
    )
    await proxy.start()

    # All CrewAI tool calls route through MCPKernel
    tools = await proxy.list_tools()
    print(f"Available tools ({len(tools)}):")
    for tool in tools:
        print(f"  {tool['name']}: {tool['description']}")

    # Secure tool execution
    result = await proxy.call_tool("read_file", {"path": "config.yaml"})
    print(f"\nResult: {result['content']}")

    await proxy.stop()

asyncio.run(crewai_example())
```

---

## AutoGen

```python
"""Secure an AutoGen multi-agent system with MCPKernel."""

import asyncio
from mcpkernel import MCPKernelProxy

async def autogen_example():
    # MCPKernel sits between AutoGen agents and MCP servers
    proxy = MCPKernelProxy(
        upstream=[
            "http://localhost:3000/mcp",  # filesystem server
            "http://localhost:3001/mcp",  # code execution server
        ],
        policy="strict",
        taint=True,
        sandbox=True,  # Sandbox code execution
    )
    await proxy.start()

    # Agent A reads a file (passes policy check)
    file_result = await proxy.call_tool("read_file", {"path": "data.csv"})
    print(f"File read: trace={file_result['trace_id']}")

    # Agent B tries to execute code (sandboxed by policy)
    try:
        exec_result = await proxy.call_tool("execute_python", {
            "code": "import os; os.listdir('/')",
        })
        print(f"Code exec: {exec_result['content']}")
    except Exception as e:
        print(f"Blocked: {e}")

    await proxy.stop()

asyncio.run(autogen_example())
```

---

## Using the `@protect` Decorator

The simplest integration — add security to any function:

```python
import asyncio
from mcpkernel import protect

@protect(policy="strict", taint=True, audit=True)
async def fetch_user_data(user_id: str) -> dict:
    """This function is automatically secured by MCPKernel."""
    # MCPKernel checks arguments for PII/secrets before this runs
    return {"user_id": user_id, "name": "Alice", "email": "alice@example.com"}

@protect(policy="strict", taint=True)
async def send_notification(to: str, message: str) -> str:
    """Taint tracking catches secrets in arguments."""
    return f"Sent to {to}: {message}"

async def main():
    # Normal usage — MCPKernel runs transparently
    user = await fetch_user_data("user-123")
    print(f"User: {user}")

    result = await send_notification("admin@example.com", "Deploy complete")
    print(result)

asyncio.run(main())
```

---

## Langfuse Observability Export

Send MCPKernel traces to Langfuse for LLM observability:

```yaml
# config.yaml
langfuse:
  enabled: true
  public_key: "pk-lf-..."
  secret_key: "sk-lf-..."
  host: "https://cloud.langfuse.com"
  project_name: "my-agent"
```

```bash
# Export traces to Langfuse
mcpkernel langfuse-export --db .mcpkernel/traces.db
```

---

## Guardrails AI Integration

Use Guardrails AI validators alongside MCPKernel:

```yaml
# config.yaml
guardrails_ai:
  enabled: true
  pii_validator: true
  toxic_content: false
  secrets_validator: true
  on_fail: "noop"        # noop | exception | fix
```

When enabled, Guardrails AI validators run as an additional check in the taint detection pipeline.

---

## MCP Server Registry

Discover and verify MCP servers from the official registry:

```bash
# Search the registry
mcpkernel registry-search "filesystem"
```

Output:

```
Registry results for 'filesystem':
  @mcp/server-filesystem
    Description: Secure file system access
    Transport: stdio
    Command: npx @mcp/server-filesystem
  @mcp/server-filesystem-extended
    Description: Extended file operations
    Transport: stdio
```

```bash
# List all registered servers
mcpkernel registry-list --limit 10
```

---

## Snyk Agent Scan

Scan your agent's tool chain for known vulnerabilities:

```bash
mcpkernel agent-scan
```

Output:

```
Scanning agent tool chain...
  ✓ @mcp/server-filesystem — no vulnerabilities
  ⚠ @mcp/server-github v1.2.0 — 1 medium severity issue
    CVE-2025-1234: Input validation bypass in git_clone
  ✓ Local tools — no vulnerabilities

Summary: 1 issue found (0 critical, 1 medium, 0 low)
```

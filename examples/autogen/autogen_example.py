"""Example: Using MCPKernel with AutoGen multi-agent conversations.

Demonstrates how to route AutoGen tool invocations through the
MCPKernel proxy for policy enforcement, taint tracking, and
deterministic execution envelopes.
"""

import httpx

MCPKERNEL_URL = "http://localhost:8000/mcp"


def call_tool_via_mcpkernel(tool_name: str, arguments: dict) -> dict:
    """Route a tool call through MCPKernel proxy."""
    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": tool_name,
            "arguments": arguments,
        },
    }
    resp = httpx.post(MCPKERNEL_URL, json=payload, timeout=30)
    resp.raise_for_status()
    return resp.json()


def autogen_example():
    """Simulate an AutoGen agent calling tools via MCPKernel."""

    # 1. Agent executes code in a sandboxed environment
    result = call_tool_via_mcpkernel("execute_code", {
        "code": "result = 2 + 2\nprint(result)",
        "language": "python",
    })
    print("Execute result:", result)

    # 2. Agent reads a file
    result = call_tool_via_mcpkernel("file_read", {
        "path": "/tmp/safe_file.txt",
    })
    print("File read result:", result)

    # 3. Agent tries to access a sensitive path — should be blocked by policy
    result = call_tool_via_mcpkernel("file_read", {
        "path": "/etc/passwd",
    })
    print("Blocked result:", result)


if __name__ == "__main__":
    autogen_example()

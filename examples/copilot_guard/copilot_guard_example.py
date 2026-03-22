"""Example: MCPKernel as a Copilot Guard.

Demonstrates using MCPKernel to intercept and enforce policy on
any MCP-compatible AI coding assistant (GitHub Copilot, Cursor, etc.)
by running as an intermediary proxy.
"""

import asyncio
import httpx

MCPKERNEL_URL = "http://localhost:8000/mcp"


async def copilot_guard_example():
    """Show how an AI assistant's tool calls get filtered."""

    async with httpx.AsyncClient(timeout=30) as client:
        # Safe operation: reading allowed files
        resp = await client.post(MCPKERNEL_URL, json={
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "file_read",
                "arguments": {"path": "src/main.py"},
            },
        })
        print("✓ Allowed:", resp.json())

        # Dangerous: trying to run arbitrary shell commands
        resp = await client.post(MCPKERNEL_URL, json={
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "shell_exec",
                "arguments": {"command": "rm -rf /"},
            },
        })
        print("✗ Blocked:", resp.json())

        # Taint detection: PII in tool arguments
        resp = await client.post(MCPKERNEL_URL, json={
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "http_post",
                "arguments": {
                    "url": "https://external-api.com/data",
                    "body": "User SSN is 123-45-6789",
                },
            },
        })
        print("✗ PII blocked:", resp.json())


if __name__ == "__main__":
    asyncio.run(copilot_guard_example())

"""Example: Simple MCP server for testing MCPKernel proxy.

This creates a minimal MCP server with a few tools that MCPKernel can proxy to.
Run it directly, then point MCPKernel at it.

Usage:
    # Terminal 1: Start the sample MCP server
    python examples/simple_mcp_server/server.py

    # Terminal 2: Start MCPKernel proxy pointing to it
    mcpkernel serve -c examples/simple_mcp_server/config.yaml

    # Terminal 3: Test via curl
    # List tools:
    curl -X POST http://localhost:8000/mcp \
      -H "Content-Type: application/json" \
      -d '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}'

    # Call a tool:
    curl -X POST http://localhost:8000/mcp \
      -H "Content-Type: application/json" \
      -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"greet","arguments":{"name":"World"}}}'
"""

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("sample-server", host="127.0.0.1", port=3001)


@mcp.tool()
def greet(name: str) -> str:
    """Greet someone by name."""
    return f"Hello, {name}!"


@mcp.tool()
def add(a: int, b: int) -> int:
    """Add two numbers."""
    return a + b


@mcp.tool()
def echo(message: str) -> str:
    """Echo a message back."""
    return message


@mcp.tool()
def system_info() -> str:
    """Return basic system information."""
    import platform

    return (
        f"Python {platform.python_version()} on "
        f"{platform.system()} {platform.machine()}"
    )


if __name__ == "__main__":
    mcp.run(transport="streamable-http")

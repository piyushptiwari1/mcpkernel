"""Example: Using MCPKernel with CrewAI.

Shows how CrewAI agents can be wrapped to route all tool calls
through the MCPKernel security gateway.
"""

import httpx

MCPKERNEL_URL = "http://localhost:8000/mcp"


class MCPKernelTool:
    """Wrapper that routes tool calls through MCPKernel."""

    def __init__(self, tool_name: str, description: str = ""):
        self.name = tool_name
        self.description = description

    def run(self, **kwargs) -> str:
        payload = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": self.name,
                "arguments": kwargs,
            },
        }
        resp = httpx.post(MCPKERNEL_URL, json=payload, timeout=30)
        resp.raise_for_status()
        data = resp.json()

        if "error" in data:
            return f"Error: {data['error']['message']}"

        content = data.get("result", {}).get("content", [])
        return content[0].get("text", "") if content else ""


def crewai_example():
    """Simulate CrewAI agents using MCPKernel-protected tools."""

    search_tool = MCPKernelTool("web_search", "Search the web safely")
    code_tool = MCPKernelTool("execute_code", "Run code in sandbox")

    # Research task
    result = search_tool.run(query="latest Python security best practices")
    print(f"Search result: {result}")

    # Code execution task
    result = code_tool.run(code="import sys; print(sys.version)", language="python")
    print(f"Code result: {result}")


if __name__ == "__main__":
    crewai_example()

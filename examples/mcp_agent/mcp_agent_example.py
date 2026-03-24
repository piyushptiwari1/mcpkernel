"""Example: mcp-agent framework with MCPKernel security proxy.

This example demonstrates using the ``mcp-agent`` framework
(https://github.com/lastmile-ai/mcp-agent) with MCPKernel as a transparent
security proxy between the agent and upstream MCP servers.

Architecture::

    mcp-agent  →  MCPKernel (proxy:9090)  →  upstream MCP servers
       ↑              ↓
    agent app    policy + taint + DEE + audit

Prerequisites:
    pip install mcp-agent mcpkernel

Usage:
    1. Start an upstream MCP server (e.g. the official filesystem server)
    2. Start MCPKernel:  mcpkernel serve --config examples/mcp_agent/config.yaml
    3. Run this example: python examples/mcp_agent/mcp_agent_example.py
"""

from __future__ import annotations

import asyncio
import sys


async def main() -> None:
    """Run a simple mcp-agent that connects through MCPKernel."""
    try:
        from mcp_agent.app import MCPApp
        from mcp_agent.agents.agent import Agent
        from mcp_agent.workflows.llm.augmented_llm_openai import OpenAIAugmentedLLM
    except ImportError:
        print("This example requires the mcp-agent package:")
        print("  pip install mcp-agent")
        sys.exit(1)

    # The MCPApp loads its config from mcp_agent.config.yaml (or the path
    # specified in MCP_AGENT_CONFIG env var).  In that config, we point
    # the MCP server URLs at MCPKernel's proxy endpoint instead of the
    # upstream servers directly.

    app = MCPApp(name="mcpkernel-demo")

    async with app.run() as agent_app:
        # Create an agent context that uses the proxied MCP servers
        context = agent_app.context

        # Create an agent with access to the tools registered in MCPKernel
        agent = Agent(
            name="demo-agent",
            instruction=(
                "You are a helpful assistant with access to tools. "
                "All tool calls are transparently secured by MCPKernel: "
                "policy-enforced, taint-tracked, and audit-logged."
            ),
            server_names=["mcpkernel-proxy"],
        )

        async with agent:
            # Attach an LLM to the agent
            llm = await agent.attach_llm(OpenAIAugmentedLLM)

            # Run a sample query
            result = await llm.generate_str(
                message="List the files in the current directory using the filesystem tools.",
            )
            print(f"\nAgent response:\n{result}")

    print("\n✓ All tool calls were secured by MCPKernel")
    print("  Check audit logs: mcpkernel audit-query")
    print("  Check DEE traces: mcpkernel trace-list")


if __name__ == "__main__":
    asyncio.run(main())

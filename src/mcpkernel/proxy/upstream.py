"""Upstream MCP server connection manager.

Manages persistent connections to upstream MCP servers and forwards
tool calls, resource reads, and prompt requests through the
MCPKernel security pipeline.
"""

from __future__ import annotations

import asyncio
from datetime import timedelta
from typing import TYPE_CHECKING, Any

import httpx

from mcpkernel.utils import get_logger

if TYPE_CHECKING:
    from mcp.client.session import ClientSession
    from mcp.types import (
        CallToolResult,
        GetPromptResult,
        ListToolsResult,
        Prompt,
        ReadResourceContentsResponse,
        Resource,
        ResourceTemplate,
        Tool,
    )

    from mcpkernel.config import UpstreamServerConfig

logger = get_logger(__name__)


class UpstreamConnection:
    """A single connection to an upstream MCP server."""

    def __init__(self, config: UpstreamServerConfig) -> None:
        self._config = config
        self._session: ClientSession | None = None
        self._tools: list[Tool] = []
        self._exit_stack: Any = None
        self._task_group: Any = None

    @property
    def name(self) -> str:
        return self._config.name

    @property
    def tools(self) -> list[Tool]:
        return list(self._tools)

    @property
    def tool_names(self) -> set[str]:
        return {t.name for t in self._tools}

    @property
    def connected(self) -> bool:
        return self._session is not None

    async def connect(self) -> None:
        """Establish connection to the upstream MCP server."""
        from contextlib import AsyncExitStack

        from mcp.client.session import ClientSession

        self._exit_stack = AsyncExitStack()
        await self._exit_stack.__aenter__()

        transport = self._config.transport.value

        if transport in ("streamable_http", "sse"):
            read_stream, write_stream = await self._connect_http()
        elif transport == "stdio":
            read_stream, write_stream = await self._connect_stdio()
        else:
            msg = f"Unsupported transport: {transport}"
            raise ValueError(msg)

        self._session = await self._exit_stack.enter_async_context(ClientSession(read_stream, write_stream))
        init_result = await self._session.initialize()
        logger.info(
            "upstream connected",
            name=self._config.name,
            server=init_result.serverInfo.name if init_result.serverInfo else "unknown",
            version=init_result.serverInfo.version if init_result.serverInfo else "unknown",
            protocol=init_result.protocolVersion,
        )

        # Discover available tools
        tools_result = await self._session.list_tools()
        self._tools = list(tools_result.tools)
        logger.info(
            "upstream tools discovered",
            name=self._config.name,
            tool_count=len(self._tools),
            tools=[t.name for t in self._tools],
        )

    async def _connect_http(self) -> tuple[Any, Any]:
        """Create StreamableHTTP or SSE transport."""
        transport = self._config.transport.value
        url = self._config.url

        headers = dict(self._config.headers) if self._config.headers else {}
        http_client = httpx.AsyncClient(headers=headers, timeout=self._config.timeout_seconds)
        http_client = await self._exit_stack.enter_async_context(http_client)

        if transport == "streamable_http":
            from mcp.client.streamable_http import streamable_http_client

            read_stream, write_stream, _ = await self._exit_stack.enter_async_context(
                streamable_http_client(url, http_client=http_client)
            )
        else:
            from mcp.client.sse import sse_client

            read_stream, write_stream = await self._exit_stack.enter_async_context(sse_client(url, headers=headers))

        return read_stream, write_stream

    async def _connect_stdio(self) -> tuple[Any, Any]:
        """Create stdio transport for local MCP servers."""
        from mcp.client.stdio import StdioServerParameters, stdio_client

        if not self._config.command:
            msg = f"stdio transport requires 'command' for server '{self._config.name}'"
            raise ValueError(msg)

        server_params = StdioServerParameters(
            command=self._config.command,
            args=list(self._config.args),
            env=dict(self._config.env) if self._config.env else None,
        )
        read_stream, write_stream = await self._exit_stack.enter_async_context(stdio_client(server_params))
        return read_stream, write_stream

    async def call_tool(self, name: str, arguments: dict[str, Any] | None = None) -> CallToolResult:
        """Forward a tool call to the upstream server."""
        if self._session is None:
            msg = f"Not connected to upstream server '{self._config.name}'"
            raise RuntimeError(msg)

        return await self._session.call_tool(
            name,
            arguments=arguments,
            read_timeout_seconds=timedelta(seconds=self._config.timeout_seconds),
        )

    async def list_tools(self) -> ListToolsResult:
        """List tools from the upstream server."""
        if self._session is None:
            msg = f"Not connected to upstream server '{self._config.name}'"
            raise RuntimeError(msg)

        result = await self._session.list_tools()
        self._tools = list(result.tools)
        return result

    async def list_resources(self) -> list[Resource]:
        """List resources from the upstream server."""
        if self._session is None:
            return []
        try:
            result = await self._session.list_resources()
            return list(result.resources)
        except Exception:
            logger.debug("upstream does not support resources", name=self._config.name)
            return []

    async def read_resource(self, uri: str) -> ReadResourceContentsResponse:
        """Read a resource by URI from the upstream server."""
        if self._session is None:
            msg = f"Not connected to upstream server '{self._config.name}'"
            raise RuntimeError(msg)
        from pydantic import AnyUrl

        return await self._session.read_resource(AnyUrl(uri))

    async def list_resource_templates(self) -> list[ResourceTemplate]:
        """List resource templates from the upstream server."""
        if self._session is None:
            return []
        try:
            result = await self._session.list_resource_templates()
            return list(result.resourceTemplates)
        except Exception:
            logger.debug("upstream does not support resource templates", name=self._config.name)
            return []

    async def list_prompts(self) -> list[Prompt]:
        """List prompts from the upstream server."""
        if self._session is None:
            return []
        try:
            result = await self._session.list_prompts()
            return list(result.prompts)
        except Exception:
            logger.debug("upstream does not support prompts", name=self._config.name)
            return []

    async def get_prompt(self, name: str, arguments: dict[str, str] | None = None) -> GetPromptResult:
        """Get a prompt by name from the upstream server."""
        if self._session is None:
            msg = f"Not connected to upstream server '{self._config.name}'"
            raise RuntimeError(msg)
        return await self._session.get_prompt(name, arguments=arguments)

    async def ping(self) -> bool:
        """Ping the upstream server to check connectivity.

        Returns True if the server responded, False on error.
        """
        if self._session is None:
            return False
        try:
            await self._session.send_ping()
            return True
        except Exception:
            logger.debug("upstream ping failed", name=self._config.name, exc_info=True)
            return False

    async def reconnect(self) -> None:
        """Disconnect and reconnect to the upstream server."""
        logger.info("upstream reconnecting", name=self._config.name)
        await self.disconnect()
        await self.connect()

    async def disconnect(self) -> None:
        """Close the connection to the upstream server."""
        if self._exit_stack is not None:
            try:
                await self._exit_stack.aclose()
            except Exception:
                logger.warning("error closing upstream connection", name=self._config.name, exc_info=True)
            finally:
                self._session = None
                self._exit_stack = None
        logger.info("upstream disconnected", name=self._config.name)


class UpstreamManager:
    """Manages connections to all configured upstream MCP servers.

    Routes tool calls, resource reads, and prompt requests to the correct
    upstream server. Supports auto-reconnection with exponential backoff.
    """

    def __init__(self) -> None:
        self._connections: dict[str, UpstreamConnection] = {}
        self._tool_routing: dict[str, str] = {}  # tool_name → server_name
        self._resource_routing: dict[str, str] = {}  # resource_uri → server_name
        self._prompt_routing: dict[str, str] = {}  # prompt_name → server_name
        self._configs: list[UpstreamServerConfig] = []

    @property
    def connections(self) -> dict[str, UpstreamConnection]:
        return dict(self._connections)

    @property
    def all_tool_names(self) -> set[str]:
        return set(self._tool_routing.keys())

    def get_server_for_tool(self, tool_name: str) -> UpstreamConnection | None:
        """Find which server handles a given tool."""
        server_name = self._tool_routing.get(tool_name)
        if server_name is None:
            return None
        return self._connections.get(server_name)

    def get_server_for_resource(self, uri: str) -> UpstreamConnection | None:
        """Find which server provides a given resource."""
        server_name = self._resource_routing.get(uri)
        if server_name is None:
            return None
        return self._connections.get(server_name)

    def get_server_for_prompt(self, prompt_name: str) -> UpstreamConnection | None:
        """Find which server provides a given prompt."""
        server_name = self._prompt_routing.get(prompt_name)
        if server_name is None:
            return None
        return self._connections.get(server_name)

    async def connect_all(self, configs: list[UpstreamServerConfig]) -> None:
        """Connect to all configured upstream servers."""
        self._configs = list(configs)
        for config in configs:
            conn = UpstreamConnection(config)
            try:
                await conn.connect()
                self._connections[config.name] = conn
                await self._build_routing(config.name, conn)
                logger.info(
                    "upstream registered",
                    name=config.name,
                    tools=len(conn.tool_names),
                )
            except Exception:
                logger.error("failed to connect upstream", name=config.name, exc_info=True)

    async def _build_routing(self, server_name: str, conn: UpstreamConnection) -> None:
        """Build routing tables for tools, resources, and prompts."""
        # Tools
        for tool_name in conn.tool_names:
            if tool_name in self._tool_routing:
                logger.warning(
                    "tool name conflict",
                    tool=tool_name,
                    existing_server=self._tool_routing[tool_name],
                    new_server=server_name,
                )
            self._tool_routing[tool_name] = server_name

        # Discover resources
        resources = await conn.list_resources()
        for res in resources:
            uri = str(res.uri)
            self._resource_routing[uri] = server_name

        # Discover prompts
        prompts = await conn.list_prompts()
        for prompt in prompts:
            self._prompt_routing[prompt.name] = server_name

    async def call_tool(
        self,
        tool_name: str,
        arguments: dict[str, Any] | None = None,
        *,
        max_retries: int = 2,
    ) -> CallToolResult:
        """Route a tool call to the correct upstream server with retry."""
        conn = self.get_server_for_tool(tool_name)
        if conn is None:
            from mcp.types import CallToolResult, TextContent

            return CallToolResult(
                content=[TextContent(type="text", text=f"Tool '{tool_name}' not found on any upstream server")],
                isError=True,
            )
        for attempt in range(max_retries + 1):
            try:
                return await conn.call_tool(tool_name, arguments)
            except (RuntimeError, ConnectionError, OSError) as exc:
                if attempt < max_retries:
                    delay = 2**attempt
                    logger.warning("upstream call failed, retrying", tool=tool_name, attempt=attempt, delay=delay)
                    await asyncio.sleep(delay)
                    try:
                        await conn.reconnect()
                        # Rebuild routing for this connection
                        await self._build_routing(conn.name, conn)
                    except Exception:
                        logger.error("reconnect failed", name=conn.name, exc_info=True)
                else:
                    raise RuntimeError(f"Upstream call failed after {max_retries + 1} attempts: {exc}") from exc
        raise RuntimeError("Unreachable")  # pragma: no cover

    async def list_all_tools(self) -> list[Tool]:
        """Aggregate tools from all upstream servers."""
        all_tools: list[Tool] = []
        for conn in self._connections.values():
            all_tools.extend(conn.tools)
        return all_tools

    async def list_all_resources(self) -> list[Resource]:
        """Aggregate resources from all upstream servers."""
        all_resources: list[Resource] = []
        for conn in self._connections.values():
            resources = await conn.list_resources()
            all_resources.extend(resources)
        return all_resources

    async def list_all_resource_templates(self) -> list[ResourceTemplate]:
        """Aggregate resource templates from all upstream servers."""
        all_templates: list[ResourceTemplate] = []
        for conn in self._connections.values():
            templates = await conn.list_resource_templates()
            all_templates.extend(templates)
        return all_templates

    async def read_resource(self, uri: str) -> ReadResourceContentsResponse:
        """Route a resource read to the correct upstream server."""
        conn = self.get_server_for_resource(uri)
        if conn is None:
            # Try all connections (resource may be a template)
            for c in self._connections.values():
                try:
                    return await c.read_resource(uri)
                except Exception:  # noqa: S112
                    continue
            msg = f"Resource '{uri}' not found on any upstream server"
            raise ValueError(msg)
        return await conn.read_resource(uri)

    async def list_all_prompts(self) -> list[Prompt]:
        """Aggregate prompts from all upstream servers."""
        all_prompts: list[Prompt] = []
        for conn in self._connections.values():
            prompts = await conn.list_prompts()
            all_prompts.extend(prompts)
        return all_prompts

    async def get_prompt(self, name: str, arguments: dict[str, str] | None = None) -> GetPromptResult:
        """Route a prompt request to the correct upstream server."""
        conn = self.get_server_for_prompt(name)
        if conn is None:
            msg = f"Prompt '{name}' not found on any upstream server"
            raise ValueError(msg)
        return await conn.get_prompt(name, arguments)

    async def disconnect_all(self) -> None:
        """Disconnect from all upstream servers."""
        for conn in self._connections.values():
            await conn.disconnect()
        self._connections.clear()
        self._tool_routing.clear()
        self._resource_routing.clear()
        self._prompt_routing.clear()

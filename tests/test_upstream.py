"""Tests for mcpkernel.proxy.upstream — MCP upstream connection manager."""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from mcpkernel.config import UpstreamServerConfig, UpstreamTransport
from mcpkernel.proxy.upstream import UpstreamConnection, UpstreamManager


# ---------------------------------------------------------------------------
# UpstreamConnection tests
# ---------------------------------------------------------------------------
class TestUpstreamConnection:
    def _make_config(self, **kwargs: Any) -> UpstreamServerConfig:
        defaults = {
            "name": "test-server",
            "url": "http://localhost:3000/mcp",
            "transport": UpstreamTransport.STREAMABLE_HTTP,
        }
        defaults.update(kwargs)
        return UpstreamServerConfig(**defaults)

    def test_init(self) -> None:
        config = self._make_config()
        conn = UpstreamConnection(config)
        assert conn.name == "test-server"
        assert not conn.connected
        assert conn.tools == []
        assert conn.tool_names == set()

    def test_stdio_requires_command(self) -> None:
        config = self._make_config(transport=UpstreamTransport.STDIO, command=None)
        conn = UpstreamConnection(config)
        assert conn.name == "test-server"

    @pytest.mark.asyncio
    async def test_call_tool_not_connected_raises(self) -> None:
        config = self._make_config()
        conn = UpstreamConnection(config)
        with pytest.raises(RuntimeError, match="Not connected"):
            await conn.call_tool("test_tool")

    @pytest.mark.asyncio
    async def test_list_tools_not_connected_raises(self) -> None:
        config = self._make_config()
        conn = UpstreamConnection(config)
        with pytest.raises(RuntimeError, match="Not connected"):
            await conn.list_tools()

    @pytest.mark.asyncio
    async def test_disconnect_when_not_connected(self) -> None:
        config = self._make_config()
        conn = UpstreamConnection(config)
        # Should not raise
        await conn.disconnect()
        assert not conn.connected

    @pytest.mark.asyncio
    async def test_connect_streamable_http(self) -> None:
        """Test connection with mocked MCP SDK."""
        config = self._make_config()
        conn = UpstreamConnection(config)

        # Mock the MCP SDK components
        mock_session = AsyncMock()
        mock_init_result = MagicMock()
        mock_init_result.serverInfo.name = "test-upstream"
        mock_init_result.serverInfo.version = "1.0"
        mock_init_result.protocolVersion = "2025-03-26"
        mock_session.initialize.return_value = mock_init_result

        mock_tool = MagicMock()
        mock_tool.name = "read_file"
        mock_tool.description = "Read a file"
        mock_tool.inputSchema = {"type": "object"}
        mock_tools_result = MagicMock()
        mock_tools_result.tools = [mock_tool]
        mock_session.list_tools.return_value = mock_tools_result

        # We need to mock the contextlib.AsyncExitStack and ClientSession
        mock_read_stream = MagicMock()
        mock_write_stream = MagicMock()

        with (
            patch("mcpkernel.proxy.upstream.httpx.AsyncClient") as mock_httpx,
            patch("mcp.client.streamable_http.streamable_http_client") as mock_transport,
            patch("mcp.client.session.ClientSession") as mock_client_session_cls,
        ):
            # Setup mocks
            mock_httpx_instance = AsyncMock()
            mock_httpx.return_value = mock_httpx_instance

            # streamable_http_client is an async context manager returning (read, write, get_session_id)
            mock_transport_cm = AsyncMock()
            mock_transport_cm.__aenter__ = AsyncMock(return_value=(mock_read_stream, mock_write_stream, MagicMock()))
            mock_transport_cm.__aexit__ = AsyncMock(return_value=False)
            mock_transport.return_value = mock_transport_cm

            # ClientSession is also an async context manager
            mock_client_session_cls.return_value = mock_session
            mock_session.__aenter__ = AsyncMock(return_value=mock_session)
            mock_session.__aexit__ = AsyncMock(return_value=False)

            await conn.connect()

            assert conn.connected
            assert "read_file" in conn.tool_names
            assert len(conn.tools) == 1

            await conn.disconnect()

    @pytest.mark.asyncio
    async def test_connect_stdio_no_command_raises(self) -> None:
        config = self._make_config(transport=UpstreamTransport.STDIO, command=None)
        conn = UpstreamConnection(config)
        with pytest.raises(ValueError, match="stdio transport requires 'command'"):
            await conn.connect()


# ---------------------------------------------------------------------------
# UpstreamManager tests
# ---------------------------------------------------------------------------
class TestUpstreamManager:
    def test_init(self) -> None:
        mgr = UpstreamManager()
        assert mgr.connections == {}
        assert mgr.all_tool_names == set()

    def test_get_server_for_tool_none(self) -> None:
        mgr = UpstreamManager()
        assert mgr.get_server_for_tool("nonexistent") is None

    @pytest.mark.asyncio
    async def test_disconnect_all_empty(self) -> None:
        mgr = UpstreamManager()
        await mgr.disconnect_all()
        assert len(mgr.connections) == 0

    @pytest.mark.asyncio
    async def test_call_tool_no_connections(self) -> None:
        mgr = UpstreamManager()
        result = await mgr.call_tool("any_tool")
        assert result.isError

    @pytest.mark.asyncio
    async def test_list_all_tools_empty(self) -> None:
        mgr = UpstreamManager()
        tools = await mgr.list_all_tools()
        assert tools == []

    @pytest.mark.asyncio
    async def test_connect_all_with_failing_server(self) -> None:
        """Failed connections should be logged but not crash."""
        config = UpstreamServerConfig(
            name="bad-server",
            url="http://localhost:9999/mcp",
            transport=UpstreamTransport.STREAMABLE_HTTP,
        )
        mgr = UpstreamManager()
        # Mock UpstreamConnection.connect to raise
        with patch.object(UpstreamConnection, "connect", side_effect=ConnectionError("refused")):
            await mgr.connect_all([config])
        assert "bad-server" not in mgr.connections

    @pytest.mark.asyncio
    async def test_tool_routing(self) -> None:
        """Verify tool routing works with mock connections."""
        mgr = UpstreamManager()

        # Manually wire up mock connections
        mock_conn_a = MagicMock(spec=UpstreamConnection)
        mock_conn_a.name = "server-a"
        mock_conn_a.tool_names = {"read_file", "write_file"}
        mock_conn_a.tools = []
        mock_conn_a.connected = True

        mock_conn_b = MagicMock(spec=UpstreamConnection)
        mock_conn_b.name = "server-b"
        mock_conn_b.tool_names = {"search", "index"}
        mock_conn_b.tools = []
        mock_conn_b.connected = True

        mgr._connections["server-a"] = mock_conn_a
        mgr._connections["server-b"] = mock_conn_b
        mgr._tool_routing = {
            "read_file": "server-a",
            "write_file": "server-a",
            "search": "server-b",
            "index": "server-b",
        }

        assert mgr.get_server_for_tool("read_file") == mock_conn_a
        assert mgr.get_server_for_tool("search") == mock_conn_b
        assert mgr.get_server_for_tool("unknown") is None
        assert mgr.all_tool_names == {"read_file", "write_file", "search", "index"}


# ---------------------------------------------------------------------------
# Transform integration tests
# ---------------------------------------------------------------------------
class TestTransformEnhanced:
    def test_json_rpc_passthrough(self) -> None:
        from mcpkernel.proxy.transform import normalize_to_mcp

        raw = {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}
        result = normalize_to_mcp(raw)
        assert result == raw

    def test_rest_alias_list_tools(self) -> None:
        from mcpkernel.proxy.transform import normalize_to_mcp

        raw = {"method": "list_tools", "id": 5}
        result = normalize_to_mcp(raw)
        assert result["method"] == "tools/list"
        assert result["jsonrpc"] == "2.0"

    def test_rest_alias_call_tool(self) -> None:
        from mcpkernel.proxy.transform import normalize_to_mcp

        raw = {"method": "call_tool", "tool": "read_file", "arguments": {"path": "/data"}, "id": 2}
        result = normalize_to_mcp(raw)
        assert result["method"] == "tools/call"
        assert result["params"]["name"] == "read_file"
        assert result["params"]["arguments"]["path"] == "/data"

    def test_flat_tool_call(self) -> None:
        from mcpkernel.proxy.transform import normalize_to_mcp

        raw = {"tool": "search", "arguments": {"query": "hello"}}
        result = normalize_to_mcp(raw)
        assert result["method"] == "tools/call"
        assert result["params"]["name"] == "search"

    def test_mcp_method_passthrough(self) -> None:
        from mcpkernel.proxy.transform import normalize_to_mcp

        raw = {"method": "initialize", "params": {}}
        result = normalize_to_mcp(raw)
        assert result["method"] == "initialize"

    def test_unknown_method(self) -> None:
        from mcpkernel.proxy.transform import normalize_to_mcp

        raw = {"method": "custom/method", "params": {}}
        result = normalize_to_mcp(raw)
        assert result["method"] == "custom/method"
        assert result["jsonrpc"] == "2.0"

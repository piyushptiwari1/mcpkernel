"""Tests for MCPKernel MCP server module."""

from __future__ import annotations

import pytest

from mcpkernel.mcp_server import TOOLS, _handle_jsonrpc, handle_tool_call


class TestToolDefinitions:
    """Tests for MCP tool definitions."""

    def test_tools_list_not_empty(self) -> None:
        assert len(TOOLS) == 6

    def test_all_tools_have_required_fields(self) -> None:
        for tool in TOOLS:
            assert "name" in tool
            assert "description" in tool
            assert "inputSchema" in tool

    def test_all_tool_names_prefixed(self) -> None:
        for tool in TOOLS:
            assert tool["name"].startswith("mcpkernel_")

    def test_tool_names(self) -> None:
        names = {t["name"] for t in TOOLS}
        expected = {
            "mcpkernel_scan_tool",
            "mcpkernel_validate_policy",
            "mcpkernel_discover_configs",
            "mcpkernel_check_taint",
            "mcpkernel_scan_skill",
            "mcpkernel_doctor",
        }
        assert names == expected


class TestHandleToolCall:
    """Tests for tool call dispatch."""

    @pytest.mark.asyncio
    async def test_unknown_tool(self) -> None:
        result = await handle_tool_call("nonexistent_tool", {})
        assert result["isError"] is True
        assert "Unknown tool" in result["content"][0]["text"]

    @pytest.mark.asyncio
    async def test_doctor_tool(self) -> None:
        result = await handle_tool_call("mcpkernel_doctor", {})
        assert result["isError"] is False
        assert "MCPKernel Doctor" in result["content"][0]["text"]

    @pytest.mark.asyncio
    async def test_check_taint_clean(self) -> None:
        result = await handle_tool_call("mcpkernel_check_taint", {"text": "hello world"})
        assert result["isError"] is False
        assert "No sensitive data" in result["content"][0]["text"]

    @pytest.mark.asyncio
    async def test_scan_skill_missing(self) -> None:
        result = await handle_tool_call(
            "mcpkernel_scan_skill",
            {"skill_path": "/nonexistent/SKILL.md"},
        )
        assert result["isError"] is False
        text = result["content"][0]["text"]
        assert "issue" in text.lower() or "not found" in text.lower()

    @pytest.mark.asyncio
    async def test_discover_configs(self) -> None:
        result = await handle_tool_call("mcpkernel_discover_configs", {})
        assert result["isError"] is False
        assert isinstance(result["content"][0]["text"], str)


class TestHandleJsonRpc:
    """Tests for JSON-RPC 2.0 message handling."""

    @pytest.mark.asyncio
    async def test_initialize(self) -> None:
        msg = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}
        response = await _handle_jsonrpc(msg)
        assert response is not None
        assert response["id"] == 1
        assert "mcpkernel" in response["result"]["serverInfo"]["name"]
        assert response["result"]["protocolVersion"] == "2024-11-05"

    @pytest.mark.asyncio
    async def test_notifications_initialized(self) -> None:
        msg = {"jsonrpc": "2.0", "method": "notifications/initialized"}
        response = await _handle_jsonrpc(msg)
        assert response is None  # No response for notifications

    @pytest.mark.asyncio
    async def test_tools_list(self) -> None:
        msg = {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}
        response = await _handle_jsonrpc(msg)
        assert response is not None
        assert response["id"] == 2
        assert len(response["result"]["tools"]) == 6

    @pytest.mark.asyncio
    async def test_tools_call(self) -> None:
        msg = {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {"name": "mcpkernel_doctor", "arguments": {}},
        }
        response = await _handle_jsonrpc(msg)
        assert response is not None
        assert response["id"] == 3
        assert "MCPKernel Doctor" in response["result"]["content"][0]["text"]

    @pytest.mark.asyncio
    async def test_unknown_method(self) -> None:
        msg = {"jsonrpc": "2.0", "id": 4, "method": "unknown/method", "params": {}}
        response = await _handle_jsonrpc(msg)
        assert response is not None
        assert "error" in response
        assert response["error"]["code"] == -32601

    @pytest.mark.asyncio
    async def test_unknown_notification(self) -> None:
        msg = {"jsonrpc": "2.0", "method": "unknown/notify"}
        response = await _handle_jsonrpc(msg)
        assert response is None  # Notifications without id get no response

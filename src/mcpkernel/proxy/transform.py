"""Request/response transform helpers (legacy API → MCP normalization).

Handles normalization of different request formats into MCP JSON-RPC 2.0.
"""

from __future__ import annotations

from typing import Any

# Known MCP methods
_MCP_METHODS = frozenset(
    {
        "initialize",
        "notifications/initialized",
        "tools/list",
        "tools/call",
        "resources/list",
        "resources/read",
        "resources/templates/list",
        "prompts/list",
        "prompts/get",
        "logging/setLevel",
        "completion/complete",
        "ping",
    }
)

# REST-style action → MCP method mapping
_REST_METHOD_MAP: dict[str, str] = {
    "list_tools": "tools/list",
    "list-tools": "tools/list",
    "call_tool": "tools/call",
    "call-tool": "tools/call",
    "list_resources": "resources/list",
    "list-resources": "resources/list",
    "read_resource": "resources/read",
    "read-resource": "resources/read",
    "list_prompts": "prompts/list",
    "list-prompts": "prompts/list",
    "get_prompt": "prompts/get",
    "get-prompt": "prompts/get",
}


def normalize_to_mcp(raw: dict[str, Any]) -> dict[str, Any]:
    """Wrap a non-MCP request body into a JSON-RPC 2.0 message.

    If the request is already valid JSON-RPC 2.0, it is returned unchanged.
    For REST-style requests, maps to the appropriate MCP method.
    """
    if raw.get("jsonrpc") == "2.0" and raw.get("method"):
        return raw

    request_id = raw.get("id", 1)

    # Check for explicit method field (REST-style)
    method = raw.get("method", raw.get("action", ""))
    if method in _MCP_METHODS:
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": method,
            "params": raw.get("params", {}),
        }

    # Map REST aliases
    mapped = _REST_METHOD_MAP.get(method, "")
    if mapped:
        params = raw.get("params", {})
        if not params and mapped == "tools/call":
            # Build params from flat keys
            tool_name = raw.get("tool", raw.get("name", raw.get("function", "")))
            arguments = raw.get("arguments", raw.get("args", raw.get("input", {})))
            params = {
                "name": tool_name,
                "arguments": arguments if isinstance(arguments, dict) else {},
            }
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": mapped,
            "params": params,
        }

    # Best-effort: if there's a tool/name/function field, assume tools/call
    tool_name = raw.get("tool", raw.get("name", raw.get("function", "")))
    if tool_name:
        arguments = raw.get("arguments", raw.get("args", raw.get("input", {})))
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": "tools/call",
            "params": {
                "name": tool_name,
                "arguments": arguments if isinstance(arguments, dict) else {},
            },
        }

    # Can't determine method — return as-is with jsonrpc wrapper
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "method": raw.get("method", ""),
        "params": raw.get("params", {}),
    }


def normalize_from_mcp(jsonrpc_response: dict[str, Any]) -> dict[str, Any]:
    """Unwrap a JSON-RPC 2.0 response into a flat dict for legacy clients."""
    result = jsonrpc_response.get("result", {})
    error = jsonrpc_response.get("error")
    if error:
        return {"ok": False, "error": error}
    return {
        "ok": not result.get("isError", False),
        "content": result.get("content", []),
        "structured": result.get("structuredContent"),
    }

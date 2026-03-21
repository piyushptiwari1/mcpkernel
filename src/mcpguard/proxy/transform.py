"""Request/response transform helpers (legacy API → MCP normalization)."""

from __future__ import annotations

from typing import Any


def normalize_to_mcp(raw: dict[str, Any]) -> dict[str, Any]:
    """Wrap a non-MCP request body into a JSON-RPC 2.0 ``tools/call``.

    If the request is already valid JSON-RPC, it is returned unchanged.
    """
    if raw.get("jsonrpc") == "2.0":
        return raw

    # Best-effort mapping from a flat REST-style body
    tool_name = raw.get("tool", raw.get("name", raw.get("function", "")))
    arguments = raw.get("arguments", raw.get("args", raw.get("input", {})))
    return {
        "jsonrpc": "2.0",
        "id": raw.get("id", 1),
        "method": "tools/call",
        "params": {
            "name": tool_name,
            "arguments": arguments if isinstance(arguments, dict) else {},
        },
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

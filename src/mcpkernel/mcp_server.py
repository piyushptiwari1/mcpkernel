"""MCPKernel MCP Server — expose security tools as MCP tools.

This module makes MCPKernel itself callable as an MCP server. Any MCP
client (Claude Desktop, Cursor, VS Code, OpenClaw, etc.) can add
MCPKernel as a server to get security scanning, policy validation,
taint analysis, and config discovery as native agent tools.

Transports:
* **stdio** — ``mcpkernel mcp-serve`` (recommended for local use)
* **Streamable HTTP** — ``mcpkernel mcp-serve --transport http``

Usage in Claude Desktop config::

    {
        "mcpServers": {
            "mcpkernel": {
                "command": "mcpkernel",
                "args": ["mcp-serve"]
            }
        }
    }
"""

from __future__ import annotations

import asyncio
import json
from typing import Any

from mcpkernel import __version__
from mcpkernel.utils import get_logger

logger = get_logger(__name__)

# Tool definitions exposed by the MCPKernel MCP server
TOOLS: list[dict[str, Any]] = [
    {
        "name": "mcpkernel_scan_tool",
        "description": (
            "Scan an MCP tool's description and metadata for prompt injection, "
            "poisoning, shadowing, and Unicode obfuscation attacks."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "tool_name": {"type": "string", "description": "Name of the tool to scan"},
                "description": {"type": "string", "description": "Tool description text to analyze"},
                "server_name": {"type": "string", "description": "MCP server name (optional)", "default": "unknown"},
            },
            "required": ["tool_name", "description"],
        },
    },
    {
        "name": "mcpkernel_validate_policy",
        "description": "Validate an MCPKernel YAML policy file for syntax and rule correctness.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "policy_path": {"type": "string", "description": "Path to the YAML policy file"},
            },
            "required": ["policy_path"],
        },
    },
    {
        "name": "mcpkernel_discover_configs",
        "description": (
            "Auto-discover MCP server configurations across all installed IDE clients "
            "(Claude Desktop, Cursor, VS Code, Windsurf, OpenClaw, etc.)."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "include_project": {
                    "type": "boolean",
                    "description": "Also scan project-level configs (.mcp.json, .cursor/mcp.json)",
                    "default": True,
                },
            },
        },
    },
    {
        "name": "mcpkernel_check_taint",
        "description": "Analyze text for taint labels: PII, secrets, user input, or external data.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "text": {"type": "string", "description": "Text to analyze for sensitive data"},
            },
            "required": ["text"],
        },
    },
    {
        "name": "mcpkernel_scan_skill",
        "description": (
            "Scan an OpenClaw/ClawHub SKILL.md file for security issues: "
            "dangerous shell commands, file access, exfiltration patterns, and metadata mismatches."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "skill_path": {"type": "string", "description": "Path to SKILL.md file"},
            },
            "required": ["skill_path"],
        },
    },
    {
        "name": "mcpkernel_doctor",
        "description": (
            "Run MCPKernel health diagnostics: check config, dependencies, exposed secrets, and misconfigurations."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {},
        },
    },
]


async def handle_tool_call(tool_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    """Dispatch an MCP tool call to the appropriate handler.

    Returns a dict with ``content`` (list of content blocks) and ``isError`` flag.
    """
    handlers = {
        "mcpkernel_scan_tool": _handle_scan_tool,
        "mcpkernel_validate_policy": _handle_validate_policy,
        "mcpkernel_discover_configs": _handle_discover_configs,
        "mcpkernel_check_taint": _handle_check_taint,
        "mcpkernel_scan_skill": _handle_scan_skill,
        "mcpkernel_doctor": _handle_doctor,
    }
    handler = handlers.get(tool_name)
    if handler is None:
        return {
            "content": [{"type": "text", "text": f"Unknown tool: {tool_name}"}],
            "isError": True,
        }
    try:
        return await handler(arguments)
    except Exception as exc:
        logger.error("mcp_server_tool_error", tool=tool_name, error=str(exc))
        return {
            "content": [{"type": "text", "text": f"Error: {exc}"}],
            "isError": True,
        }


# ---------------------------------------------------------------------------
# Tool handlers
# ---------------------------------------------------------------------------


async def _handle_scan_tool(args: dict[str, Any]) -> dict[str, Any]:
    """Scan a tool description for poisoning/injection attacks."""
    from mcpkernel.integrations.poisoning import scan_tool_descriptions

    tool_def = {
        "name": args["tool_name"],
        "description": args.get("description", ""),
    }
    server_name = args.get("server_name", "unknown")
    report = scan_tool_descriptions([tool_def], server_name)

    if not report.findings:
        text = f"No poisoning issues found in tool '{args['tool_name']}'."
    else:
        lines = [f"Found {len(report.findings)} issue(s) in '{args['tool_name']}':"]
        for f in report.findings:
            lines.append(f"  [{f.severity.upper()}] {f.title}")
            if f.description:
                lines.append(f"    {f.description}")
            if f.remediation:
                lines.append(f"    Fix: {f.remediation}")
        text = "\n".join(lines)

    return {"content": [{"type": "text", "text": text}], "isError": False}


async def _handle_validate_policy(args: dict[str, Any]) -> dict[str, Any]:
    """Validate a YAML policy file."""
    from pathlib import Path

    from mcpkernel.policy.loader import load_policy

    policy_path = Path(args["policy_path"])
    if not policy_path.exists():
        return {
            "content": [{"type": "text", "text": f"Policy file not found: {policy_path}"}],
            "isError": True,
        }

    try:
        rules = load_policy(policy_path)
        text = f"Policy valid: {len(rules)} rule(s) loaded from {policy_path.name}"
    except Exception as exc:
        text = f"Policy validation failed: {exc}"
        return {"content": [{"type": "text", "text": text}], "isError": True}

    return {"content": [{"type": "text", "text": text}], "isError": False}


async def _handle_discover_configs(args: dict[str, Any]) -> dict[str, Any]:
    """Auto-discover MCP configs."""
    from mcpkernel.integrations.discovery import discover_mcp_configs, summarize_discovery

    configs = discover_mcp_configs(include_project=args.get("include_project", True))
    text = summarize_discovery(configs)
    return {"content": [{"type": "text", "text": text}], "isError": False}


async def _handle_check_taint(args: dict[str, Any]) -> dict[str, Any]:
    """Check text for taint labels."""
    from mcpkernel.taint.sources import detect_tainted_sources

    text = args["text"]
    detections = detect_tainted_sources({"text": text})
    if not detections:
        result = "No sensitive data detected."
    else:
        lines = [f"Detected {len(detections)} taint source(s):"]
        for d in detections:
            lines.append(f"  [{d.label.value}] {d.pattern_name}: '{d.matched_text}'")
        result = "\n".join(lines)
    return {"content": [{"type": "text", "text": result}], "isError": False}


async def _handle_scan_skill(args: dict[str, Any]) -> dict[str, Any]:
    """Scan an OpenClaw SKILL.md for security issues."""
    from mcpkernel.integrations.skill_scanner import scan_skill_file

    skill_path = args["skill_path"]
    findings = await scan_skill_file(skill_path)
    if not findings:
        return {
            "content": [{"type": "text", "text": f"No security issues found in {skill_path}"}],
            "isError": False,
        }
    lines = [f"Found {len(findings)} issue(s) in {skill_path}:"]
    for f in findings:
        lines.append(f"  [{f['severity']}] {f['title']}")
        if f.get("detail"):
            lines.append(f"    {f['detail']}")
    return {"content": [{"type": "text", "text": "\n".join(lines)}], "isError": False}


async def _handle_doctor(args: dict[str, Any]) -> dict[str, Any]:
    """Run MCPKernel health diagnostics."""
    from mcpkernel.integrations.doctor import run_diagnostics

    report = await run_diagnostics()
    return {"content": [{"type": "text", "text": report}], "isError": False}


# ---------------------------------------------------------------------------
# MCP server protocol handling (stdio)
# ---------------------------------------------------------------------------


async def run_mcp_stdio_server() -> None:
    """Run MCPKernel as an MCP server over stdio transport."""
    import sys

    reader = asyncio.StreamReader()
    protocol = asyncio.StreamReaderProtocol(reader)
    await asyncio.get_event_loop().connect_read_pipe(lambda: protocol, sys.stdin)

    writer_transport, writer_protocol = await asyncio.get_event_loop().connect_write_pipe(
        asyncio.streams.FlowControlMixin, sys.stdout
    )
    writer = asyncio.StreamWriter(writer_transport, writer_protocol, None, asyncio.get_event_loop())

    logger.info("mcp_server_started", transport="stdio", tools=len(TOOLS))

    while True:
        line = await reader.readline()
        if not line:
            break

        try:
            msg = json.loads(line.decode())
        except (json.JSONDecodeError, UnicodeDecodeError):
            continue

        response = await _handle_jsonrpc(msg)
        if response is not None:
            writer.write((json.dumps(response) + "\n").encode())
            await writer.drain()


async def _handle_jsonrpc(msg: dict[str, Any]) -> dict[str, Any] | None:
    """Handle a JSON-RPC 2.0 message."""
    method = msg.get("method", "")
    msg_id = msg.get("id")
    params = msg.get("params", {})

    if method == "initialize":
        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {"name": "mcpkernel", "version": __version__},
            },
        }

    if method == "notifications/initialized":
        return None  # No response needed

    if method == "tools/list":
        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "result": {"tools": TOOLS},
        }

    if method == "tools/call":
        tool_name = params.get("name", "")
        arguments = params.get("arguments", {})
        result = await handle_tool_call(tool_name, arguments)
        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "result": result,
        }

    # Unknown method
    if msg_id is not None:
        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "error": {"code": -32601, "message": f"Method not found: {method}"},
        }
    return None

"""Auto-discover MCP configurations across IDE clients and agent platforms.

Scans well-known config paths for Claude Desktop, Cursor, VS Code,
Windsurf, Gemini CLI, OpenClaw, and other MCP-capable clients.
"""

from __future__ import annotations

import json
import os
import platform
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from mcpkernel.utils import get_logger

logger = get_logger(__name__)


@dataclass
class MCPServerConfig:
    """A single MCP server definition found in a config file."""

    name: str
    command: str
    args: list[str] = field(default_factory=list)
    env: dict[str, str] = field(default_factory=dict)
    url: str | None = None
    transport: str = "stdio"  # stdio | sse | streamable-http


@dataclass
class DiscoveredConfig:
    """An MCP config file discovered on the system."""

    client_name: str
    config_path: Path
    servers: list[MCPServerConfig] = field(default_factory=list)
    raw: dict[str, Any] = field(default_factory=dict)
    error: str | None = None


def _home() -> Path:
    return Path.home()


def _system() -> str:
    return platform.system()


# Known MCP config locations per client
def _get_search_paths() -> list[tuple[str, Path]]:
    """Return (client_name, config_path) for all known MCP clients."""
    home = _home()
    system = _system()
    paths: list[tuple[str, Path]] = []

    # --- Claude Desktop ---
    if system == "Darwin":
        paths.append(("Claude Desktop", home / "Library/Application Support/Claude/claude_desktop_config.json"))
    elif system == "Windows":
        appdata = Path(os.environ.get("APPDATA", home / "AppData/Roaming"))
        paths.append(("Claude Desktop", appdata / "Claude/claude_desktop_config.json"))
    else:  # Linux / other
        paths.append(("Claude Desktop", home / ".config/claude/claude_desktop_config.json"))

    # --- Cursor ---
    if system == "Darwin":
        paths.append(("Cursor", home / "Library/Application Support/Cursor/User/globalStorage/mcp.json"))
        paths.append(("Cursor", home / ".cursor/mcp.json"))
    elif system == "Windows":
        appdata = Path(os.environ.get("APPDATA", home / "AppData/Roaming"))
        paths.append(("Cursor", appdata / "Cursor/User/globalStorage/mcp.json"))
        paths.append(("Cursor", home / ".cursor/mcp.json"))
    else:
        paths.append(("Cursor", home / ".config/Cursor/User/globalStorage/mcp.json"))
        paths.append(("Cursor", home / ".cursor/mcp.json"))

    # --- VS Code ---
    if system == "Darwin":
        paths.append(("VS Code", home / "Library/Application Support/Code/User/globalStorage/mcp.json"))
    elif system == "Windows":
        appdata = Path(os.environ.get("APPDATA", home / "AppData/Roaming"))
        paths.append(("VS Code", appdata / "Code/User/globalStorage/mcp.json"))
    else:
        paths.append(("VS Code", home / ".config/Code/User/globalStorage/mcp.json"))

    # --- VS Code settings.json (MCP can be in settings) ---
    if system == "Darwin":
        paths.append(("VS Code Settings", home / "Library/Application Support/Code/User/settings.json"))
    elif system == "Windows":
        appdata = Path(os.environ.get("APPDATA", home / "AppData/Roaming"))
        paths.append(("VS Code Settings", appdata / "Code/User/settings.json"))
    else:
        paths.append(("VS Code Settings", home / ".config/Code/User/settings.json"))

    # --- Windsurf ---
    if system == "Darwin":
        paths.append(("Windsurf", home / "Library/Application Support/Windsurf/User/globalStorage/mcp.json"))
    elif system == "Windows":
        appdata = Path(os.environ.get("APPDATA", home / "AppData/Roaming"))
        paths.append(("Windsurf", appdata / "Windsurf/User/globalStorage/mcp.json"))
    else:
        paths.append(("Windsurf", home / ".config/Windsurf/User/globalStorage/mcp.json"))
    paths.append(("Windsurf", home / ".windsurf/mcp.json"))

    # --- Gemini CLI ---
    paths.append(("Gemini CLI", home / ".gemini/settings.json"))

    # --- OpenClaw ---
    paths.append(("OpenClaw", home / ".openclaw/config.json"))
    paths.append(("OpenClaw", home / ".openclaw/mcp.json"))
    if system == "Darwin":
        paths.append(("OpenClaw", home / "Library/Application Support/OpenClaw/config.json"))
    elif system == "Windows":
        appdata = Path(os.environ.get("APPDATA", home / "AppData/Roaming"))
        paths.append(("OpenClaw", appdata / "OpenClaw/config.json"))
    else:
        paths.append(("OpenClaw", home / ".config/openclaw/config.json"))

    # --- Kiro ---
    paths.append(("Kiro", home / ".kiro/mcp.json"))

    # --- Zed ---
    if system == "Darwin":
        paths.append(("Zed", home / "Library/Application Support/Zed/mcp.json"))
    else:
        paths.append(("Zed", home / ".config/zed/mcp.json"))

    # --- Project-level configs (cwd) ---
    cwd = Path.cwd()
    paths.append(("Project (.mcp.json)", cwd / ".mcp.json"))
    paths.append(("Project (mcp.json)", cwd / "mcp.json"))
    paths.append(("Project (.cursor/mcp.json)", cwd / ".cursor/mcp.json"))
    paths.append(("Project (.vscode/mcp.json)", cwd / ".vscode/mcp.json"))

    return paths


def _parse_mcp_servers(data: dict[str, Any]) -> list[MCPServerConfig]:
    """Extract MCP server configs from a parsed JSON object."""
    servers: list[MCPServerConfig] = []

    # Standard format: {"mcpServers": {...}} or {"mcp": {"servers": {...}}}
    server_dict: dict[str, Any] = {}
    if "mcpServers" in data:
        server_dict = data["mcpServers"]
    elif "mcp" in data and isinstance(data["mcp"], dict):
        server_dict = data["mcp"].get("servers", {})
    elif "servers" in data:
        server_dict = data["servers"]

    for name, cfg in server_dict.items():
        if not isinstance(cfg, dict):
            continue

        transport = "stdio"
        url = cfg.get("url")
        if url:
            transport = "sse" if "sse" in str(url).lower() else "streamable-http"

        servers.append(
            MCPServerConfig(
                name=name,
                command=cfg.get("command", ""),
                args=cfg.get("args", []),
                env=cfg.get("env", {}),
                url=url,
                transport=transport,
            )
        )

    return servers


def discover_mcp_configs(
    *,
    include_project: bool = True,
    extra_paths: list[Path] | None = None,
) -> list[DiscoveredConfig]:
    """Scan all known MCP config locations and return discovered configs.

    Parameters
    ----------
    include_project:
        Whether to include project-level configs (cwd-relative).
    extra_paths:
        Additional paths to check beyond the built-in set.
    """
    results: list[DiscoveredConfig] = []
    seen_paths: set[str] = set()

    search_paths = _get_search_paths()
    if not include_project:
        search_paths = [(name, p) for name, p in search_paths if not name.startswith("Project")]

    if extra_paths:
        search_paths.extend(("Custom", p) for p in extra_paths)

    for client_name, config_path in search_paths:
        resolved = str(config_path.resolve())
        if resolved in seen_paths:
            continue
        seen_paths.add(resolved)

        if not config_path.exists():
            continue

        dc = DiscoveredConfig(client_name=client_name, config_path=config_path)

        try:
            raw_text = config_path.read_text(encoding="utf-8")
            data = json.loads(raw_text)
            dc.raw = data
            dc.servers = _parse_mcp_servers(data)
        except json.JSONDecodeError as exc:
            dc.error = f"Invalid JSON: {exc}"
            logger.warning("mcp_config_parse_error", path=str(config_path), error=str(exc))
        except OSError as exc:
            dc.error = f"Read error: {exc}"
            logger.warning("mcp_config_read_error", path=str(config_path), error=str(exc))

        results.append(dc)
        logger.info(
            "mcp_config_discovered",
            client=client_name,
            path=str(config_path),
            server_count=len(dc.servers),
        )

    return results


def summarize_discovery(configs: list[DiscoveredConfig]) -> str:
    """Return a human-readable summary of discovered MCP configurations."""
    if not configs:
        return "No MCP configurations found on this system."

    lines: list[str] = []
    total_servers = 0

    for dc in configs:
        status = "✓" if not dc.error else "✗"
        lines.append(f"\n{status} {dc.client_name}")
        lines.append(f"  Path: {dc.config_path}")

        if dc.error:
            lines.append(f"  Error: {dc.error}")
            continue

        if not dc.servers:
            lines.append("  No MCP servers configured")
            continue

        for srv in dc.servers:
            total_servers += 1
            cmd_display = srv.url or f"{srv.command} {' '.join(srv.args)}"
            lines.append(f"  • {srv.name} ({srv.transport}): {cmd_display}")

            # Flag potential security concerns
            if srv.env:
                secret_keys = [
                    k for k in srv.env if any(s in k.upper() for s in ("KEY", "SECRET", "TOKEN", "PASSWORD"))
                ]
                if secret_keys:
                    lines.append(f"    ⚠ Exposed secrets in env: {', '.join(secret_keys)}")

    header = f"Discovered {len(configs)} config(s) with {total_servers} MCP server(s):"
    return header + "\n" + "\n".join(lines)

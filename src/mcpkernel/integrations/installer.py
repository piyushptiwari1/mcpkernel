"""Multi-client MCP server installer.

Installs MCPKernel as an MCP server in any supported IDE client's
configuration file.  Inspired by kernel.sh's ``kernel mcp install
--target <client>`` pattern.

Supported targets::

    mcpkernel install --target claude       # Claude Desktop
    mcpkernel install --target cursor       # Cursor IDE
    mcpkernel install --target vscode       # VS Code
    mcpkernel install --target windsurf     # Windsurf IDE
    mcpkernel install --target zed          # Zed editor
    mcpkernel install --target openclaw     # OpenClaw assistant
    mcpkernel install --target goose        # Goose AI
"""

from __future__ import annotations

import json
import os
import platform
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from mcpkernel.utils import get_logger

logger = get_logger(__name__)


@dataclass
class InstallResult:
    """Result from an install operation."""

    success: bool
    target: str
    config_path: Path | None = None
    message: str = ""
    backup_path: Path | None = None


def _home() -> Path:
    return Path.home()


def _system() -> str:
    return platform.system()


def _find_mcpkernel_bin() -> str:
    """Find the mcpkernel binary path."""
    which = shutil.which("mcpkernel")
    return which if which else "mcpkernel"


# --- MCP server config block that gets injected ---


def _mcpkernel_server_config(mode: str = "proxy") -> dict[str, Any]:
    """Generate the MCPKernel MCP server config block.

    Parameters
    ----------
    mode:
        "proxy" — run as a security proxy (intercepts other servers).
        "tools" — run as an MCP server exposing security tools.
    """
    bin_path = _find_mcpkernel_bin()
    if mode == "tools":
        return {
            "command": bin_path,
            "args": ["mcp-serve"],
        }
    return {
        "command": bin_path,
        "args": ["serve", "--transport", "stdio"],
    }


# --- Target config file paths ---


def _get_target_config_path(target: str) -> Path | None:
    """Return the config file path for a given target client."""
    home = _home()
    system = _system()

    paths: dict[str, list[Path]] = {
        "claude": [],
        "cursor": [],
        "vscode": [],
        "windsurf": [],
        "zed": [],
        "openclaw": [],
        "goose": [],
    }

    # Claude Desktop
    if system == "Darwin":
        paths["claude"].append(home / "Library/Application Support/Claude/claude_desktop_config.json")
    elif system == "Windows":
        appdata = Path(os.environ.get("APPDATA", home / "AppData/Roaming"))
        paths["claude"].append(appdata / "Claude/claude_desktop_config.json")
    else:
        paths["claude"].append(home / ".config/claude/claude_desktop_config.json")

    # Cursor
    paths["cursor"].append(home / ".cursor/mcp.json")

    # VS Code
    if system == "Darwin":
        paths["vscode"].append(home / "Library/Application Support/Code/User/settings.json")
    elif system == "Windows":
        appdata = Path(os.environ.get("APPDATA", home / "AppData/Roaming"))
        paths["vscode"].append(appdata / "Code/User/settings.json")
    else:
        paths["vscode"].append(home / ".config/Code/User/settings.json")

    # Windsurf
    if system == "Darwin":
        paths["windsurf"].append(home / "Library/Application Support/Windsurf/User/globalStorage/mcp.json")
    elif system == "Windows":
        appdata = Path(os.environ.get("APPDATA", home / "AppData/Roaming"))
        paths["windsurf"].append(appdata / "Windsurf/User/globalStorage/mcp.json")
    else:
        paths["windsurf"].append(home / ".config/Windsurf/User/globalStorage/mcp.json")

    # Zed
    if system == "Darwin":
        paths["zed"].append(home / ".config/zed/settings.json")
    else:
        paths["zed"].append(home / ".config/zed/settings.json")

    # OpenClaw
    paths["openclaw"].append(home / ".openclaw/openclaw.json")

    # Goose
    paths["goose"].append(home / ".config/goose/config.yaml")

    target_paths = paths.get(target, [])
    for p in target_paths:
        if p.exists():
            return p

    # Return first path even if it doesn't exist (we'll create it)
    return target_paths[0] if target_paths else None


def _backup_config(config_path: Path) -> Path | None:
    """Create a .bak backup of the config file."""
    if config_path.exists():
        backup = config_path.with_suffix(config_path.suffix + ".mcpkernel.bak")
        shutil.copy2(config_path, backup)
        return backup
    return None


def install_to_target(
    target: str,
    *,
    mode: str = "tools",
    force: bool = False,
) -> InstallResult:
    """Install MCPKernel as an MCP server in the target client's config.

    Parameters
    ----------
    target:
        Client name: claude, cursor, vscode, windsurf, zed, openclaw, goose.
    mode:
        "tools" — expose MCPKernel security tools as MCP tools (default).
        "proxy" — run as a security proxy intercepting all tool calls.
    force:
        Overwrite existing MCPKernel config entry if present.
    """
    target = target.lower().strip()
    supported = {"claude", "cursor", "vscode", "windsurf", "zed", "openclaw", "goose"}
    if target not in supported:
        return InstallResult(
            success=False,
            target=target,
            message=f"Unsupported target '{target}'. Supported: {', '.join(sorted(supported))}",
        )

    config_path = _get_target_config_path(target)
    if config_path is None:
        return InstallResult(
            success=False,
            target=target,
            message=f"Could not determine config path for '{target}'",
        )

    server_config = _mcpkernel_server_config(mode)

    try:
        if target == "goose":
            return _install_goose(config_path, server_config, force)
        if target == "openclaw":
            return _install_openclaw(config_path, server_config, force)
        if target == "zed":
            return _install_zed(config_path, server_config, force)
        return _install_json_mcp(target, config_path, server_config, force)
    except Exception as exc:
        return InstallResult(
            success=False,
            target=target,
            config_path=config_path,
            message=f"Installation failed: {exc}",
        )


def _install_json_mcp(
    target: str,
    config_path: Path,
    server_config: dict[str, Any],
    force: bool,
) -> InstallResult:
    """Install into a JSON config that uses mcpServers key."""
    config: dict[str, Any] = {}
    if config_path.exists():
        config = json.loads(config_path.read_text(encoding="utf-8"))

    servers = config.setdefault("mcpServers", {})
    if "mcpkernel" in servers and not force:
        return InstallResult(
            success=False,
            target=target,
            config_path=config_path,
            message="MCPKernel already configured. Use --force to overwrite.",
        )

    backup = _backup_config(config_path)
    servers["mcpkernel"] = server_config

    config_path.parent.mkdir(parents=True, exist_ok=True)
    config_path.write_text(json.dumps(config, indent=2) + "\n", encoding="utf-8")

    return InstallResult(
        success=True,
        target=target,
        config_path=config_path,
        backup_path=backup,
        message=f"MCPKernel installed in {target} config at {config_path}",
    )


def _install_zed(
    config_path: Path,
    server_config: dict[str, Any],
    force: bool,
) -> InstallResult:
    """Install into Zed's settings.json (uses context_servers key)."""
    config: dict[str, Any] = {}
    if config_path.exists():
        config = json.loads(config_path.read_text(encoding="utf-8"))

    servers = config.setdefault("context_servers", {})
    if "mcpkernel" in servers and not force:
        return InstallResult(
            success=False,
            target="zed",
            config_path=config_path,
            message="MCPKernel already configured. Use --force to overwrite.",
        )

    backup = _backup_config(config_path)
    servers["mcpkernel"] = {
        "source": "custom",
        "command": server_config["command"],
        "args": server_config.get("args", []),
    }

    config_path.parent.mkdir(parents=True, exist_ok=True)
    config_path.write_text(json.dumps(config, indent=2) + "\n", encoding="utf-8")

    return InstallResult(
        success=True,
        target="zed",
        config_path=config_path,
        backup_path=backup,
        message=f"MCPKernel installed in Zed config at {config_path}",
    )


def _install_openclaw(
    config_path: Path,
    server_config: dict[str, Any],
    force: bool,
) -> InstallResult:
    """Install as an OpenClaw MCP tool config."""
    config: dict[str, Any] = {}
    if config_path.exists():
        config = json.loads(config_path.read_text(encoding="utf-8"))

    mcp = config.setdefault("mcp", {}).setdefault("servers", {})
    if "mcpkernel" in mcp and not force:
        return InstallResult(
            success=False,
            target="openclaw",
            config_path=config_path,
            message="MCPKernel already configured. Use --force to overwrite.",
        )

    backup = _backup_config(config_path)
    mcp["mcpkernel"] = server_config

    config_path.parent.mkdir(parents=True, exist_ok=True)
    config_path.write_text(json.dumps(config, indent=2) + "\n", encoding="utf-8")

    return InstallResult(
        success=True,
        target="openclaw",
        config_path=config_path,
        backup_path=backup,
        message=f"MCPKernel installed in OpenClaw config at {config_path}",
    )


def _install_goose(
    config_path: Path,
    server_config: dict[str, Any],
    force: bool,
) -> InstallResult:
    """Install into Goose AI's YAML config."""
    import yaml

    config: dict[str, Any] = {}
    if config_path.exists():
        config = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}

    extensions = config.setdefault("extensions", {})
    if "mcpkernel" in extensions and not force:
        return InstallResult(
            success=False,
            target="goose",
            config_path=config_path,
            message="MCPKernel already configured. Use --force to overwrite.",
        )

    backup = _backup_config(config_path)
    extensions["mcpkernel"] = {
        "type": "STDIO",
        "name": "MCPKernel Security",
        "command": f"{server_config['command']} {' '.join(server_config.get('args', []))}",
        "timeout": 300,
        "description": "AI agent security gateway — policy enforcement, taint tracking, and tool scanning",
    }

    config_path.parent.mkdir(parents=True, exist_ok=True)
    config_path.write_text(yaml.dump(config, default_flow_style=False), encoding="utf-8")

    return InstallResult(
        success=True,
        target="goose",
        config_path=config_path,
        backup_path=backup,
        message=f"MCPKernel installed in Goose config at {config_path}",
    )


def uninstall_from_target(target: str) -> InstallResult:
    """Remove MCPKernel from a target client's configuration."""
    target = target.lower().strip()
    config_path = _get_target_config_path(target)
    if config_path is None or not config_path.exists():
        return InstallResult(
            success=False,
            target=target,
            message=f"Config file not found for '{target}'",
        )

    try:
        if target == "goose":
            import yaml

            config = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
            if "mcpkernel" in config.get("extensions", {}):
                backup = _backup_config(config_path)
                del config["extensions"]["mcpkernel"]
                config_path.write_text(yaml.dump(config, default_flow_style=False), encoding="utf-8")
                return InstallResult(
                    success=True,
                    target=target,
                    config_path=config_path,
                    backup_path=backup,
                    message="MCPKernel removed from Goose config",
                )
        else:
            config = json.loads(config_path.read_text(encoding="utf-8"))
            key = "context_servers" if target == "zed" else ("mcpServers" if target != "openclaw" else "mcp")

            if target == "openclaw":
                servers = config.get("mcp", {}).get("servers", {})
                if "mcpkernel" in servers:
                    backup = _backup_config(config_path)
                    del servers["mcpkernel"]
                    config_path.write_text(json.dumps(config, indent=2) + "\n", encoding="utf-8")
                    return InstallResult(
                        success=True,
                        target=target,
                        config_path=config_path,
                        backup_path=backup,
                        message="MCPKernel removed",
                    )
            else:
                servers = config.get(key, {})
                if "mcpkernel" in servers:
                    backup = _backup_config(config_path)
                    del servers["mcpkernel"]
                    config_path.write_text(json.dumps(config, indent=2) + "\n", encoding="utf-8")
                    return InstallResult(
                        success=True,
                        target=target,
                        config_path=config_path,
                        backup_path=backup,
                        message="MCPKernel removed",
                    )
    except Exception as exc:
        return InstallResult(success=False, target=target, message=f"Uninstall failed: {exc}")

    return InstallResult(success=False, target=target, message="MCPKernel not found in config")


def get_supported_targets() -> list[str]:
    """Return list of supported installation targets."""
    return ["claude", "cursor", "vscode", "windsurf", "zed", "openclaw", "goose"]

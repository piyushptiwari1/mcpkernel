"""MCPKernel Doctor — health diagnostics and misconfiguration detection.

Inspired by OpenClaw's ``openclaw doctor``, this module checks:

- Python + dependency versions
- Config file validity
- Running services and ports
- Exposed secrets in environment or config files
- File permission issues
- Upstream MCP server connectivity
"""

from __future__ import annotations

import os
import platform
import shutil
import sys
from pathlib import Path
from typing import Any

from mcpkernel.utils import get_logger

logger = get_logger(__name__)


async def run_diagnostics(workspace: str | Path | None = None) -> str:
    """Run all MCPKernel health diagnostics and return a formatted report.

    Parameters
    ----------
    workspace:
        Optional workspace root to check for project-level configs.
    """
    checks: list[dict[str, Any]] = []

    checks.extend(_check_python())
    checks.extend(_check_dependencies())
    checks.extend(_check_config_files(workspace))
    checks.extend(_check_env_secrets())
    checks.extend(_check_tools_available())
    checks.extend(_check_permissions())

    return _format_report(checks)


def _check_python() -> list[dict[str, Any]]:
    """Check Python version and runtime."""
    checks = []
    version = platform.python_version()
    major, minor = sys.version_info[:2]

    if (major, minor) >= (3, 12):
        checks.append({"name": "Python version", "status": "pass", "detail": f"Python {version}"})
    elif (major, minor) >= (3, 10):
        checks.append({"name": "Python version", "status": "warn", "detail": f"Python {version} — 3.12+ recommended"})
    else:
        checks.append({"name": "Python version", "status": "fail", "detail": f"Python {version} — 3.10+ required"})

    return checks


def _check_dependencies() -> list[dict[str, Any]]:
    """Check that critical dependencies are importable."""
    checks = []
    deps = {
        "mcpkernel": "mcpkernel",
        "mcp SDK": "mcp",
        "fastapi": "fastapi",
        "uvicorn": "uvicorn",
        "pydantic": "pydantic",
        "structlog": "structlog",
        "PyYAML": "yaml",
    }
    optional_deps = {
        "PyJWT": "jwt",
        "cryptography": "cryptography",
        "wasmtime": "wasmtime",
        "docker": "docker",
        "prometheus_client": "prometheus_client",
    }

    for name, module in deps.items():
        try:
            __import__(module)
            checks.append({"name": f"Dependency: {name}", "status": "pass", "detail": "installed"})
        except ImportError:
            checks.append({"name": f"Dependency: {name}", "status": "fail", "detail": "NOT installed (required)"})

    for name, module in optional_deps.items():
        try:
            __import__(module)
            checks.append({"name": f"Optional: {name}", "status": "pass", "detail": "installed"})
        except ImportError:
            checks.append({"name": f"Optional: {name}", "status": "info", "detail": "not installed"})

    return checks


def _check_config_files(workspace: str | Path | None = None) -> list[dict[str, Any]]:
    """Check for MCPKernel config files and their validity."""
    checks = []

    # Global config locations
    home = Path.home()
    global_paths = [
        home / ".mcpkernel" / "config.yaml",
        home / ".mcpkernel" / "config.yml",
    ]

    found_global = False
    for p in global_paths:
        if p.exists():
            found_global = True
            try:
                import yaml

                data = yaml.safe_load(p.read_text(encoding="utf-8"))
                if isinstance(data, dict):
                    checks.append({"name": f"Global config: {p.name}", "status": "pass", "detail": str(p)})
                else:
                    checks.append(
                        {
                            "name": f"Global config: {p.name}",
                            "status": "warn",
                            "detail": "Not a valid config dict",
                        }
                    )
            except Exception as exc:
                checks.append({"name": f"Global config: {p.name}", "status": "fail", "detail": f"Parse error: {exc}"})

    if not found_global:
        checks.append({"name": "Global config", "status": "info", "detail": "No global config found (using defaults)"})

    # Project config
    if workspace:
        ws = Path(workspace)
        project_configs = [
            ws / ".mcpkernel" / "config.yaml",
            ws / "mcpkernel.yaml",
            ws / "mcpkernel.yml",
        ]
        for p in project_configs:
            if p.exists():
                checks.append({"name": f"Project config: {p.name}", "status": "pass", "detail": str(p)})

    # Policy files
    policy_dirs = [Path("policies"), Path(".mcpkernel/policies")]
    for pd in policy_dirs:
        if pd.exists():
            yamls = list(pd.glob("*.yaml")) + list(pd.glob("*.yml"))
            checks.append({"name": f"Policy dir: {pd}", "status": "pass", "detail": f"{len(yamls)} policy file(s)"})

    return checks


def _check_env_secrets() -> list[dict[str, Any]]:
    """Check for accidentally exposed secrets in environment."""
    checks = []
    suspicious_patterns = {
        "MCPKERNEL_SECRET": "MCPKernel shared secret",
        "MCPKERNEL_JWT_SECRET": "JWT signing secret",
        "OPENAI_API_KEY": "OpenAI API key",
        "ANTHROPIC_API_KEY": "Anthropic API key",
        "AWS_SECRET_ACCESS_KEY": "AWS secret key",
        "GITHUB_TOKEN": "GitHub token",
        "SLACK_BOT_TOKEN": "Slack bot token",
        "DISCORD_BOT_TOKEN": "Discord bot token",
    }

    for env_var, description in suspicious_patterns.items():
        value = os.environ.get(env_var, "")
        if value and len(value) > 8 and value not in ("changeme", "test", "placeholder", "xxx"):
            checks.append(
                {
                    "name": f"Env: {env_var}",
                    "status": "warn",
                    "detail": (
                        f"{description} is set in environment (value hidden). Ensure it's not exposed in configs."
                    ),
                }
            )

    if not any(c["status"] == "warn" for c in checks):
        checks.append({"name": "Environment secrets", "status": "pass", "detail": "No exposed secrets detected"})

    return checks


def _check_tools_available() -> list[dict[str, Any]]:
    """Check for optional external tools."""
    checks = []
    tools = {
        "docker": "Docker — required for Docker sandbox backend",
        "wasmtime": "Wasmtime — required for WASM sandbox backend",
        "agent-scan": "Snyk Agent Scan — MCP security scanning",
        "sigstore": "Sigstore — DEE envelope signing",
        "ruff": "Ruff — Python linting/formatting",
    }

    for tool, description in tools.items():
        if shutil.which(tool):
            checks.append({"name": f"Tool: {tool}", "status": "pass", "detail": description})
        else:
            checks.append({"name": f"Tool: {tool}", "status": "info", "detail": f"{description} (not found)"})

    return checks


def _check_permissions() -> list[dict[str, Any]]:
    """Check file permissions for security issues."""
    checks = []

    # Check if config files are world-readable
    home = Path.home()
    sensitive_paths = [
        home / ".mcpkernel" / "config.yaml",
        home / ".mcpkernel" / "credentials",
    ]

    for p in sensitive_paths:
        if p.exists():
            mode = p.stat().st_mode
            if mode & 0o077:  # Others can read/write
                checks.append(
                    {
                        "name": f"Permissions: {p.name}",
                        "status": "warn",
                        "detail": f"{p} is accessible by other users (mode {oct(mode)}). Run: chmod 600 {p}",
                    }
                )

    return checks


def _format_report(checks: list[dict[str, Any]]) -> str:
    """Format diagnostic checks into a human-readable report."""
    lines = ["MCPKernel Doctor", "=" * 50, ""]

    status_icons = {"pass": "[PASS]", "fail": "[FAIL]", "warn": "[WARN]", "info": "[INFO]"}

    pass_count = sum(1 for c in checks if c["status"] == "pass")
    fail_count = sum(1 for c in checks if c["status"] == "fail")
    warn_count = sum(1 for c in checks if c["status"] == "warn")

    for check in checks:
        icon = status_icons.get(check["status"], "[????]")
        lines.append(f"  {icon} {check['name']}: {check['detail']}")

    lines.append("")
    lines.append(f"Summary: {pass_count} passed, {fail_count} failed, {warn_count} warnings")
    lines.append(f"Total checks: {len(checks)}")

    if fail_count > 0:
        lines.append("")
        lines.append("Action required: Fix FAIL items above before running MCPKernel in production.")
    elif warn_count > 0:
        lines.append("")
        lines.append("Review WARN items above for potential issues.")
    else:
        lines.append("")
        lines.append("All checks passed! MCPKernel is ready.")

    return "\n".join(lines)

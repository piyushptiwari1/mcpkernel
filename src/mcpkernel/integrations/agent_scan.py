"""Snyk Agent Scan integration — static MCP server security scanning.

Bridges Snyk's ``agent-scan`` CLI tool (formerly ``mcp-scan``) with
MCPKernel's policy engine.  Runs the scanner on MCP server configs,
parses the JSON report, and generates MCPKernel policy rules based
on discovered vulnerabilities.

Usage::

    scanner = AgentScanner()
    if scanner.available:
        report = await scanner.scan_config(Path(".mcpkernel/config.yaml"))
        rules = scanner.report_to_policy_rules(report)
"""

from __future__ import annotations

import json
import shutil
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from pathlib import Path

from mcpkernel.utils import get_logger

logger = get_logger(__name__)


@dataclass
class AgentScanConfig:
    """Configuration for Snyk Agent Scan integration."""

    enabled: bool = True
    binary_name: str = "agent-scan"
    timeout_seconds: int = 120
    auto_generate_policy: bool = True


@dataclass
class ScanFinding:
    """A single finding from the agent scan report."""

    rule_id: str
    severity: str  # critical, high, medium, low, info
    title: str
    description: str
    server_name: str = ""
    tool_name: str = ""
    category: str = ""  # prompt_injection, tool_poisoning, tool_shadowing, etc.
    remediation: str = ""

    @property
    def is_blocking(self) -> bool:
        """Return True if this finding should block tool calls by default."""
        return self.severity in ("critical", "high")


@dataclass
class ScanReport:
    """Parsed scan report from agent-scan."""

    scan_time: float = 0.0
    scanner_version: str = ""
    servers_scanned: int = 0
    findings: list[ScanFinding] = field(default_factory=list)
    raw_output: str = ""

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "critical")

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "high")

    @property
    def has_blockers(self) -> bool:
        return any(f.is_blocking for f in self.findings)


class AgentScanner:
    """Bridge to Snyk's agent-scan CLI tool.

    Detects if the ``agent-scan`` binary is available on PATH, runs
    scans against MCP server configurations or directories, and parses
    the JSON output into structured findings.
    """

    def __init__(self, config: AgentScanConfig | None = None) -> None:
        self._config = config or AgentScanConfig()
        self._binary_path: str | None = None

    @property
    def available(self) -> bool:
        """Return True if the agent-scan binary is found on PATH."""
        if self._binary_path is None:
            self._binary_path = shutil.which(self._config.binary_name) or ""
        return bool(self._binary_path)

    async def scan_directory(self, directory: Path) -> ScanReport:
        """Run agent-scan on a directory (auto-discovers MCP configs).

        Looks for Claude Desktop, Cursor, VS Code, and custom
        MCP config files.
        """
        if not self.available:
            logger.warning("agent-scan not found on PATH — install with: npm install -g @anthropic/agent-scan")
            return ScanReport(raw_output="agent-scan not available")

        return await self._run_scan(["--directory", str(directory)])

    async def scan_config(self, config_path: Path) -> ScanReport:
        """Run agent-scan on a specific MCPKernel config file."""
        if not self.available:
            return ScanReport(raw_output="agent-scan not available")

        return await self._run_scan(["--config", str(config_path)])

    async def scan_server_url(self, url: str) -> ScanReport:
        """Run agent-scan against a specific MCP server URL."""
        if not self.available:
            return ScanReport(raw_output="agent-scan not available")

        # Validate URL scheme to prevent SSRF via delegated subprocess
        import urllib.parse

        parsed = urllib.parse.urlparse(url)
        if parsed.scheme not in ("http", "https"):
            logger.warning("agent-scan rejected non-HTTP URL", url=url, scheme=parsed.scheme)
            return ScanReport(raw_output=f"Invalid URL scheme: {parsed.scheme}. Only http/https allowed.")

        return await self._run_scan(["--url", url])

    def report_to_policy_rules(self, report: ScanReport) -> list[dict[str, Any]]:
        """Convert scan findings to MCPKernel policy rule dicts.

        Each critical/high finding generates a ``deny`` rule.
        Medium findings generate ``log`` rules.
        Low/info findings generate ``audit`` rules.
        """
        rules: list[dict[str, Any]] = []

        for finding in report.findings:
            rule_action = "deny" if finding.is_blocking else "log"

            tool_patterns = [".*"]
            if finding.tool_name:
                tool_patterns = [finding.tool_name]
            elif finding.server_name:
                tool_patterns = [f"{finding.server_name}:.*"]

            rule = {
                "id": f"SCAN-{finding.rule_id}",
                "name": f"[Agent Scan] {finding.title}",
                "description": (
                    f"Auto-generated from agent-scan finding: {finding.description}. "
                    f"Severity: {finding.severity}. Category: {finding.category}."
                ),
                "action": rule_action,
                "tool_patterns": tool_patterns,
                "conditions": {
                    "source": "agent-scan",
                    "category": finding.category,
                    "severity": finding.severity,
                },
            }

            if finding.remediation:
                rule["description"] += f" Remediation: {finding.remediation}"

            rules.append(rule)

        logger.info(
            "generated policy rules from scan",
            total_findings=len(report.findings),
            rules_generated=len(rules),
            blockers=report.has_blockers,
        )
        return rules

    async def _run_scan(self, extra_args: list[str]) -> ScanReport:
        """Execute the agent-scan binary and parse output."""
        import asyncio

        cmd = [self._binary_path or self._config.binary_name, "--json", *extra_args]

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(),
                timeout=self._config.timeout_seconds,
            )

            output = stdout.decode("utf-8", errors="replace")

            if proc.returncode != 0 and not output.strip():
                err_msg = stderr.decode("utf-8", errors="replace")
                logger.error("agent-scan failed", returncode=proc.returncode, stderr=err_msg[:500])
                return ScanReport(raw_output=err_msg)

            return _parse_scan_output(output)

        except TimeoutError:
            logger.error("agent-scan timed out", timeout=self._config.timeout_seconds)
            return ScanReport(raw_output="Scan timed out")
        except FileNotFoundError:
            logger.error("agent-scan binary not found")
            return ScanReport(raw_output="agent-scan not found")
        except Exception as exc:
            logger.error("agent-scan execution error", error=str(exc))
            return ScanReport(raw_output=str(exc))


def _parse_scan_output(output: str) -> ScanReport:
    """Parse agent-scan's JSON output into a ScanReport."""
    try:
        data = json.loads(output)
    except json.JSONDecodeError:
        logger.warning("agent-scan output is not valid JSON")
        return ScanReport(raw_output=output)

    findings: list[ScanFinding] = []

    # Handle different output formats (agent-scan / mcp-scan)
    raw_findings = data.get("findings", data.get("vulnerabilities", data.get("results", [])))

    for f in raw_findings:
        findings.append(
            ScanFinding(
                rule_id=f.get("rule_id", f.get("id", "UNKNOWN")),
                severity=f.get("severity", "info").lower(),
                title=f.get("title", f.get("name", "")),
                description=f.get("description", f.get("message", "")),
                server_name=f.get("server_name", f.get("server", "")),
                tool_name=f.get("tool_name", f.get("tool", "")),
                category=f.get("category", f.get("type", "")),
                remediation=f.get("remediation", f.get("fix", "")),
            )
        )

    return ScanReport(
        scan_time=data.get("scan_time", data.get("duration", 0.0)),
        scanner_version=data.get("version", data.get("scanner_version", "")),
        servers_scanned=data.get("servers_scanned", data.get("server_count", 0)),
        findings=findings,
        raw_output=output,
    )

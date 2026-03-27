"""MCP tool description poisoning and injection detection.

Scans tool descriptions for hidden instructions, prompt injection,
privilege escalation, and shadowing attacks that exploit LLM trust.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from mcpkernel.utils import get_logger

logger = get_logger(__name__)


class Severity(StrEnum):
    """Finding severity levels."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingCategory(StrEnum):
    """Categories of tool poisoning attacks."""

    PROMPT_INJECTION = "prompt-injection"
    TOOL_SHADOWING = "tool-shadowing"
    PRIVILEGE_ESCALATION = "privilege-escalation"
    DATA_EXFILTRATION = "data-exfiltration"
    HIDDEN_INSTRUCTION = "hidden-instruction"
    UNICODE_OBFUSCATION = "unicode-obfuscation"
    CREDENTIAL_EXPOSURE = "credential-exposure"


@dataclass
class PoisoningFinding:
    """A single tool poisoning detection result."""

    rule_id: str
    category: FindingCategory
    severity: Severity
    title: str
    description: str
    tool_name: str
    server_name: str = ""
    matched_text: str = ""
    remediation: str = ""


@dataclass
class PoisoningScanReport:
    """Result of scanning MCP tools for poisoning."""

    server_name: str
    tools_scanned: int = 0
    findings: list[PoisoningFinding] = field(default_factory=list)

    @property
    def has_blockers(self) -> bool:
        return any(f.severity in (Severity.CRITICAL, Severity.HIGH) for f in self.findings)


# --- Detection Rules ---

# Patterns that indicate hidden prompt injection in tool descriptions
_INJECTION_PATTERNS: list[tuple[str, str, Severity, str]] = [
    # (pattern, title, severity, remediation)
    (
        r"(?:ignore|forget|disregard)\s+(?:all\s+)?(?:previous|prior|above|the|your)\s+(?:instructions?|rules?|constraints?|guidelines?)",
        "Prompt injection: override instructions",
        Severity.CRITICAL,
        "Remove instruction-override language from tool descriptions",
    ),
    (
        r"you\s+(?:must|should|are|will)\s+(?:always|never|now|instead)",
        "Prompt injection: behavioral directive",
        Severity.HIGH,
        "Tool descriptions should describe functionality, not give behavioral directives",
    ),
    (
        r"(?:do\s+not|don'?t|never)\s+(?:tell|inform|reveal|show|mention)\s+(?:the\s+)?user",
        "Prompt injection: concealment directive",
        Severity.CRITICAL,
        "Tool descriptions must not instruct the model to hide information from users",
    ),
    (
        r"(?:system|admin|root|sudo)\s+(?:prompt|access|privilege|mode|override)",
        "Privilege escalation: elevated access claim",
        Severity.HIGH,
        "Tool descriptions should not claim elevated privileges",
    ),
    (
        r"(?:before|after|instead\s+of)\s+(?:calling|using|executing)\s+(?:any\s+)?(?:other\s+)?tools?",
        "Tool shadowing: execution order manipulation",
        Severity.HIGH,
        "Tool descriptions should not interfere with other tools' execution",
    ),
    (
        r"(?:secretly|silently|covertly|quietly|without\s+(?:the\s+)?user(?:'?s)?\s+(?:knowledge|knowing|consent))",
        "Hidden action: stealth operation directive",
        Severity.CRITICAL,
        "Tool descriptions must not instruct covert operations",
    ),
    (
        r"(?:send|post|upload|transmit|exfiltrate|forward)\s+(?:to|data|the|all|any)\s+(?:https?://|ftp://|wss?://)",
        "Data exfiltration: outbound data transfer",
        Severity.CRITICAL,
        "Tool descriptions should not direct data to external endpoints",
    ),
    (
        r"<\s*(?:script|img|iframe|object|embed|svg|style)[\s>]",
        "XSS injection: HTML/script tag in description",
        Severity.HIGH,
        "Remove HTML/script tags from tool descriptions",
    ),
    (
        r"(?:password|api[_\s]?key|secret|token|credential)s?\s*(?:=|:|is|are)\s*['\"]?\S+",
        "Credential exposure: hardcoded secrets",
        Severity.CRITICAL,
        "Remove hardcoded credentials from tool descriptions",
    ),
    (
        r"(?:```|<code>)[\s\S]*(?:eval|exec|subprocess|os\.system|__import__|compile)\s*\(",
        "Code injection: executable code in description",
        Severity.HIGH,
        "Tool descriptions should not contain executable code snippets",
    ),
]

# Unicode obfuscation patterns
_UNICODE_SUSPICIOUS: list[tuple[str, str, Severity]] = [
    (
        r"[\u200b\u200c\u200d\u200e\u200f\ufeff]",
        "Zero-width characters detected (potential hidden text)",
        Severity.HIGH,
    ),
    (r"[\u202a-\u202e\u2066-\u2069]", "BiDi control characters detected (text direction manipulation)", Severity.HIGH),
    (r"[\U000e0001-\U000e007f]", "Unicode tag characters detected (invisible payload)", Severity.CRITICAL),
    (r"[\u0300-\u036f]{3,}", "Excessive combining characters (visual confusion attack)", Severity.MEDIUM),
    (r"[\uff01-\uff5e]", "Fullwidth characters detected (visual spoofing)", Severity.LOW),
]

# Tool name shadowing — names that mimic common built-in tools
_SHADOWED_NAMES: set[str] = {
    "read_file",
    "write_file",
    "execute_command",
    "run_terminal",
    "search_files",
    "list_directory",
    "edit_file",
    "create_file",
    "fetch_url",
    "http_request",
    "bash",
    "python",
    "shell",
}


def scan_tool_descriptions(
    tools: list[dict[str, Any]],
    server_name: str = "unknown",
) -> PoisoningScanReport:
    """Scan MCP tool descriptions for poisoning and injection attacks.

    Parameters
    ----------
    tools:
        List of MCP tool definitions, each with ``name``, ``description``,
        and optionally ``inputSchema``.
    server_name:
        Name of the MCP server these tools belong to.
    """
    report = PoisoningScanReport(server_name=server_name, tools_scanned=len(tools))

    for tool in tools:
        tool_name = tool.get("name", "unnamed")
        description = tool.get("description", "")
        input_schema = tool.get("inputSchema", {})

        # Combine text to scan
        text_to_scan = description
        if isinstance(input_schema, dict):
            # Include parameter descriptions
            for _prop_name, prop_def in input_schema.get("properties", {}).items():
                if isinstance(prop_def, dict) and "description" in prop_def:
                    text_to_scan += f"\n{prop_def['description']}"

        # 1. Check injection patterns
        for pattern, title, severity, remediation in _INJECTION_PATTERNS:
            match = re.search(pattern, text_to_scan, re.IGNORECASE)
            if match:
                report.findings.append(
                    PoisoningFinding(
                        rule_id=f"POISON-{len(report.findings) + 1:03d}",
                        category=_categorize_pattern(title),
                        severity=severity,
                        title=title,
                        description=f"Tool '{tool_name}' description contains suspicious pattern",
                        tool_name=tool_name,
                        server_name=server_name,
                        matched_text=match.group(0)[:100],
                        remediation=remediation,
                    )
                )

        # 2. Check unicode obfuscation
        for pattern, title, severity in _UNICODE_SUSPICIOUS:
            match = re.search(pattern, text_to_scan)
            if match:
                report.findings.append(
                    PoisoningFinding(
                        rule_id=f"POISON-{len(report.findings) + 1:03d}",
                        category=FindingCategory.UNICODE_OBFUSCATION,
                        severity=severity,
                        title=title,
                        description=f"Tool '{tool_name}' contains obfuscated unicode characters",
                        tool_name=tool_name,
                        server_name=server_name,
                        matched_text=repr(match.group(0))[:100],
                        remediation="Remove hidden unicode characters from tool descriptions",
                    )
                )

        # 3. Check tool name shadowing
        if tool_name.lower().replace("-", "_") in _SHADOWED_NAMES:
            report.findings.append(
                PoisoningFinding(
                    rule_id=f"POISON-{len(report.findings) + 1:03d}",
                    category=FindingCategory.TOOL_SHADOWING,
                    severity=Severity.MEDIUM,
                    title=f"Tool name '{tool_name}' shadows a common built-in tool",
                    description="This tool name may confuse the LLM into calling it instead of the legitimate built-in",
                    tool_name=tool_name,
                    server_name=server_name,
                    remediation="Use a unique, namespaced tool name to avoid shadowing",
                )
            )

        # 4. Check for excessively long descriptions (>2000 chars)
        if len(description) > 2000:
            report.findings.append(
                PoisoningFinding(
                    rule_id=f"POISON-{len(report.findings) + 1:03d}",
                    category=FindingCategory.HIDDEN_INSTRUCTION,
                    severity=Severity.MEDIUM,
                    title="Excessively long tool description",
                    description=(
                        f"Tool '{tool_name}' has a {len(description)}-char description"
                        " — may contain hidden instructions"
                    ),
                    tool_name=tool_name,
                    server_name=server_name,
                    remediation="Keep tool descriptions concise (<500 chars). Review for hidden content.",
                )
            )

    if report.findings:
        logger.warning(
            "tool_poisoning_detected",
            server=server_name,
            finding_count=len(report.findings),
            critical_count=sum(1 for f in report.findings if f.severity == Severity.CRITICAL),
        )
    else:
        logger.info("tool_poisoning_scan_clean", server=server_name, tools_scanned=len(tools))

    return report


def _categorize_pattern(title: str) -> FindingCategory:
    """Categorize a finding based on its title."""
    title_lower = title.lower()
    if "injection" in title_lower or "xss" in title_lower:
        return FindingCategory.PROMPT_INJECTION
    if "shadow" in title_lower:
        return FindingCategory.TOOL_SHADOWING
    if "privilege" in title_lower:
        return FindingCategory.PRIVILEGE_ESCALATION
    if "exfiltration" in title_lower or "data" in title_lower:
        return FindingCategory.DATA_EXFILTRATION
    if "concealment" in title_lower or "hidden" in title_lower or "stealth" in title_lower:
        return FindingCategory.HIDDEN_INSTRUCTION
    if "credential" in title_lower:
        return FindingCategory.CREDENTIAL_EXPOSURE
    return FindingCategory.PROMPT_INJECTION

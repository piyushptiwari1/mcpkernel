# ruff: noqa: E501
"""Toxic Flow Analyzer — static "lethal trifecta" detection for MCP tool sets.

Inspired by Invariant Labs' Toxic Flow Analysis (TFA) — see
https://invariantlabs.ai/blog/toxic-flow-analysis. The "lethal trifecta"
(coined by Simon Willison) describes the combination of capabilities that
turn an otherwise innocent agent into a data-exfiltration vehicle:

  1. **Untrusted input** — a tool that returns attacker-controlled content
     (web search, email read, file contents, MCP resource fetch, elicitation
     response, etc.).
  2. **Sensitive data access** — a tool that can read secrets, credentials,
     PII, private files, or internal APIs.
  3. **Exfil sink** — a tool that can transmit data outside the trust
     boundary (HTTP POST, email send, slack post, db insert, file upload,
     etc.).

Whenever a single agent has access to a tool from each category, there is a
*path* by which a prompt injection in (1) can coerce the model into
extracting (2) and transmitting via (3). The analyzer enumerates every such
path **before runtime**, producing a SARIF report consumable by GitHub
Code Scanning / Defender / Snyk.

This complements (rather than replaces) MCPKernel's runtime taint engine.
The taint engine catches violations as they happen; the flow analyzer
catches dangerous tool *configurations* before a single request is served.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from mcpkernel.utils import get_logger

logger = get_logger(__name__)

__all__ = [
    "FlowCategory",
    "FlowFinding",
    "FlowSeverity",
    "ToolFlowProfile",
    "ToxicFlowAnalyzer",
    "analyze_tool_manifest",
]


class FlowCategory(StrEnum):
    """The three legs of the lethal trifecta."""

    UNTRUSTED_INPUT = "untrusted_input"
    SENSITIVE_DATA = "sensitive_data"
    EXFIL_SINK = "exfil_sink"


class FlowSeverity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


# ---------------------------------------------------------------------------
# Built-in classification heuristics
# ---------------------------------------------------------------------------
# Each entry: (regex on tool name OR description, category, confidence 0-1).
# Confidence < 1.0 lets policy authors require a second confirming signal
# before flagging a path as critical.

_CLASSIFIERS: list[tuple[re.Pattern[str], FlowCategory, float]] = [
    # --- Untrusted input -------------------------------------------------
    (re.compile(r"\b(web[_-]?search|google|bing|duckduckgo)\b", re.I), FlowCategory.UNTRUSTED_INPUT, 1.0),
    (re.compile(r"\b(fetch[_-]?url|http[_-]?get|browse|scrape|crawl)\b", re.I), FlowCategory.UNTRUSTED_INPUT, 1.0),
    (re.compile(r"\b(read[_-]?email|email[_-]?fetch|imap|gmail)\b", re.I), FlowCategory.UNTRUSTED_INPUT, 1.0),
    (re.compile(r"\b(read[_-]?file|cat|fs[_-]?read|filesystem[_-]?read)\b", re.I), FlowCategory.UNTRUSTED_INPUT, 0.7),
    (
        re.compile(r"\b(github[_-]?(issues?|comments?|prs?)|gitlab[_-]?(issues?|comments?))\b", re.I),
        FlowCategory.UNTRUSTED_INPUT,
        1.0,
    ),
    (
        re.compile(r"\b(slack[_-]?read|teams[_-]?read|discord[_-]?read|chat[_-]?history)\b", re.I),
        FlowCategory.UNTRUSTED_INPUT,
        1.0,
    ),
    (re.compile(r"\b(elicit|user[_-]?input|prompt[_-]?user)\b", re.I), FlowCategory.UNTRUSTED_INPUT, 1.0),
    (re.compile(r"\b(resources?[/_-]?read|mcp[_-]?resource)\b", re.I), FlowCategory.UNTRUSTED_INPUT, 0.8),
    # --- Sensitive data --------------------------------------------------
    (re.compile(r"\b(secret|password|credential|token|api[_-]?key)\b", re.I), FlowCategory.SENSITIVE_DATA, 1.0),
    (re.compile(r"\b(env|environment|dotenv|\.env)\b", re.I), FlowCategory.SENSITIVE_DATA, 1.0),
    (re.compile(r"\b(vault|secrets[_-]?manager|kms|hashicorp)\b", re.I), FlowCategory.SENSITIVE_DATA, 1.0),
    (re.compile(r"\b(ssh[_-]?key|private[_-]?key|pem|gpg)\b", re.I), FlowCategory.SENSITIVE_DATA, 1.0),
    (re.compile(r"\b(database|db[_-]?query|sql|postgres|mysql|mongo)\b", re.I), FlowCategory.SENSITIVE_DATA, 0.8),
    (re.compile(r"\b(internal[_-]?api|admin[_-]?api|management[_-]?api)\b", re.I), FlowCategory.SENSITIVE_DATA, 0.9),
    (
        re.compile(r"\b(pii|personal[_-]?data|customer[_-]?data|user[_-]?data)\b", re.I),
        FlowCategory.SENSITIVE_DATA,
        1.0,
    ),
    (re.compile(r"\b(read[_-]?file|cat|fs[_-]?read)\b", re.I), FlowCategory.SENSITIVE_DATA, 0.5),
    # --- Exfil sinks -----------------------------------------------------
    (re.compile(r"\b(http[_-]?post|http[_-]?put|http[_-]?request|fetch)\b", re.I), FlowCategory.EXFIL_SINK, 1.0),
    (re.compile(r"\b(send[_-]?email|email[_-]?send|smtp|sendmail)\b", re.I), FlowCategory.EXFIL_SINK, 1.0),
    (
        re.compile(r"\b(slack[_-]?post|slack[_-]?send|teams[_-]?post|discord[_-]?send)\b", re.I),
        FlowCategory.EXFIL_SINK,
        1.0,
    ),
    (re.compile(r"\b(webhook|zapier|ifttt|n8n)\b", re.I), FlowCategory.EXFIL_SINK, 1.0),
    (re.compile(r"\b(upload|s3[_-]?put|blob[_-]?upload|gcs[_-]?upload)\b", re.I), FlowCategory.EXFIL_SINK, 1.0),
    (re.compile(r"\b(write[_-]?file|fs[_-]?write|file[_-]?write)\b", re.I), FlowCategory.EXFIL_SINK, 0.4),
    (re.compile(r"\b(dns[_-]?query|nslookup|resolve)\b", re.I), FlowCategory.EXFIL_SINK, 0.7),
    (
        re.compile(r"\b(open[_-]?url|browser[_-]?open|render[_-]?image|fetch[_-]?image)\b", re.I),
        FlowCategory.EXFIL_SINK,
        0.9,
    ),
]


@dataclass
class ToolFlowProfile:
    """The categories a single tool participates in."""

    name: str
    categories: dict[FlowCategory, float] = field(default_factory=dict)
    description: str = ""

    @property
    def is_untrusted_input(self) -> bool:
        return FlowCategory.UNTRUSTED_INPUT in self.categories

    @property
    def is_sensitive_data(self) -> bool:
        return FlowCategory.SENSITIVE_DATA in self.categories

    @property
    def is_exfil_sink(self) -> bool:
        return FlowCategory.EXFIL_SINK in self.categories


@dataclass
class FlowFinding:
    """A detected lethal-trifecta path."""

    severity: FlowSeverity
    untrusted_input: str  # tool name
    sensitive_data: str  # tool name
    exfil_sink: str  # tool name
    confidence: float
    description: str
    remediation: str = ""

    @property
    def rule_id(self) -> str:
        return "TFA-001-lethal-trifecta"

    def to_sarif_result(self) -> dict[str, Any]:
        """Convert to a SARIFResult-shaped dict (delayed import to avoid cycle)."""
        return {
            "rule_id": self.rule_id,
            "level": "error" if self.severity in (FlowSeverity.CRITICAL, FlowSeverity.HIGH) else "warning",
            "message": self.description,
            "help_text": self.remediation,
            "help_uri": "https://github.com/piyushptiwari1/mcpkernel/blob/main/docs/security/toxic-flow.md",
        }


class ToxicFlowAnalyzer:
    """Detect lethal-trifecta tool combinations in an MCP tool manifest.

    Usage::

        analyzer = ToxicFlowAnalyzer()
        analyzer.classify_tools(tools)        # tools: list of dicts with {name, description}
        findings = analyzer.find_toxic_flows()
        for f in findings:
            print(f.severity, f.description)
    """

    def __init__(
        self,
        *,
        custom_classifiers: list[tuple[re.Pattern[str], FlowCategory, float]] | None = None,
        explicit_overrides: dict[str, set[FlowCategory]] | None = None,
    ) -> None:
        """Construct the analyzer.

        Parameters
        ----------
        custom_classifiers:
            Additional regex/category/confidence triples appended to the
            built-in set. Use this for project-specific tool naming.
        explicit_overrides:
            Map of ``tool_name -> {FlowCategory, ...}`` that bypasses the
            regex heuristics entirely. Useful when a tool's name doesn't
            match any pattern but the operator knows its true category.
        """
        self._classifiers = list(_CLASSIFIERS) + (custom_classifiers or [])
        self._overrides = explicit_overrides or {}
        self._profiles: dict[str, ToolFlowProfile] = {}

    # ------------------------------------------------------------------
    # Classification
    # ------------------------------------------------------------------
    def classify_tool(self, name: str, description: str = "") -> ToolFlowProfile:
        """Classify a single tool by name + description."""
        raw = f"{name} {description}".lower()
        # Also build a version with ``_`` / ``-`` replaced by spaces so
        # ``\b`` word boundaries fire correctly for ``read_secret`` etc.
        # We search both variants and take whichever matches.
        spaced = re.sub(r"[_\-]+", " ", raw)
        profile = ToolFlowProfile(name=name, description=description)

        # Explicit override wins
        if name in self._overrides:
            for cat in self._overrides[name]:
                profile.categories[cat] = 1.0
            self._profiles[name] = profile
            return profile

        for pattern, category, confidence in self._classifiers:
            if pattern.search(raw) or pattern.search(spaced):
                # Take max confidence if a tool matches multiple patterns of
                # the same category.
                profile.categories[category] = max(profile.categories.get(category, 0.0), confidence)

        self._profiles[name] = profile
        return profile

    def classify_tools(self, tools: list[dict[str, Any]]) -> dict[str, ToolFlowProfile]:
        """Classify a list of tool definitions.

        ``tools`` accepts the MCP ``tools/list`` shape: each entry must
        provide a ``name`` and may provide a ``description``.
        """
        for tool in tools:
            self.classify_tool(
                name=str(tool.get("name", "")),
                description=str(tool.get("description", "")),
            )
        return self._profiles

    # ------------------------------------------------------------------
    # Flow analysis
    # ------------------------------------------------------------------
    def find_toxic_flows(self, *, min_confidence: float = 0.6) -> list[FlowFinding]:
        """Enumerate every (untrusted, sensitive, sink) triple in the manifest.

        Parameters
        ----------
        min_confidence:
            Drop classifications below this confidence before combining.
            Default 0.6 — high enough to suppress regex noise, low enough to
            catch the common cases.
        """
        untrusted = [
            (n, p.categories[FlowCategory.UNTRUSTED_INPUT])
            for n, p in self._profiles.items()
            if p.categories.get(FlowCategory.UNTRUSTED_INPUT, 0) >= min_confidence
        ]
        sensitive = [
            (n, p.categories[FlowCategory.SENSITIVE_DATA])
            for n, p in self._profiles.items()
            if p.categories.get(FlowCategory.SENSITIVE_DATA, 0) >= min_confidence
        ]
        sinks = [
            (n, p.categories[FlowCategory.EXFIL_SINK])
            for n, p in self._profiles.items()
            if p.categories.get(FlowCategory.EXFIL_SINK, 0) >= min_confidence
        ]

        findings: list[FlowFinding] = []
        for u_name, u_conf in untrusted:
            for s_name, s_conf in sensitive:
                for x_name, x_conf in sinks:
                    # A single tool can play multiple roles — that's actually
                    # *worse*, not better. But triples of three distinct
                    # tools are the canonical case; we include same-tool
                    # combinations too with a confidence multiplier.
                    confidence = u_conf * s_conf * x_conf
                    severity = self._classify_severity(confidence, u_name, s_name, x_name)
                    description = (
                        f"Lethal trifecta detected: untrusted input from "
                        f"'{u_name}' could be combined with sensitive data "
                        f"from '{s_name}' and exfiltrated via '{x_name}'. "
                        f"A prompt injection in '{u_name}' could coerce the "
                        f"model into reading data via '{s_name}' and "
                        f"transmitting it via '{x_name}'."
                    )
                    remediation = (
                        "Remove one leg of the trifecta from this agent's tool "
                        "list, isolate them in separate agents, or enforce a "
                        "TaintHook policy that blocks tainted data from "
                        f"reaching '{x_name}'."
                    )
                    findings.append(
                        FlowFinding(
                            severity=severity,
                            untrusted_input=u_name,
                            sensitive_data=s_name,
                            exfil_sink=x_name,
                            confidence=confidence,
                            description=description,
                            remediation=remediation,
                        )
                    )

        # Sort by severity descending then confidence descending
        sev_order = {FlowSeverity.CRITICAL: 0, FlowSeverity.HIGH: 1, FlowSeverity.MEDIUM: 2, FlowSeverity.LOW: 3}
        findings.sort(key=lambda f: (sev_order[f.severity], -f.confidence))
        return findings

    @staticmethod
    def _classify_severity(
        confidence: float,
        untrusted: str,
        sensitive: str,
        sink: str,
    ) -> FlowSeverity:
        """Severity heuristic.

        A single tool that wears all three hats is the most dangerous case
        (no model mediation needed). Confidence >= 0.9 across all legs is
        critical; >= 0.7 high; >= 0.5 medium; else low.
        """
        distinct = len({untrusted, sensitive, sink})
        if distinct == 1:
            return FlowSeverity.CRITICAL
        if confidence >= 0.9:
            return FlowSeverity.CRITICAL if distinct == 2 else FlowSeverity.HIGH
        if confidence >= 0.7:
            return FlowSeverity.HIGH
        if confidence >= 0.5:
            return FlowSeverity.MEDIUM
        return FlowSeverity.LOW

    # ------------------------------------------------------------------
    # Output helpers
    # ------------------------------------------------------------------
    def to_sarif(self, findings: list[FlowFinding] | None = None) -> dict[str, Any]:
        """Render findings as a SARIF 2.1.0 document."""
        from mcpkernel.audit.sarif import SARIFResult, generate_sarif

        if findings is None:
            findings = self.find_toxic_flows()

        results = [
            SARIFResult(
                rule_id=f.rule_id,
                level="error" if f.severity in (FlowSeverity.CRITICAL, FlowSeverity.HIGH) else "warning",
                message=f.description,
                help_text=f.remediation,
                help_uri="https://github.com/piyushptiwari1/mcpkernel/blob/main/docs/security/toxic-flow.md",
            )
            for f in findings
        ]
        return generate_sarif(results, tool_name="mcpkernel-tfa")

    def summary(self, findings: list[FlowFinding] | None = None) -> str:
        """Produce a human-readable Markdown summary."""
        if findings is None:
            findings = self.find_toxic_flows()
        if not findings:
            return "✓ No toxic flows detected."

        lines = [f"# Toxic Flow Analysis — {len(findings)} finding(s)", ""]
        by_sev: dict[FlowSeverity, list[FlowFinding]] = {}
        for f in findings:
            by_sev.setdefault(f.severity, []).append(f)

        for sev in (FlowSeverity.CRITICAL, FlowSeverity.HIGH, FlowSeverity.MEDIUM, FlowSeverity.LOW):
            if sev not in by_sev:
                continue
            lines.append(f"## {sev.value.upper()} ({len(by_sev[sev])})")
            for f in by_sev[sev]:
                lines.append(
                    f"- `{f.untrusted_input}` -> `{f.sensitive_data}` -> "
                    f"`{f.exfil_sink}` (confidence={f.confidence:.2f})"
                )
            lines.append("")

        return "\n".join(lines)


def analyze_tool_manifest(
    tools: list[dict[str, Any]],
    *,
    min_confidence: float = 0.6,
    custom_classifiers: list[tuple[re.Pattern[str], FlowCategory, float]] | None = None,
    explicit_overrides: dict[str, set[FlowCategory]] | None = None,
) -> list[FlowFinding]:
    """Convenience one-shot entrypoint.

    Example::

        from mcpkernel.taint import analyze_tool_manifest

        findings = analyze_tool_manifest([
            {"name": "web_search", "description": "Search the web"},
            {"name": "read_secret", "description": "Read from Vault"},
            {"name": "http_post", "description": "Send HTTP POST"},
        ])
        # -> 1 critical finding: web_search + read_secret + http_post
    """
    analyzer = ToxicFlowAnalyzer(
        custom_classifiers=custom_classifiers,
        explicit_overrides=explicit_overrides,
    )
    analyzer.classify_tools(tools)
    return analyzer.find_toxic_flows(min_confidence=min_confidence)

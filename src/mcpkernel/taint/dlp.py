"""DLP (Data Loss Prevention) chain detection for MCP tool calls.

Detects dangerous data-flow chains like:
  read_file(.env) → http_post(external_url)   -- SECRET exfiltration
  query_database(users) → email_send(external) -- PII exfiltration
  user_input → execute_code                    -- Injection chain

This extends the taint module with pattern-based chain analysis.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from mcpkernel.taint.tracker import TaintLabel
from mcpkernel.utils import get_logger

logger = get_logger(__name__)


class ChainSeverity(StrEnum):
    """Severity of a detected data-flow chain."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class DLPChainRule:
    """A rule that defines a dangerous data-flow chain."""

    rule_id: str
    name: str
    description: str
    severity: ChainSeverity

    # Source: tool patterns that produce sensitive data
    source_tools: list[str]
    source_labels: set[TaintLabel]

    # Sink: tool patterns that would exfiltrate the data
    sink_tools: list[str]

    # Maximum number of hops between source and sink
    max_chain_length: int = 5


@dataclass
class DLPChainViolation:
    """A detected dangerous data-flow chain."""

    rule: DLPChainRule
    chain: list[str]  # tool names in order
    source_tool: str
    sink_tool: str
    labels: set[TaintLabel]
    metadata: dict[str, Any] = field(default_factory=dict)


# Built-in DLP chain rules
BUILTIN_DLP_RULES: list[DLPChainRule] = [
    DLPChainRule(
        rule_id="DLP-001",
        name="Secret exfiltration via HTTP",
        description="Sensitive file read followed by outbound HTTP request",
        severity=ChainSeverity.CRITICAL,
        source_tools=["read_file", "file_read", "get_file", "cat"],
        source_labels={TaintLabel.SECRET},
        sink_tools=["http_post", "http_request", "fetch", "curl", "wget", "send_request"],
    ),
    DLPChainRule(
        rule_id="DLP-002",
        name="PII exfiltration via email",
        description="Database/user data query followed by email transmission",
        severity=ChainSeverity.CRITICAL,
        source_tools=["query_database", "sql_query", "db_query", "get_users", "list_users"],
        source_labels={TaintLabel.PII},
        sink_tools=["email_send", "send_email", "send_message", "smtp_send"],
    ),
    DLPChainRule(
        rule_id="DLP-003",
        name="Secret exfiltration via email",
        description="Secret/credential read followed by email transmission",
        severity=ChainSeverity.CRITICAL,
        source_tools=["read_file", "file_read", "get_secret", "get_env"],
        source_labels={TaintLabel.SECRET},
        sink_tools=["email_send", "send_email", "send_message"],
    ),
    DLPChainRule(
        rule_id="DLP-004",
        name="User input to code execution",
        description="User input flowing into code execution (injection risk)",
        severity=ChainSeverity.HIGH,
        source_tools=["get_input", "prompt_user", "chat", "ask"],
        source_labels={TaintLabel.USER_INPUT},
        sink_tools=["execute_code", "run_code", "eval", "exec", "shell", "bash", "run_terminal"],
    ),
    DLPChainRule(
        rule_id="DLP-005",
        name="PII to external API",
        description="PII data flowing to external third-party APIs",
        severity=ChainSeverity.HIGH,
        source_tools=["query_database", "get_users", "list_contacts", "search_users"],
        source_labels={TaintLabel.PII},
        sink_tools=["http_post", "http_request", "api_call", "webhook"],
    ),
    DLPChainRule(
        rule_id="DLP-006",
        name="LLM output to file write",
        description="Unchecked LLM output written directly to filesystem",
        severity=ChainSeverity.MEDIUM,
        source_tools=["generate", "complete", "chat", "llm_call"],
        source_labels={TaintLabel.LLM_OUTPUT},
        sink_tools=["write_file", "file_write", "save_file", "create_file"],
    ),
    DLPChainRule(
        rule_id="DLP-007",
        name="External data to code execution",
        description="Untrusted external data flowing into code execution",
        severity=ChainSeverity.CRITICAL,
        source_tools=["http_get", "fetch_url", "download", "scrape"],
        source_labels={TaintLabel.UNTRUSTED_EXTERNAL},
        sink_tools=["execute_code", "run_code", "eval", "exec", "shell", "bash"],
    ),
]


def _tool_matches(tool_name: str, patterns: list[str]) -> bool:
    """Check if a tool name matches any of the pattern names."""
    normalized = tool_name.lower().replace("-", "_").replace(".", "_")
    for pat in patterns:
        pat_norm = pat.lower().replace("-", "_").replace(".", "_")
        if pat_norm in normalized or normalized in pat_norm:
            return True
    return False


class DLPChainDetector:
    """Analyzes sequences of MCP tool calls for dangerous data-flow chains.

    Usage:
        detector = DLPChainDetector()
        detector.record_call("read_file", {TaintLabel.SECRET})
        detector.record_call("summarize", {TaintLabel.SECRET})  # propagated
        violations = detector.record_call("http_post", {TaintLabel.SECRET})
        # violations will contain DLP-001
    """

    def __init__(
        self,
        *,
        custom_rules: list[DLPChainRule] | None = None,
        enabled: bool = True,
    ) -> None:
        self._rules = BUILTIN_DLP_RULES + (custom_rules or [])
        self._enabled = enabled
        # Track: (tool_name, taint_labels) in order
        self._call_chain: list[tuple[str, set[TaintLabel]]] = []
        self._violations: list[DLPChainViolation] = []

    def record_call(
        self,
        tool_name: str,
        labels: set[TaintLabel],
    ) -> list[DLPChainViolation]:
        """Record a tool call and check for DLP chain violations.

        Returns any new violations detected by this call.
        """
        if not self._enabled:
            return []

        self._call_chain.append((tool_name, set(labels)))
        new_violations: list[DLPChainViolation] = []

        for rule in self._rules:
            # Is this call a sink for this rule?
            if not _tool_matches(tool_name, rule.sink_tools):
                continue

            # Do the current labels match the rule's source labels?
            if not (labels & rule.source_labels):
                continue

            # Walk backward to find a matching source within max_chain_length
            chain_start = max(0, len(self._call_chain) - rule.max_chain_length - 1)
            for i in range(chain_start, len(self._call_chain) - 1):
                past_tool, past_labels = self._call_chain[i]
                if _tool_matches(past_tool, rule.source_tools) and (past_labels & rule.source_labels):
                    # Found a complete chain!
                    chain = [t for t, _ in self._call_chain[i:]]

                    violation = DLPChainViolation(
                        rule=rule,
                        chain=chain,
                        source_tool=past_tool,
                        sink_tool=tool_name,
                        labels=labels & rule.source_labels,
                    )
                    new_violations.append(violation)
                    self._violations.append(violation)

                    logger.warning(
                        "dlp_chain_detected",
                        rule_id=rule.rule_id,
                        rule_name=rule.name,
                        severity=rule.severity.value,
                        chain=" → ".join(chain),
                        source=past_tool,
                        sink=tool_name,
                    )
                    break  # One match per rule is enough

        return new_violations

    @property
    def violations(self) -> list[DLPChainViolation]:
        """All violations detected so far."""
        return list(self._violations)

    @property
    def call_chain(self) -> list[tuple[str, set[TaintLabel]]]:
        """Full call chain recorded so far."""
        return list(self._call_chain)

    def reset(self) -> None:
        """Clear call history and violations (e.g., between sessions)."""
        self._call_chain.clear()
        self._violations.clear()

    def summarize(self) -> str:
        """Return a human-readable summary of detected violations."""
        if not self._violations:
            return "No DLP chain violations detected."

        lines: list[str] = [f"Detected {len(self._violations)} DLP chain violation(s):\n"]
        for v in self._violations:
            lines.append(f"  [{v.rule.severity.value.upper()}] {v.rule.rule_id}: {v.rule.name}")
            lines.append(f"    Chain: {' → '.join(v.chain)}")
            lines.append(f"    Labels: {', '.join(lbl.value for lbl in v.labels)}")
            lines.append(f"    {v.rule.description}")
            lines.append("")

        return "\n".join(lines)

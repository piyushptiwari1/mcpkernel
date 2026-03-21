"""Core policy engine — evaluate rules against tool calls."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from mcpguard.utils import get_logger

logger = get_logger(__name__)


class PolicyAction(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    AUDIT = "audit"
    SANDBOX = "sandbox"
    WARN = "warn"


@dataclass
class PolicyRule:
    """A single policy rule."""

    id: str
    name: str
    description: str = ""
    action: PolicyAction = PolicyAction.DENY
    priority: int = 100
    # Matching criteria
    tool_patterns: list[str] = field(default_factory=list)
    argument_patterns: dict[str, str] = field(default_factory=dict)
    taint_labels: list[str] = field(default_factory=list)
    # OWASP ASI 2026 mapping
    owasp_asi_id: str = ""
    # Conditions
    conditions: dict[str, Any] = field(default_factory=dict)
    enabled: bool = True


@dataclass
class PolicyDecision:
    """Result of policy evaluation."""

    action: PolicyAction
    matched_rules: list[PolicyRule]
    reasons: list[str]
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def allowed(self) -> bool:
        return self.action in (PolicyAction.ALLOW, PolicyAction.AUDIT, PolicyAction.WARN)


class PolicyEngine:
    """Evaluate tool calls against a set of policy rules.

    Rules are matched by tool name pattern, argument patterns, and
    taint labels.  The highest-priority matching rule wins (lowest
    priority number = highest precedence).
    """

    def __init__(self, *, default_action: PolicyAction = PolicyAction.ALLOW) -> None:
        self._rules: list[PolicyRule] = []
        self._default_action = default_action

    def add_rule(self, rule: PolicyRule) -> None:
        self._rules.append(rule)
        self._rules.sort(key=lambda r: r.priority)
        logger.debug("policy rule added", rule_id=rule.id, priority=rule.priority)

    def add_rules(self, rules: list[PolicyRule]) -> None:
        for rule in rules:
            self.add_rule(rule)

    def remove_rule(self, rule_id: str) -> None:
        self._rules = [r for r in self._rules if r.id != rule_id]

    def evaluate(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        *,
        taint_labels: set[str] | None = None,
        context: dict[str, Any] | None = None,
    ) -> PolicyDecision:
        """Evaluate all matching rules and return the decision.

        The most restrictive matching rule wins.
        """
        matched: list[PolicyRule] = []
        reasons: list[str] = []

        for rule in self._rules:
            if not rule.enabled:
                continue

            if not self._matches_tool(rule, tool_name):
                continue

            if not self._matches_arguments(rule, arguments):
                continue

            if not self._matches_taint(rule, taint_labels or set()):
                continue

            if not self._matches_conditions(rule, context or {}):
                continue

            matched.append(rule)
            reasons.append(f"[{rule.id}] {rule.name}: {rule.description}")

        if not matched:
            return PolicyDecision(
                action=self._default_action,
                matched_rules=[],
                reasons=[f"No matching policy rules — default {self._default_action.value}"],
            )

        # Most restrictive action wins (DENY > SANDBOX > WARN > AUDIT > ALLOW)
        action_precedence = {
            PolicyAction.DENY: 0,
            PolicyAction.SANDBOX: 1,
            PolicyAction.WARN: 2,
            PolicyAction.AUDIT: 3,
            PolicyAction.ALLOW: 4,
        }
        final_action = min(
            (r.action for r in matched),
            key=lambda a: action_precedence.get(a, 99),
        )

        decision = PolicyDecision(
            action=final_action,
            matched_rules=matched,
            reasons=reasons,
            metadata={
                "owasp_asi_ids": [r.owasp_asi_id for r in matched if r.owasp_asi_id],
            },
        )
        logger.info(
            "policy evaluated",
            tool=tool_name,
            action=final_action.value,
            matched_count=len(matched),
        )
        return decision

    @staticmethod
    def _matches_tool(rule: PolicyRule, tool_name: str) -> bool:
        if not rule.tool_patterns:
            return True  # No tool filter = matches all
        for pat in rule.tool_patterns:
            try:
                if re.fullmatch(pat, tool_name):
                    return True
            except re.error as exc:
                logger.warning(
                    "invalid regex in tool_patterns — skipping",
                    rule_id=rule.id,
                    pattern=pat,
                    error=str(exc),
                )
        return False

    @staticmethod
    def _matches_arguments(rule: PolicyRule, arguments: dict[str, Any]) -> bool:
        if not rule.argument_patterns:
            return True
        for key, pattern in rule.argument_patterns.items():
            value = arguments.get(key)
            if value is None:
                return False
            try:
                if not re.search(pattern, str(value)):
                    return False
            except re.error as exc:
                logger.warning(
                    "invalid regex in argument_patterns — skipping",
                    rule_id=rule.id,
                    argument=key,
                    pattern=pattern,
                    error=str(exc),
                )
                return False
        return True

    @staticmethod
    def _matches_taint(rule: PolicyRule, taint_labels: set[str]) -> bool:
        if not rule.taint_labels:
            return True
        return bool(set(rule.taint_labels) & taint_labels)

    @staticmethod
    def _matches_conditions(rule: PolicyRule, context: dict[str, Any]) -> bool:
        if not rule.conditions:
            return True
        for key, expected in rule.conditions.items():
            actual = context.get(key)
            if actual != expected:
                return False
        return True

    @property
    def rules(self) -> list[PolicyRule]:
        return list(self._rules)

    def summary(self) -> dict[str, Any]:
        return {
            "total_rules": len(self._rules),
            "enabled": sum(1 for r in self._rules if r.enabled),
            "by_action": {
                action.value: sum(1 for r in self._rules if r.action == action)
                for action in PolicyAction
            },
        }

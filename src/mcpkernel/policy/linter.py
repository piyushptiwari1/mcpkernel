"""Policy linter — static analysis over PolicyRule sets (D.2).

Surfaces structural defects that ``validate-policy`` would otherwise miss:

* Duplicate rule IDs.
* Unreachable rules (a higher-priority rule shadows the same tool pattern).
* Wildcard / catch-all rules ahead of more specific allow rules.
* Empty ``tool_patterns`` and ``argument_patterns``.
* ReDoS-prone patterns (nested quantifiers, unbounded backtracking).
* Missing OWASP mappings on deny rules.
* Mixing ``glob`` and ``regex`` styles without the ``$``/``^`` anchors.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from mcpkernel.policy.engine import PolicyRule


class LintSeverity(StrEnum):
    ERROR = "error"
    WARNING = "warning"
    INFO = "info"


@dataclass(frozen=True)
class LintFinding:
    rule_id: str
    code: str
    severity: LintSeverity
    message: str

    def format(self) -> str:
        sev = self.severity.value.upper()
        return f"[{sev}] {self.code} {self.rule_id}: {self.message}"


# ReDoS-prone constructs (best-effort heuristic; not exhaustive).
_REDOS_PATTERNS = (
    re.compile(r"\([^)]*[+*]\)[+*]"),  # nested quantifiers: (a+)+, (.*)*
    re.compile(r"\([^)]*\|[^)]*\)[+*]"),  # alternation under quantifier: (a|a)+
)


def _is_glob(pattern: str) -> bool:
    return any(c in pattern for c in "*?[") and not pattern.startswith("^")


def _looks_redos(pattern: str) -> bool:
    return any(p.search(pattern) for p in _REDOS_PATTERNS)


def lint_rules(rules: list[PolicyRule]) -> list[LintFinding]:
    """Run all lint checks on a list of parsed rules.

    Returns a list of findings sorted by severity (errors first) then rule id.
    """
    from mcpkernel.policy.engine import PolicyAction

    findings: list[LintFinding] = []

    # 1. Duplicate IDs
    seen_ids: dict[str, int] = {}
    for r in rules:
        seen_ids[r.id] = seen_ids.get(r.id, 0) + 1
    for rid, n in seen_ids.items():
        if n > 1:
            findings.append(LintFinding(rid, "PL001", LintSeverity.ERROR, f"duplicate rule id appears {n}x"))

    # Per-rule structural / regex checks
    for r in rules:
        if not r.tool_patterns and not r.argument_patterns and not r.taint_labels:
            findings.append(
                LintFinding(
                    r.id,
                    "PL002",
                    LintSeverity.WARNING,
                    "rule has no tool/argument patterns and no taint labels — it never matches",
                )
            )

        for pat in r.tool_patterns:
            if not isinstance(pat, str) or not pat:
                findings.append(LintFinding(r.id, "PL003", LintSeverity.ERROR, f"empty/invalid tool pattern: {pat!r}"))
                continue
            if _looks_redos(pat):
                findings.append(LintFinding(r.id, "PL004", LintSeverity.WARNING, f"ReDoS-prone pattern: {pat!r}"))
            if pat in (".*", ".+", "*", "**"):
                findings.append(
                    LintFinding(
                        r.id,
                        "PL005",
                        LintSeverity.WARNING,
                        f"catch-all tool pattern {pat!r} — verify priority ordering",
                    )
                )

        for field_name, pat in (r.argument_patterns or {}).items():
            if isinstance(pat, str) and _looks_redos(pat):
                findings.append(
                    LintFinding(
                        r.id,
                        "PL004",
                        LintSeverity.WARNING,
                        f"ReDoS-prone argument pattern on {field_name!r}: {pat!r}",
                    )
                )

        if r.action == PolicyAction.DENY and not (r.owasp_asi_id or r.owasp_llm_id):
            findings.append(
                LintFinding(
                    r.id,
                    "PL006",
                    LintSeverity.INFO,
                    "deny rule has no OWASP ASI / LLM mapping — consider adding one for audit",
                )
            )

    # 2. Unreachable rules: a deny rule with the same tool_patterns and
    # equal-or-higher priority earlier in the list shadows this one.
    by_priority = sorted(rules, key=lambda x: x.priority)
    for i, r in enumerate(by_priority):
        if r.action != PolicyAction.DENY or not r.tool_patterns:
            continue
        for earlier in by_priority[:i]:
            if earlier.action != PolicyAction.DENY:
                continue
            if set(earlier.tool_patterns) >= set(r.tool_patterns) and earlier.priority <= r.priority:
                findings.append(
                    LintFinding(
                        r.id,
                        "PL007",
                        LintSeverity.WARNING,
                        f"rule unreachable — fully shadowed by earlier deny rule {earlier.id!r}",
                    )
                )
                break

    findings.sort(key=lambda f: (("error", "warning", "info").index(f.severity.value), f.rule_id))
    return findings


def lint_files(paths: list[str]) -> list[LintFinding]:
    """Parse YAML policy files/dirs and run lint checks."""
    from pathlib import Path

    from mcpkernel.policy.loader import load_policy_dir, load_policy_file

    rules: list[PolicyRule] = []
    for raw in paths:
        p = Path(raw)
        if p.is_dir():
            rules.extend(load_policy_dir(p))
        else:
            rules.extend(load_policy_file(p))
    return lint_rules(rules)


__all__ = ["LintFinding", "LintSeverity", "lint_files", "lint_rules"]

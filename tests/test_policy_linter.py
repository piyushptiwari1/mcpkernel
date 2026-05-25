"""Tests for the policy linter (D.2)."""

from __future__ import annotations

import textwrap
from pathlib import Path  # noqa: TC003  # used at runtime for type hints below

import pytest
from typer.testing import CliRunner

from mcpkernel.cli import app
from mcpkernel.policy.engine import PolicyAction, PolicyRule
from mcpkernel.policy.linter import LintSeverity, lint_files, lint_rules


def _rule(rid: str, **kw) -> PolicyRule:
    defaults = dict(
        id=rid,
        name=rid,
        description="",
        action=PolicyAction.DENY,
        priority=100,
        tool_patterns=["foo_.*"],
        argument_patterns={},
        taint_labels=[],
        owasp_asi_id="ASI-01",
        owasp_llm_id="",
        conditions={},
        enabled=True,
    )
    defaults.update(kw)
    return PolicyRule(**defaults)


class TestLintRules:
    def test_clean_rules_yield_no_findings(self) -> None:
        assert lint_rules([_rule("r1"), _rule("r2", tool_patterns=["bar_.*"])]) == []

    def test_detects_duplicate_ids(self) -> None:
        findings = lint_rules([_rule("dup"), _rule("dup", tool_patterns=["other_.*"])])
        assert any(f.code == "PL001" for f in findings)
        assert any(f.severity == LintSeverity.ERROR for f in findings)

    def test_detects_empty_match_criteria(self) -> None:
        findings = lint_rules(
            [_rule("empty", tool_patterns=[], argument_patterns={}, taint_labels=[])]
        )
        assert any(f.code == "PL002" for f in findings)

    def test_detects_redos_pattern(self) -> None:
        findings = lint_rules([_rule("redos", tool_patterns=["(a+)+"])])
        assert any(f.code == "PL004" for f in findings)

    def test_detects_catch_all(self) -> None:
        findings = lint_rules([_rule("wild", tool_patterns=[".*"])])
        assert any(f.code == "PL005" for f in findings)

    def test_detects_missing_owasp_on_deny(self) -> None:
        findings = lint_rules([_rule("nomap", owasp_asi_id="", owasp_llm_id="")])
        assert any(f.code == "PL006" for f in findings)

    def test_detects_shadowed_rule(self) -> None:
        broad = _rule("broad", tool_patterns=["foo_.*", "bar_.*"], priority=10)
        narrow = _rule("narrow", tool_patterns=["foo_.*"], priority=20)
        findings = lint_rules([broad, narrow])
        assert any(f.code == "PL007" and f.rule_id == "narrow" for f in findings)


class TestLintFiles:
    def test_lint_files_loads_yaml(self, tmp_path: Path) -> None:
        f = tmp_path / "policy.yaml"
        f.write_text(
            textwrap.dedent(
                """
                rules:
                  - id: leak_block
                    name: Block leaks
                    action: deny
                    tool_patterns: ["(a+)+"]
                """
            ).strip()
        )
        findings = lint_files([str(f)])
        assert any(fnd.code == "PL004" for fnd in findings)


class TestCLI:
    def test_cli_clean_policy_exits_zero(self, tmp_path: Path) -> None:
        f = tmp_path / "p.yaml"
        f.write_text(
            textwrap.dedent(
                """
                rules:
                  - id: r1
                    name: Block shell
                    action: deny
                    tool_patterns: ["shell_exec"]
                    owasp_asi_id: "ASI-01"
                """
            ).strip()
        )
        runner = CliRunner()
        result = runner.invoke(app, ["policy-lint", str(f)])
        assert result.exit_code == 0
        assert "No lint findings" in result.stdout

    def test_cli_strict_fails_on_warning(self, tmp_path: Path) -> None:
        f = tmp_path / "p.yaml"
        f.write_text(
            textwrap.dedent(
                """
                rules:
                  - id: r1
                    name: Bad
                    action: deny
                    tool_patterns: [".*"]
                    owasp_asi_id: "ASI-01"
                """
            ).strip()
        )
        runner = CliRunner()
        result = runner.invoke(app, ["policy-lint", "--strict", str(f)])
        assert result.exit_code == 1
        assert "PL005" in result.stdout


@pytest.mark.parametrize(
    "pattern,expected_code",
    [
        ("(a+)+", "PL004"),
        ("(a|b)*", "PL004"),
        (".*", "PL005"),
    ],
)
def test_per_pattern_diagnostics(pattern: str, expected_code: str) -> None:
    findings = lint_rules([_rule("r", tool_patterns=[pattern])])
    assert any(f.code == expected_code for f in findings)

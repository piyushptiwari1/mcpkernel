"""Tests for mcpkernel.policy — engine, loader."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from mcpkernel.policy.engine import PolicyAction, PolicyEngine, PolicyRule
from mcpkernel.policy.loader import load_policy_dir, load_policy_file
from mcpkernel.utils import ConfigError

if TYPE_CHECKING:
    from pathlib import Path


class TestPolicyEngine:
    def test_default_allow(self):
        engine = PolicyEngine()
        decision = engine.evaluate("some_tool", {})
        assert decision.allowed
        assert decision.action == PolicyAction.ALLOW

    def test_deny_rule(self):
        engine = PolicyEngine()
        engine.add_rule(
            PolicyRule(
                id="TEST-001",
                name="Block shell",
                action=PolicyAction.DENY,
                tool_patterns=["shell_.*"],
            )
        )
        decision = engine.evaluate("shell_exec", {})
        assert not decision.allowed
        assert decision.action == PolicyAction.DENY

    def test_allow_unmatched_tool(self):
        engine = PolicyEngine()
        engine.add_rule(
            PolicyRule(
                id="TEST-001",
                name="Block shell",
                action=PolicyAction.DENY,
                tool_patterns=["shell_.*"],
            )
        )
        decision = engine.evaluate("file_read", {})
        assert decision.allowed

    def test_argument_pattern_match(self):
        engine = PolicyEngine()
        engine.add_rule(
            PolicyRule(
                id="TEST-002",
                name="Block path traversal",
                action=PolicyAction.DENY,
                tool_patterns=["file_read"],
                argument_patterns={"path": r"\.\."},
            )
        )
        decision = engine.evaluate("file_read", {"path": "../../etc/passwd"})
        assert not decision.allowed

    def test_taint_label_match(self):
        engine = PolicyEngine()
        engine.add_rule(
            PolicyRule(
                id="TEST-003",
                name="Block PII exfil",
                action=PolicyAction.DENY,
                tool_patterns=["http_post"],
                taint_labels=["pii"],
            )
        )
        decision = engine.evaluate("http_post", {}, taint_labels={"pii"})
        assert not decision.allowed

    def test_priority_ordering(self):
        engine = PolicyEngine()
        engine.add_rule(
            PolicyRule(
                id="LOW",
                name="Allow",
                action=PolicyAction.ALLOW,
                priority=100,
                tool_patterns=[".*"],
            )
        )
        engine.add_rule(
            PolicyRule(
                id="HIGH",
                name="Deny",
                action=PolicyAction.DENY,
                priority=10,
                tool_patterns=[".*"],
            )
        )
        decision = engine.evaluate("any_tool", {})
        assert decision.action == PolicyAction.DENY  # Most restrictive wins

    def test_disabled_rule_skipped(self):
        engine = PolicyEngine()
        engine.add_rule(
            PolicyRule(
                id="DISABLED",
                name="Disabled",
                action=PolicyAction.DENY,
                tool_patterns=[".*"],
                enabled=False,
            )
        )
        decision = engine.evaluate("any_tool", {})
        assert decision.allowed

    def test_owasp_asi_metadata(self):
        engine = PolicyEngine()
        engine.add_rule(
            PolicyRule(
                id="ASI-01",
                name="Prompt injection",
                action=PolicyAction.DENY,
                tool_patterns=[".*"],
                taint_labels=["user_input"],
                owasp_asi_id="ASI-01",
            )
        )
        decision = engine.evaluate("tool", {}, taint_labels={"user_input"})
        assert "ASI-01" in decision.metadata.get("owasp_asi_ids", [])

    def test_summary(self):
        engine = PolicyEngine()
        engine.add_rule(PolicyRule(id="R1", name="R1", action=PolicyAction.DENY))
        engine.add_rule(PolicyRule(id="R2", name="R2", action=PolicyAction.AUDIT))
        summary = engine.summary()
        assert summary["total_rules"] == 2


class TestPolicyLoader:
    def test_load_valid_file(self, sample_policy_yaml: Path):
        rules = load_policy_file(sample_policy_yaml)
        assert len(rules) == 2
        assert rules[0].id == "TEST-001"

    def test_load_missing_file(self):
        with pytest.raises(ConfigError):
            load_policy_file("/nonexistent/policy.yaml")

    def test_load_directory(self, tmp_path: Path):
        for i in range(3):
            (tmp_path / f"policy_{i}.yaml").write_text(
                f"rules:\n  - id: DIR-{i}\n    name: Rule {i}\n    action: audit\n"
            )
        rules = load_policy_dir(tmp_path)
        assert len(rules) == 3

    def test_load_empty_directory(self, tmp_path: Path):
        rules = load_policy_dir(tmp_path)
        assert len(rules) == 0

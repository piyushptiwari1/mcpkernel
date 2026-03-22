"""Tests for safe handling of malformed regex in policy rules."""

from __future__ import annotations

from mcpkernel.policy.engine import PolicyAction, PolicyEngine, PolicyRule


class TestPolicyRegexSafety:
    """Ensure invalid regex patterns in policy rules don't crash evaluation."""

    def test_invalid_tool_pattern_does_not_raise(self):
        """A malformed regex in tool_patterns must not propagate re.error."""
        engine = PolicyEngine()
        engine.add_rule(
            PolicyRule(
                id="BAD-REGEX-1",
                name="Bad tool pattern",
                action=PolicyAction.DENY,
                tool_patterns=["[unclosed"],
            )
        )
        decision = engine.evaluate("any_tool", {})
        # Bad pattern is skipped → no rule matches → default allow
        assert decision.allowed
        assert decision.action == PolicyAction.ALLOW

    def test_invalid_argument_pattern_does_not_raise(self):
        """A malformed regex in argument_patterns must not propagate re.error."""
        engine = PolicyEngine()
        engine.add_rule(
            PolicyRule(
                id="BAD-REGEX-2",
                name="Bad arg pattern",
                action=PolicyAction.DENY,
                tool_patterns=[".*"],
                argument_patterns={"path": "[unclosed"},
            )
        )
        decision = engine.evaluate("file_read", {"path": "/etc/passwd"})
        # Bad argument pattern is skipped → rule fails to match → default allow
        assert decision.allowed
        assert decision.action == PolicyAction.ALLOW

    def test_valid_rule_still_matches_after_bad_regex(self):
        """A valid fallback rule must still match even when a bad-regex rule is present."""
        engine = PolicyEngine()
        # Bad regex rule (higher priority)
        engine.add_rule(
            PolicyRule(
                id="BAD-REGEX-3",
                name="Bad pattern",
                action=PolicyAction.DENY,
                priority=10,
                tool_patterns=["[unclosed"],
            )
        )
        # Valid deny rule (lower priority)
        engine.add_rule(
            PolicyRule(
                id="VALID-DENY",
                name="Block shell",
                action=PolicyAction.DENY,
                priority=50,
                tool_patterns=["shell_.*"],
            )
        )
        decision = engine.evaluate("shell_exec", {})
        assert not decision.allowed
        assert decision.action == PolicyAction.DENY
        assert any(r.id == "VALID-DENY" for r in decision.matched_rules)

    def test_mixed_valid_and_invalid_tool_patterns(self):
        """A rule with one valid and one invalid tool pattern still matches on the valid one."""
        engine = PolicyEngine()
        engine.add_rule(
            PolicyRule(
                id="MIXED-1",
                name="Mixed patterns",
                action=PolicyAction.DENY,
                tool_patterns=["[bad", "shell_.*"],
            )
        )
        decision = engine.evaluate("shell_exec", {})
        assert not decision.allowed
        assert decision.action == PolicyAction.DENY

"""Tests for coverage gaps across policy, taint, audit, and proxy modules."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from mcpkernel.audit.exporter import AuditExportFormat, export_audit_logs
from mcpkernel.audit.logger import AuditEntry, AuditLogger
from mcpkernel.policy.engine import PolicyAction, PolicyEngine, PolicyRule
from mcpkernel.policy.loader import _parse_rule, load_policy_file
from mcpkernel.proxy.interceptor import InterceptorPipeline, PluginHook
from mcpkernel.proxy.rate_limit import InMemoryRateLimiter
from mcpkernel.taint.sinks import (
    SinkAction,
    SinkDefinition,
    check_sink_operation,
)
from mcpkernel.taint.sources import detect_tainted_sources
from mcpkernel.taint.tracker import TaintedValue, TaintLabel, TaintTracker
from mcpkernel.utils import ConfigError, TaintViolation

if TYPE_CHECKING:
    from pathlib import Path

# ── Policy: remove_rule ──────────────────────────────────────────────────


class TestPolicyEngineRemoveRule:
    """Tests for PolicyEngine.remove_rule()."""

    def test_remove_rule_by_id(self):
        """Test that remove_rule removes only the rule with the given id."""
        engine = PolicyEngine()
        engine.add_rule(PolicyRule(id="R1", name="Rule 1", action=PolicyAction.DENY))
        engine.add_rule(PolicyRule(id="R2", name="Rule 2", action=PolicyAction.ALLOW))
        assert len(engine.rules) == 2

        engine.remove_rule("R1")
        assert len(engine.rules) == 1
        assert engine.rules[0].id == "R2"

    def test_remove_rule_nonexistent_id(self):
        """Test that removing a non-existent id is a no-op."""
        engine = PolicyEngine()
        engine.add_rule(PolicyRule(id="R1", name="Rule 1"))
        engine.remove_rule("DOES_NOT_EXIST")
        assert len(engine.rules) == 1

    def test_remove_rule_leaves_others_sorted(self):
        """Test that priority ordering is preserved after removal."""
        engine = PolicyEngine()
        engine.add_rule(PolicyRule(id="LOW", name="Low", priority=200))
        engine.add_rule(PolicyRule(id="HIGH", name="High", priority=10))
        engine.add_rule(PolicyRule(id="MID", name="Mid", priority=100))
        engine.remove_rule("MID")
        ids = [r.id for r in engine.rules]
        assert ids == ["HIGH", "LOW"]


# ── Policy: add_rules (batch) ───────────────────────────────────────────


class TestPolicyEngineAddRules:
    """Tests for PolicyEngine.add_rules() batch insertion."""

    def test_add_rules_batch(self):
        """Test batch adding multiple rules at once."""
        engine = PolicyEngine()
        rules = [
            PolicyRule(id="B1", name="Batch 1", priority=50),
            PolicyRule(id="B2", name="Batch 2", priority=10),
            PolicyRule(id="B3", name="Batch 3", priority=100),
        ]
        engine.add_rules(rules)
        assert len(engine.rules) == 3
        # Should be sorted by priority ascending
        assert [r.id for r in engine.rules] == ["B2", "B1", "B3"]

    def test_add_rules_empty_list(self):
        """Test batch adding empty list is a no-op."""
        engine = PolicyEngine()
        engine.add_rules([])
        assert len(engine.rules) == 0


# ── Policy: _parse_rule edge cases ──────────────────────────────────────


class TestParseRule:
    """Tests for _parse_rule with edge-case inputs."""

    def test_missing_id_returns_none(self):
        """Test that a rule dict without 'id' returns None."""
        result = _parse_rule({"name": "No ID", "action": "deny"}, source="test")
        assert result is None

    def test_invalid_action_defaults_to_deny(self):
        """Test that an unknown action string defaults to DENY."""
        rule = _parse_rule(
            {"id": "X1", "name": "Bad action", "action": "explode"},
            source="test",
        )
        assert rule is not None
        assert rule.action == PolicyAction.DENY

    def test_valid_parse(self):
        """Test normal parsing returns a fully populated PolicyRule."""
        rule = _parse_rule(
            {
                "id": "P1",
                "name": "Allow read",
                "action": "allow",
                "priority": 50,
                "tool_patterns": ["file_read"],
                "owasp_asi_id": "ASI-01",
            },
            source="test",
        )
        assert rule is not None
        assert rule.id == "P1"
        assert rule.action == PolicyAction.ALLOW
        assert rule.priority == 50
        assert rule.owasp_asi_id == "ASI-01"


# ── Policy: load_policy_file missing rules key ──────────────────────────


class TestLoadPolicyFileMissingRules:
    """Tests for load_policy_file with invalid YAML."""

    def test_no_rules_key_raises(self, tmp_path: Path):
        """Test that a YAML file without the 'rules' key raises ConfigError."""
        bad_file = tmp_path / "bad.yaml"
        bad_file.write_text("version: 1\npolicies:\n  - name: foo\n")
        with pytest.raises(ConfigError, match="missing 'rules' key"):
            load_policy_file(bad_file)

    def test_file_not_found_raises(self):
        """Test that a non-existent file raises ConfigError."""
        with pytest.raises(ConfigError, match="not found"):
            load_policy_file("/does/not/exist.yaml")


# ── Taint: get_all_tainted ──────────────────────────────────────────────


class TestTaintTrackerGetAllTainted:
    """Tests for TaintTracker.get_all_tainted()."""

    def test_returns_all_tainted_values(self):
        """Test that get_all_tainted returns every currently tainted value."""
        tracker = TaintTracker()
        tracker.mark("a", TaintLabel.SECRET, source_id="s1")
        tracker.mark("b", TaintLabel.PII, source_id="s2")
        tracker.mark("c", TaintLabel.USER_INPUT, source_id="s3")
        assert len(tracker.get_all_tainted()) == 3

    def test_excludes_cleared_values(self):
        """Test that values with all labels cleared are excluded."""
        tracker = TaintTracker()
        tracker.mark("x", TaintLabel.PII, source_id="s1")
        tracker.mark("y", TaintLabel.SECRET, source_id="s2")
        tracker.clear("s1", TaintLabel.PII, sanitizer="test")
        tainted = tracker.get_all_tainted()
        assert len(tainted) == 1
        assert tainted[0].source_id == "s2"

    def test_empty_tracker(self):
        """Test that an empty tracker returns an empty list."""
        tracker = TaintTracker()
        assert tracker.get_all_tainted() == []


# ── Taint: TaintedValue.add_label ───────────────────────────────────────


class TestTaintedValueAddLabel:
    """Tests for TaintedValue.add_label()."""

    def test_add_label(self):
        """Test adding a new label to a tainted value."""
        tv = TaintedValue(
            value="data",
            labels={TaintLabel.SECRET},
            source_id="s1",
        )
        tv.add_label(TaintLabel.PII)
        assert TaintLabel.PII in tv.labels
        assert TaintLabel.SECRET in tv.labels

    def test_add_duplicate_label_is_idempotent(self):
        """Test that adding the same label twice doesn't duplicate."""
        tv = TaintedValue(
            value="data",
            labels={TaintLabel.SECRET},
            source_id="s1",
        )
        tv.add_label(TaintLabel.SECRET)
        assert len(tv.labels) == 1


# ── Taint: detect_tainted_sources — SSN, CC, phone ─────────────────────


class TestDetectTaintedSourcesPII:
    """Tests for SSN, credit card, and phone number detection."""

    def test_detect_ssn(self):
        """Test detection of US Social Security Numbers."""
        data = {"info": "SSN is 123-45-6789"}
        detections = detect_tainted_sources(data)
        assert any(d.pattern_name == "ssn" for d in detections)
        assert all(d.label == TaintLabel.PII for d in detections)

    def test_detect_credit_card_visa(self):
        """Test detection of Visa credit card numbers."""
        data = {"payment": "Card: 4111-1111-1111-1111"}
        detections = detect_tainted_sources(data)
        assert any(d.pattern_name == "credit_card" for d in detections)

    def test_detect_credit_card_mastercard(self):
        """Test detection of Mastercard numbers."""
        data = {"payment": "Card: 5500 0000 0000 0004"}
        detections = detect_tainted_sources(data)
        assert any(d.pattern_name == "credit_card" for d in detections)

    def test_detect_phone_us(self):
        """Test detection of US phone numbers."""
        data = {"contact": "Call me at (555) 123-4567"}
        detections = detect_tainted_sources(data)
        assert any(d.pattern_name == "phone_us" for d in detections)

    def test_detect_phone_with_country_code(self):
        """Test detection of US phone with +1 prefix."""
        data = {"contact": "Phone: +1-555-123-4567"}
        detections = detect_tainted_sources(data)
        assert any(d.pattern_name == "phone_us" for d in detections)


# ── Taint: check_sink_operation built-in sinks ─────────────────────────


class TestCheckSinkBuiltinSinks:
    """Tests for check_sink_operation with each built-in sink."""

    def test_file_write_blocks_secret(self):
        """Test that file_write blocks SECRET-tainted data."""
        tv = TaintedValue(value="key", labels={TaintLabel.SECRET}, source_id="s1")
        with pytest.raises(TaintViolation):
            check_sink_operation([tv], "file_write")

    def test_file_write_allows_pii(self):
        """Test that file_write allows PII (only SECRET is blocked)."""
        tv = TaintedValue(value="email", labels={TaintLabel.PII}, source_id="s1")
        result = check_sink_operation([tv], "file_write")
        assert result == SinkAction.ALLOW

    def test_db_query_blocks_user_input(self):
        """Test that db_query blocks USER_INPUT tainted data."""
        tv = TaintedValue(value="'; DROP TABLE --", labels={TaintLabel.USER_INPUT}, source_id="s1")
        with pytest.raises(TaintViolation):
            check_sink_operation([tv], "db_query")

    def test_shell_exec_blocks_untrusted_external(self):
        """Test that shell_exec blocks UNTRUSTED_EXTERNAL data."""
        tv = TaintedValue(
            value="rm -rf /",
            labels={TaintLabel.UNTRUSTED_EXTERNAL},
            source_id="s1",
        )
        with pytest.raises(TaintViolation):
            check_sink_operation([tv], "shell_exec")

    def test_eval_exec_blocks_llm_output(self):
        """Test that eval_exec blocks LLM_OUTPUT data."""
        tv = TaintedValue(
            value="__import__('os').system('id')",
            labels={TaintLabel.LLM_OUTPUT},
            source_id="s1",
        )
        with pytest.raises(TaintViolation):
            check_sink_operation([tv], "eval_exec")

    def test_unknown_sink_allows(self):
        """Test that an unknown sink type returns ALLOW."""
        tv = TaintedValue(value="x", labels={TaintLabel.SECRET}, source_id="s1")
        result = check_sink_operation([tv], "nonexistent_sink")
        assert result == SinkAction.ALLOW

    def test_empty_tainted_values_allows(self):
        """Test that empty tainted values list returns ALLOW."""
        result = check_sink_operation([], "shell_exec")
        assert result == SinkAction.ALLOW


# ── Taint: check_sink_operation custom_sinks ────────────────────────────


class TestCheckSinkCustomSinks:
    """Tests for check_sink_operation with custom_sinks parameter."""

    def test_custom_sink_blocks(self):
        """Test that a custom sink definition is enforced."""
        custom = {
            "my_sink": SinkDefinition(
                name="my_sink",
                description="Custom dangerous op",
                blocked_labels={TaintLabel.CUSTOM},
                action=SinkAction.BLOCK,
            ),
        }
        tv = TaintedValue(value="x", labels={TaintLabel.CUSTOM}, source_id="s1")
        with pytest.raises(TaintViolation):
            check_sink_operation([tv], "my_sink", custom_sinks=custom)

    def test_custom_sink_warn_action(self):
        """Test that a custom sink with WARN action returns WARN."""
        custom = {
            "warn_sink": SinkDefinition(
                name="warn_sink",
                description="Warn only",
                blocked_labels={TaintLabel.PII},
                action=SinkAction.WARN,
            ),
        }
        tv = TaintedValue(value="email", labels={TaintLabel.PII}, source_id="s1")
        result = check_sink_operation([tv], "warn_sink", custom_sinks=custom)
        assert result == SinkAction.WARN

    def test_custom_sink_overrides_builtin(self):
        """Test that custom_sinks can override a built-in sink definition."""
        custom = {
            "file_write": SinkDefinition(
                name="file_write",
                description="Custom file_write that blocks PII too",
                blocked_labels={TaintLabel.SECRET, TaintLabel.PII},
                action=SinkAction.BLOCK,
            ),
        }
        tv = TaintedValue(value="email", labels={TaintLabel.PII}, source_id="s1")
        with pytest.raises(TaintViolation):
            check_sink_operation([tv], "file_write", custom_sinks=custom)


# ── Audit: query with since parameter ───────────────────────────────────


class TestAuditLoggerQuerySince:
    """Tests for AuditLogger.query() with the since parameter."""

    @pytest.mark.asyncio
    async def test_query_since_filters_old_entries(self, audit_db: AuditLogger):
        """Test that since parameter filters out older entries."""
        old_entry = AuditEntry(event_type="old", tool_name="t1", timestamp=1000.0)
        new_entry = AuditEntry(event_type="new", tool_name="t2", timestamp=9999.0)
        await audit_db.log(old_entry)
        await audit_db.log(new_entry)

        results = await audit_db.query(since=5000.0)
        assert len(results) == 1
        assert results[0].event_type == "new"

    @pytest.mark.asyncio
    async def test_query_since_returns_all_when_zero(self, audit_db: AuditLogger):
        """Test that since=0 returns all entries."""
        await audit_db.log(AuditEntry(event_type="a", tool_name="t1", timestamp=100.0))
        await audit_db.log(AuditEntry(event_type="b", tool_name="t2", timestamp=200.0))
        results = await audit_db.query(since=0.0)
        assert len(results) == 2


# ── Audit: export_audit_logs with empty list ────────────────────────────


class TestExportAuditLogsEmpty:
    """Tests for export_audit_logs with empty entries."""

    def test_empty_jsonl(self):
        """Test JSONL export with no entries produces empty string."""
        output = export_audit_logs([], format=AuditExportFormat.JSON_LINES)
        assert output == ""

    def test_empty_csv(self):
        """Test CSV export with no entries produces only the header."""
        output = export_audit_logs([], format=AuditExportFormat.CSV)
        assert "entry_id" in output and "timestamp" in output
        # Only header line, no data rows
        assert len(output.strip().split("\n")) == 1

    def test_empty_cef(self):
        """Test CEF export with no entries produces empty string."""
        output = export_audit_logs([], format=AuditExportFormat.SIEM_CEF)
        assert output == ""


# ── Proxy: InterceptorPipeline.unregister ───────────────────────────────


class TestInterceptorPipelineUnregister:
    """Tests for InterceptorPipeline.unregister()."""

    def test_unregister_by_name(self):
        """Test that unregister removes hooks matching the given name."""

        class HookA(PluginHook):
            NAME = "hook_a"

        class HookB(PluginHook):
            NAME = "hook_b"

        pipeline = InterceptorPipeline()
        pipeline.register(HookA())
        pipeline.register(HookB())
        assert len(pipeline.hooks) == 2

        pipeline.unregister("hook_a")
        assert len(pipeline.hooks) == 1
        assert pipeline.hooks[0].NAME == "hook_b"

    def test_unregister_nonexistent_name(self):
        """Test that unregistering a non-existent name is a no-op."""

        class HookA(PluginHook):
            NAME = "hook_a"

        pipeline = InterceptorPipeline()
        pipeline.register(HookA())
        pipeline.unregister("nonexistent")
        assert len(pipeline.hooks) == 1

    def test_unregister_removes_all_with_same_name(self):
        """Test that multiple hooks with the same name are all removed."""

        class HookDup(PluginHook):
            NAME = "dup"

        pipeline = InterceptorPipeline()
        pipeline.register(HookDup())
        pipeline.register(HookDup())
        assert len(pipeline.hooks) == 2

        pipeline.unregister("dup")
        assert len(pipeline.hooks) == 0


# ── Proxy: InMemoryRateLimiter.reset ────────────────────────────────────


class TestInMemoryRateLimiterReset:
    """Tests for InMemoryRateLimiter.reset()."""

    def test_reset_restores_tokens(self):
        """Test that reset allows requests again after exhaustion."""
        limiter = InMemoryRateLimiter(requests_per_minute=60, burst_size=2)
        # Exhaust the bucket
        limiter.check("user1")
        limiter.check("user1")
        result = limiter.check("user1")
        assert not result.allowed

        # Reset and verify tokens restored
        limiter.reset("user1")
        result = limiter.check("user1")
        assert result.allowed

    def test_reset_nonexistent_key(self):
        """Test that resetting a non-existent key is a no-op."""
        limiter = InMemoryRateLimiter()
        limiter.reset("nonexistent")  # Should not raise

    def test_reset_does_not_affect_other_keys(self):
        """Test that resetting one key doesn't affect another."""
        limiter = InMemoryRateLimiter(requests_per_minute=60, burst_size=1)
        limiter.check("user1")
        limiter.check("user2")

        limiter.reset("user1")
        # user1 should be refreshed, user2 should still be rate-limited
        assert limiter.check("user1").allowed
        assert not limiter.check("user2").allowed

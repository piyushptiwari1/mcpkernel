"""Tests for Sprint 1 bug fixes: SPEC-002 through SPEC-005."""

from __future__ import annotations

import csv
import io
import time

import pytest

from mcpguard.audit.exporter import AuditExportFormat, export_audit_logs
from mcpguard.audit.logger import AuditEntry
from mcpguard.policy.engine import PolicyAction, PolicyEngine, PolicyRule
from mcpguard.proxy.rate_limit import InMemoryRateLimiter


# ---------------------------------------------------------------------------
# SPEC-002: PolicyEngine respects default_action
# ---------------------------------------------------------------------------
class TestPolicyDefaultAction:
    def test_default_allow_when_no_rules(self):
        """Default-constructed engine returns ALLOW when nothing matches."""
        engine = PolicyEngine()
        decision = engine.evaluate("any_tool", {})
        assert decision.action == PolicyAction.ALLOW

    def test_custom_default_deny(self):
        """Engine with default_action=DENY denies unmatched calls."""
        engine = PolicyEngine(default_action=PolicyAction.DENY)
        decision = engine.evaluate("unknown_tool", {"arg": "value"})
        assert decision.action == PolicyAction.DENY
        assert not decision.allowed
        assert "default deny" in decision.reasons[0].lower()

    def test_custom_default_audit(self):
        """Engine with default_action=AUDIT audits unmatched calls."""
        engine = PolicyEngine(default_action=PolicyAction.AUDIT)
        decision = engine.evaluate("unknown_tool", {})
        assert decision.action == PolicyAction.AUDIT
        assert decision.allowed  # AUDIT is considered allowed

    def test_matched_rule_overrides_default(self):
        """When a rule matches, the default_action is irrelevant."""
        engine = PolicyEngine(default_action=PolicyAction.ALLOW)
        engine.add_rule(PolicyRule(
            id="block-exec",
            name="Block exec",
            action=PolicyAction.DENY,
            tool_patterns=["exec_.*"],
        ))
        decision = engine.evaluate("exec_code", {})
        assert decision.action == PolicyAction.DENY


# ---------------------------------------------------------------------------
# SPEC-004: CSV export uses proper escaping
# ---------------------------------------------------------------------------
class TestCSVEscaping:
    def _make_entry(self, **overrides) -> AuditEntry:
        defaults = dict(
            entry_id="e1",
            timestamp=1000.0,
            event_type="tool_call",
            tool_name="test_tool",
            agent_id="agent1",
            action="allow",
            outcome="success",
            content_hash="abc123",
        )
        defaults.update(overrides)
        return AuditEntry(**defaults)

    def test_csv_header_present(self):
        output = export_audit_logs([self._make_entry()], format=AuditExportFormat.CSV)
        reader = csv.reader(io.StringIO(output))
        header = next(reader)
        assert "entry_id" in header
        assert "tool_name" in header

    def test_csv_values_with_commas(self):
        """Commas in values must be properly escaped."""
        entry = self._make_entry(tool_name="tool,with,commas")
        output = export_audit_logs([entry], format=AuditExportFormat.CSV)
        reader = csv.reader(io.StringIO(output))
        next(reader)  # skip header
        row = next(reader)
        assert "tool,with,commas" in row

    def test_csv_values_with_quotes(self):
        """Quotes in values must be properly escaped."""
        entry = self._make_entry(tool_name='tool"name')
        output = export_audit_logs([entry], format=AuditExportFormat.CSV)
        reader = csv.reader(io.StringIO(output))
        next(reader)
        row = next(reader)
        assert 'tool"name' in row

    def test_csv_values_with_newlines(self):
        """Newlines in values must be properly handled."""
        entry = self._make_entry(agent_id="agent\nline2")
        output = export_audit_logs([entry], format=AuditExportFormat.CSV)
        reader = csv.reader(io.StringIO(output))
        next(reader)
        row = next(reader)
        assert "agent\nline2" in row

    def test_csv_roundtrip(self):
        """CSV can be parsed back correctly."""
        entry = self._make_entry()
        output = export_audit_logs([entry], format=AuditExportFormat.CSV)
        reader = csv.DictReader(io.StringIO(output))
        rows = list(reader)
        assert len(rows) == 1
        assert rows[0]["entry_id"] == "e1"
        assert rows[0]["tool_name"] == "test_tool"


# ---------------------------------------------------------------------------
# SPEC-005: Rate limiter bucket eviction
# ---------------------------------------------------------------------------
class TestRateLimiterEviction:
    def test_max_buckets_attribute(self):
        """InMemoryRateLimiter has a MAX_BUCKETS class attribute."""
        assert hasattr(InMemoryRateLimiter, "MAX_BUCKETS")
        assert InMemoryRateLimiter.MAX_BUCKETS > 0

    def test_eviction_on_overflow(self):
        """When buckets exceed MAX_BUCKETS, oldest bucket is evicted."""
        limiter = InMemoryRateLimiter(requests_per_minute=60, burst_size=10)
        # Temporarily lower MAX_BUCKETS to make test feasible
        original_max = InMemoryRateLimiter.MAX_BUCKETS
        InMemoryRateLimiter.MAX_BUCKETS = 5
        try:
            for i in range(7):
                limiter.check(f"key-{i}")
            assert len(limiter._buckets) <= 6  # max 5 + 1 before evict triggers
        finally:
            InMemoryRateLimiter.MAX_BUCKETS = original_max

    def test_oldest_bucket_is_evicted(self):
        """The bucket with the oldest last_refill is removed."""
        limiter = InMemoryRateLimiter(requests_per_minute=60, burst_size=10)
        original_max = InMemoryRateLimiter.MAX_BUCKETS
        InMemoryRateLimiter.MAX_BUCKETS = 3
        try:
            limiter.check("oldest")
            # Manually backdate the oldest bucket
            limiter._buckets["oldest"].last_refill = time.monotonic() - 1000
            limiter.check("second")
            limiter.check("third")
            limiter.check("fourth")  # should evict "oldest"
            assert "oldest" not in limiter._buckets
        finally:
            InMemoryRateLimiter.MAX_BUCKETS = original_max

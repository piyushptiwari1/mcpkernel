"""Tests for mcpkernel.taint — tracker, sources, sinks, propagation, static analysis."""

from __future__ import annotations

import pytest

from mcpkernel.taint.propagation import TaintPropagator
from mcpkernel.taint.report import generate_taint_report
from mcpkernel.taint.sinks import SinkAction, check_sink_operation
from mcpkernel.taint.sources import detect_tainted_sources
from mcpkernel.taint.static_analysis import static_taint_analysis
from mcpkernel.taint.tracker import TaintLabel, TaintTracker
from mcpkernel.utils import TaintViolation


class TestTaintTracker:
    def test_mark_and_get(self):
        tracker = TaintTracker()
        tv = tracker.mark("secret-data", TaintLabel.SECRET)
        assert tv.is_tainted
        assert TaintLabel.SECRET in tv.labels
        retrieved = tracker.get(tv.source_id)
        assert retrieved is not None

    def test_clear_label(self):
        tracker = TaintTracker()
        tv = tracker.mark("data", TaintLabel.PII)
        tracker.clear(tv.source_id, TaintLabel.PII, sanitizer="test_sanitizer")
        assert TaintLabel.PII not in tv.labels
        assert tracker.is_known_sanitizer("test_sanitizer")

    def test_get_by_label(self):
        tracker = TaintTracker()
        tracker.mark("a", TaintLabel.SECRET)
        tracker.mark("b", TaintLabel.PII)
        tracker.mark("c", TaintLabel.SECRET)
        secrets = tracker.get_by_label(TaintLabel.SECRET)
        assert len(secrets) == 2

    def test_summary(self):
        tracker = TaintTracker()
        tracker.mark("x", TaintLabel.USER_INPUT)
        summary = tracker.summary()
        assert summary["active_tainted"] == 1
        assert summary["by_label"]["user_input"] == 1


class TestSourceDetection:
    def test_detect_email(self):
        data = {"message": "Contact us at user@example.com for help"}
        detections = detect_tainted_sources(data)
        assert len(detections) >= 1
        assert any(d.label == TaintLabel.PII for d in detections)

    def test_detect_aws_key(self):
        data = {"config": "aws_access_key_id = AKIAIOSFODNN7EXAMPLE"}
        detections = detect_tainted_sources(data)
        assert any(d.label == TaintLabel.SECRET for d in detections)

    def test_detect_jwt(self):
        data = {"token": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"}
        detections = detect_tainted_sources(data)
        assert any(d.label == TaintLabel.SECRET for d in detections)

    def test_nested_detection(self):
        data = {"user": {"profile": {"email": "test@example.com"}}}
        detections = detect_tainted_sources(data)
        assert len(detections) >= 1
        assert detections[0].field_path == "user.profile.email"

    def test_no_false_positives(self):
        data = {"message": "Hello, world!", "count": 42}
        detections = detect_tainted_sources(data)
        assert len(detections) == 0


class TestSinks:
    def test_block_secret_in_http(self):
        tracker = TaintTracker()
        tv = tracker.mark("api_key_123", TaintLabel.SECRET)
        with pytest.raises(TaintViolation):
            check_sink_operation([tv], "http_post")

    def test_allow_clean_data(self):
        action = check_sink_operation([], "http_post")
        assert action == SinkAction.ALLOW

    def test_warn_action(self):
        tracker = TaintTracker()
        tv = tracker.mark("data", TaintLabel.SECRET)
        action = check_sink_operation([tv], "http_post", override_action=SinkAction.WARN)
        assert action == SinkAction.WARN

    def test_unknown_sink_allows(self):
        tracker = TaintTracker()
        tv = tracker.mark("data", TaintLabel.SECRET)
        action = check_sink_operation([tv], "unknown_sink_type")
        assert action == SinkAction.ALLOW


class TestTaintPropagation:
    def test_propagation_through_call(self):
        tracker = TaintTracker()
        propagator = TaintPropagator(tracker)

        # First call with PII input
        labels = propagator.propagate_through_call(
            "search_users",
            {"query": "user@example.com"},
            [{"type": "text", "text": "Found user John"}],
        )
        assert TaintLabel.PII in labels

    def test_no_propagation_clean(self):
        tracker = TaintTracker()
        propagator = TaintPropagator(tracker)

        labels = propagator.propagate_through_call(
            "get_time",
            {"timezone": "UTC"},
            [{"type": "text", "text": "14:30"}],
        )
        assert len(labels) == 0

    def test_flow_graph(self):
        tracker = TaintTracker()
        propagator = TaintPropagator(tracker)
        propagator.propagate_through_call(
            "tool1",
            {"data": "user@test.com"},
            [{"type": "text", "text": "result"}],
        )
        graph = propagator.flow_graph
        assert "call_history" in graph
        assert "edges" in graph


class TestStaticAnalysis:
    def test_detect_eval(self):
        code = "result = eval(user_input)"
        report = static_taint_analysis(code)
        assert not report.is_clean
        assert report.has_critical
        assert any(f.rule_id == "STATIC-001" for f in report.findings)

    def test_detect_subprocess_import(self):
        code = "import subprocess\nsubprocess.run(['ls'])"
        report = static_taint_analysis(code)
        assert any(f.rule_id == "STATIC-010" for f in report.findings)

    def test_clean_code(self):
        code = "x = 1 + 2\nprint(x)"
        report = static_taint_analysis(code)
        assert report.is_clean

    def test_syntax_error(self):
        code = "def foo(\n"
        report = static_taint_analysis(code)
        assert not report.is_clean
        assert report.findings[0].rule_id == "STATIC-000"


class TestTaintReport:
    def test_report_structure(self):
        tracker = TaintTracker()
        propagator = TaintPropagator(tracker)
        propagator.propagate_through_call(
            "tool1",
            {"data": "user@test.com"},
            [{"type": "text", "text": "result"}],
        )
        report = generate_taint_report(propagator)
        assert "summary" in report
        assert "mermaid" in report
        assert "graph LR" in report["mermaid"]

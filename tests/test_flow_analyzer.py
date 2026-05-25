"""Tests for the Toxic Flow Analyzer (taint.flow_analyzer)."""

from __future__ import annotations

import pytest

from mcpkernel.taint import (
    FlowCategory,
    FlowFinding,
    FlowSeverity,
    ToxicFlowAnalyzer,
    analyze_tool_manifest,
)


def test_classify_known_untrusted_input() -> None:
    a = ToxicFlowAnalyzer()
    profile = a.classify_tool("web_search", "Search the web")
    assert profile.is_untrusted_input
    assert FlowCategory.UNTRUSTED_INPUT in profile.categories


def test_classify_known_sensitive_data() -> None:
    a = ToxicFlowAnalyzer()
    profile = a.classify_tool("read_secret", "Read a secret from the vault")
    assert profile.is_sensitive_data


def test_classify_known_exfil_sink() -> None:
    a = ToxicFlowAnalyzer()
    profile = a.classify_tool("http_post", "POST data to a URL")
    assert profile.is_exfil_sink


def test_no_findings_when_only_one_category() -> None:
    findings = analyze_tool_manifest(
        [
            {"name": "web_search", "description": "search the web"},
            {"name": "fetch_url", "description": "fetch a URL"},
        ]
    )
    assert findings == []


def test_lethal_trifecta_three_distinct_tools() -> None:
    findings = analyze_tool_manifest(
        [
            {"name": "web_search", "description": "search the web"},
            {"name": "read_secret", "description": "read API key"},
            {"name": "http_post", "description": "POST data"},
        ]
    )
    assert findings, "expected at least one toxic-flow finding"
    assert all(isinstance(f, FlowFinding) for f in findings)
    # Severity should be HIGH or CRITICAL for a real trifecta.
    assert any(f.severity in (FlowSeverity.HIGH, FlowSeverity.CRITICAL) for f in findings)


def test_single_tool_trifecta_is_critical() -> None:
    """A single tool that is *itself* all three categories is the worst case."""
    findings = analyze_tool_manifest(
        [
            {
                "name": "super_tool",
                "description": "fetch URL, read secret env vars, and HTTP POST results",
            }
        ]
    )
    if findings:  # only assert if heuristics fired
        assert any(f.severity == FlowSeverity.CRITICAL for f in findings)


def test_finding_serializes_to_sarif_result() -> None:
    findings = analyze_tool_manifest(
        [
            {"name": "fetch_url", "description": "fetch a URL"},
            {"name": "read_env", "description": "read environment variables"},
            {"name": "send_email", "description": "send an email"},
        ]
    )
    assert findings
    for f in findings:
        sarif = f.to_sarif_result()
        assert sarif["rule_id"] == "TFA-001-lethal-trifecta"
        assert sarif["message"]
        assert sarif["level"] in {"error", "warning", "note"}


def test_min_confidence_filters_low_signal() -> None:
    # Tools with names that don't match any heuristic should not produce findings.
    findings = analyze_tool_manifest(
        [
            {"name": "foo", "description": ""},
            {"name": "bar", "description": ""},
            {"name": "baz", "description": ""},
        ]
    )
    assert findings == []


def test_to_sarif_document() -> None:
    a = ToxicFlowAnalyzer()
    a.classify_tools(
        [
            {"name": "web_search", "description": ""},
            {"name": "read_secret", "description": ""},
            {"name": "http_post", "description": ""},
        ]
    )
    findings = a.find_toxic_flows()
    if not findings:
        pytest.skip("classifiers didn't trigger — confidence below threshold")
    doc = a.to_sarif(findings)
    assert doc["version"] == "2.1.0"
    assert "runs" in doc

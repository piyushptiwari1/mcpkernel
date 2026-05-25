"""Tests for v0.2.0 advances: ephemeral SessionGuard secret, metadata version,
SARIF audit export, and OAuth2 RFC 8707 resource indicator enforcement."""

# ruff: noqa: S106
from __future__ import annotations

import json

import mcpkernel


# --------------------------------------------------------------------- #
# SPEC 1: SessionGuard fail-closed default
# --------------------------------------------------------------------- #
def test_session_guard_generates_ephemeral_secret_when_unset(caplog) -> None:
    from mcpkernel.security import SessionGuard

    g1 = SessionGuard()
    g2 = SessionGuard()
    # Each instance must have its own randomly generated secret — no shared
    # constant baked into the binary.
    assert g1._secret != g2._secret  # type: ignore[attr-defined]
    assert getattr(g1, "_ephemeral_secret", False) is True
    # Belt-and-braces: the old hard-coded constant must NOT appear.
    assert b"mcpkernel-default-session-key" not in g1._secret  # type: ignore[attr-defined]


def test_session_guard_uses_explicit_secret_when_provided() -> None:
    from mcpkernel.security import SessionGuard

    g = SessionGuard(secret="user-provided-secret")
    assert getattr(g, "_ephemeral_secret", True) is False


# --------------------------------------------------------------------- #
# SPEC 2: __version__ resolves from installed package metadata
# --------------------------------------------------------------------- #
def test_version_is_not_hardcoded_placeholder() -> None:
    v = mcpkernel.__version__
    # Either a real PEP 440 version or the explicit local-dev fallback.
    assert v
    assert v != "0.1.3", "version must not be the old hard-coded value"


# --------------------------------------------------------------------- #
# SPEC 5: SARIF audit export format
# --------------------------------------------------------------------- #
def test_audit_exporter_sarif_format() -> None:
    from mcpkernel.audit.exporter import AuditExportFormat, export_audit_logs
    from mcpkernel.audit.logger import AuditEntry

    entries = [
        AuditEntry(
            event_type="policy_decision",
            tool_name="http_post",
            outcome="blocked",
            details={"reason": "lethal trifecta"},
        ),
        AuditEntry(
            event_type="policy_decision",
            tool_name="echo",
            outcome="allowed",
        ),
    ]
    rendered = export_audit_logs(entries, format=AuditExportFormat.SARIF)
    doc = json.loads(rendered)
    assert doc["version"] == "2.1.0"
    assert doc["runs"]
    results = doc["runs"][0]["results"]
    assert results, "expected at least one SARIF result"
    levels = {r["level"] for r in results}
    assert "error" in levels  # blocked → error


# --------------------------------------------------------------------- #
# SPEC 3: OAuth2 RFC 8707 resource indicator
# --------------------------------------------------------------------- #
def test_oauth2_auth_accepts_resource_kwarg() -> None:
    from mcpkernel.proxy.auth import OAuth2Auth

    a = OAuth2Auth(
        jwks_url="https://example.com/.well-known/jwks.json",
        issuer="https://issuer.example.com/",
        resource="https://mcp.example.com/",
        require_resource=True,
    )
    # Resource doubles as audience when no explicit audience was supplied.
    assert a._audience == "https://mcp.example.com/"  # type: ignore[attr-defined]
    assert a._resource == "https://mcp.example.com/"  # type: ignore[attr-defined]
    assert a._require_resource is True  # type: ignore[attr-defined]


# --------------------------------------------------------------------- #
# SPEC 6: OTel GenAI semconv constants
# --------------------------------------------------------------------- #
def test_semconv_constants_exposed() -> None:
    from mcpkernel.observability import gen_ai_tool_attributes, mcp_request_attributes

    attrs = gen_ai_tool_attributes(
        tool_name="web_search",
        tool_call_id="call-1",
        tool_type="function",
    )
    assert attrs["gen_ai.tool.name"] == "web_search"
    assert attrs["gen_ai.tool.call.id"] == "call-1"

    req = mcp_request_attributes(
        method="tools/call",
        request_id="r-1",
        session_id="s-1",
        transport="streamable_http",
        protocol_version="2025-11-25",
        server_name="example",
    )
    assert req["mcp.method.name"] == "tools/call"
    assert req["mcp.protocol.version"] == "2025-11-25"


# --------------------------------------------------------------------- #
# SPEC 7: OWASP LLM Top 10 mapping on PolicyRule
# --------------------------------------------------------------------- #
def test_policy_rule_owasp_llm_id_round_trip(tmp_path) -> None:
    from mcpkernel.policy.loader import load_policy_file

    policy_file = tmp_path / "p.yaml"
    policy_file.write_text(
        """
rules:
  - id: TEST-001
    name: test
    action: deny
    tool_patterns: ['evil_.*']
    owasp_asi_id: ASI-01
    owasp_llm_id: LLM01
"""
    )
    rules = load_policy_file(str(policy_file))
    assert rules
    assert rules[0].owasp_llm_id == "LLM01"
    assert rules[0].owasp_asi_id == "ASI-01"

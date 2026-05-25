"""Tests for DSSE / in-toto v1 audit-batch attestation (Section C.5)."""

from __future__ import annotations

import base64
import json

from mcpkernel.audit import attest_audit_batch, build_statement
from mcpkernel.audit.attestation import (
    DSSE_PAYLOAD_TYPE,
    PREDICATE_TYPE,
    STATEMENT_TYPE,
    _pae,
)
from mcpkernel.audit.logger import AuditEntry


def _mk(entry_id: str, outcome: str = "allow", labels: list[str] | None = None) -> AuditEntry:
    return AuditEntry(
        entry_id=entry_id,
        event_type="tool_call",
        tool_name="t",
        outcome=outcome,
        details={"taint_labels": labels or []},
    )


class TestStatement:
    def test_in_toto_v1_envelope(self) -> None:
        stmt = build_statement([_mk("a"), _mk("b")], batch_name="batch-1")
        assert stmt["_type"] == STATEMENT_TYPE
        assert stmt["predicateType"] == PREDICATE_TYPE
        assert len(stmt["subject"]) == 2
        for subj in stmt["subject"]:
            assert "sha256" in subj["digest"]
            assert len(subj["digest"]["sha256"]) == 64

    def test_predicate_aggregates(self) -> None:
        entries = [
            _mk("a", outcome="allow", labels=["pii", "secret"]),
            _mk("b", outcome="deny", labels=["pii"]),
            _mk("c", outcome="allow"),
        ]
        stmt = build_statement(entries, batch_name="x")
        pred = stmt["predicate"]
        assert pred["entryCount"] == 3
        assert pred["outcomeCounts"] == {"allow": 2, "deny": 1}
        assert pred["taintLabelCounts"] == {"pii": 2, "secret": 1}
        assert pred["timeRange"]["start"] <= pred["timeRange"]["end"]


class TestPAE:
    def test_dsse_pae_format(self) -> None:
        out = _pae("application/foo", b"hello")
        assert out == b"DSSEv1 15 application/foo 5 hello"


class TestAttest:
    def test_attestation_envelope_unsigned(self) -> None:
        """Without sigstore identity available, returns unsigned envelope (not raising)."""
        env = attest_audit_batch([_mk("a")], batch_name="b1")
        assert env["payloadType"] == DSSE_PAYLOAD_TYPE
        decoded = json.loads(base64.b64decode(env["payload"]))
        assert decoded["predicateType"] == PREDICATE_TYPE
        assert "statement" in env
        assert env["statement"]["predicate"]["batchName"] == "b1"
        # signatures may be empty when no Sigstore identity is available
        assert isinstance(env["signatures"], list)

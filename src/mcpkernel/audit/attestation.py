"""DSSE / in-toto v1 attestation for audit log batches (C.5).

Each batch of `AuditEntry` records is rolled up into a SHA-256 digest and
wrapped in an [in-toto Statement] (predicate type
``https://mcpkernel.dev/attestations/audit-batch/v1``), then encoded as a
[DSSE envelope] (``application/vnd.in-toto+json``) and signed by Sigstore.

The output is a self-contained, externally verifiable attestation that can
be archived alongside the log, replayed, or fed into SLSA / Rekor.

[in-toto Statement]: https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md
[DSSE envelope]: https://github.com/secure-systems-lab/dsse
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
from typing import TYPE_CHECKING, Any

import structlog

if TYPE_CHECKING:
    from collections.abc import Iterable

    from mcpkernel.audit.logger import AuditEntry

logger = structlog.get_logger(__name__)

PREDICATE_TYPE = "https://mcpkernel.dev/attestations/audit-batch/v1"
STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
DSSE_PAYLOAD_TYPE = "application/vnd.in-toto+json"


def _entry_digest(entry: AuditEntry) -> str:
    """SHA-256 of a single audit entry's stable serialization."""
    from dataclasses import asdict

    payload = json.dumps(asdict(entry), sort_keys=True, default=str)
    return hashlib.sha256(payload.encode()).hexdigest()


def build_statement(entries: Iterable[AuditEntry], *, batch_name: str) -> dict[str, Any]:
    """Build an in-toto v1 Statement over an audit batch.

    Each entry contributes a subject of the form
    ``audit-entry/<entry_id>`` with its SHA-256 digest. The predicate
    summarizes the batch: count, outcome histogram, taint-label histogram,
    time bounds.
    """
    entries_list = list(entries)
    subjects: list[dict[str, Any]] = []
    outcome_counts: dict[str, int] = {}
    label_counts: dict[str, int] = {}
    timestamps: list[float] = []

    for e in entries_list:
        subjects.append(
            {
                "name": f"audit-entry/{e.entry_id}",
                "digest": {"sha256": _entry_digest(e)},
            }
        )
        if e.outcome:
            outcome_counts[e.outcome] = outcome_counts.get(e.outcome, 0) + 1
        for label in e.details.get("taint_labels", []) or []:
            label_counts[label] = label_counts.get(label, 0) + 1
        timestamps.append(e.timestamp)

    predicate = {
        "batchName": batch_name,
        "entryCount": len(entries_list),
        "outcomeCounts": outcome_counts,
        "taintLabelCounts": label_counts,
        "timeRange": {
            "start": min(timestamps) if timestamps else None,
            "end": max(timestamps) if timestamps else None,
        },
    }
    return {
        "_type": STATEMENT_TYPE,
        "predicateType": PREDICATE_TYPE,
        "subject": subjects,
        "predicate": predicate,
    }


def _pae(payload_type: str, payload: bytes) -> bytes:
    """DSSE Pre-Authentication Encoding (PAE) per the spec."""
    return (
        b"DSSEv1 "
        + str(len(payload_type)).encode()
        + b" "
        + payload_type.encode()
        + b" "
        + str(len(payload)).encode()
        + b" "
        + payload
    )


def attest_audit_batch(
    entries: Iterable[AuditEntry],
    *,
    batch_name: str = "audit-batch",
) -> dict[str, Any]:
    """Build + Sigstore-sign a DSSE envelope over an audit batch.

    Returns a dict with keys::

        {
          "payloadType": "application/vnd.in-toto+json",
          "payload": "<base64(statement)>",
          "signatures": [{"sig": "<base64>", "keyid": "..."}],
          "sigstoreBundle": "<bundle JSON or None>",
          "statement": {...},   # unencoded statement for convenience
        }

    When ``MCPKERNEL_DEE__REQUIRE_SIGN`` is set and Sigstore signing fails,
    raises ``RuntimeError``. Otherwise returns the envelope with
    ``signatures: []`` and ``sigstoreBundle: None`` so callers can still
    archive the unsigned statement.
    """
    statement = build_statement(entries, batch_name=batch_name)
    payload_bytes = json.dumps(statement, sort_keys=True, separators=(",", ":")).encode()
    payload_b64 = base64.b64encode(payload_bytes).decode()
    pae = _pae(DSSE_PAYLOAD_TYPE, payload_bytes)

    require_sign = os.environ.get("MCPKERNEL_DEE__REQUIRE_SIGN", "").lower() in (
        "1",
        "true",
        "yes",
    )

    signatures: list[dict[str, str]] = []
    bundle_json: str | None = None

    try:
        from sigstore.sign import SigningContext

        ctx = SigningContext.production()
        identity: object | None = None
        id_token_str = os.environ.get("SIGSTORE_ID_TOKEN")
        if id_token_str:
            try:
                from sigstore.oidc import IdentityToken

                identity = IdentityToken(id_token_str)
            except Exception:  # pragma: no cover
                logger.warning("failed to parse SIGSTORE_ID_TOKEN for DSSE attest")
                identity = None

        with ctx.signer(identity_token=identity) if identity else ctx.signer() as signer:
            result = signer.sign_artifact(pae)
            bundle_json = result.bundle.to_json()
            # Extract raw signature from the bundle's messageSignature for
            # the DSSE envelope. Bundle v0.3 stores it under
            # messageSignature.signature (base64).
            try:
                bundle_obj = json.loads(bundle_json)
                raw_sig = (
                    bundle_obj.get("messageSignature", {}).get("signature")
                    or bundle_obj.get("dsseEnvelope", {})
                    .get("signatures", [{}])[0]
                    .get("sig")
                    or ""
                )
                signatures.append({"sig": raw_sig, "keyid": "sigstore"})
            except Exception:  # pragma: no cover
                logger.debug("failed to extract raw signature from bundle", exc_info=True)
    except ImportError as exc:
        if require_sign:
            msg = "MCPKERNEL_DEE__REQUIRE_SIGN=true but 'sigstore' is not installed"
            raise RuntimeError(msg) from exc
        logger.debug("sigstore not installed — DSSE attestation unsigned")
    except Exception:
        if require_sign:
            logger.error("DSSE attestation signing failed under REQUIRE_SIGN", exc_info=True)
            raise
        logger.warning("DSSE attestation signing failed", exc_info=True)

    return {
        "payloadType": DSSE_PAYLOAD_TYPE,
        "payload": payload_b64,
        "signatures": signatures,
        "sigstoreBundle": bundle_json,
        "statement": statement,
    }


__all__ = [
    "DSSE_PAYLOAD_TYPE",
    "PREDICATE_TYPE",
    "STATEMENT_TYPE",
    "attest_audit_batch",
    "build_statement",
]

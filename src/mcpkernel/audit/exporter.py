"""Audit log exporters — SIEM-compatible formats."""

from __future__ import annotations

import csv
import io
import json
from enum import StrEnum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from mcpkernel.audit.logger import AuditEntry

__all__ = ["AuditExportFormat", "export_audit_logs"]


class AuditExportFormat(StrEnum):
    JSON_LINES = "jsonl"
    CSV = "csv"
    SIEM_CEF = "cef"  # Common Event Format
    SARIF = "sarif"  # SARIF 2.1.0 — GitHub code-scanning / Defender / Snyk ingestion


def export_audit_logs(
    entries: list[AuditEntry],
    format: AuditExportFormat = AuditExportFormat.JSON_LINES,
) -> str:
    """Export audit entries in the specified format."""
    match format:
        case AuditExportFormat.JSON_LINES:
            return _export_jsonl(entries)
        case AuditExportFormat.CSV:
            return _export_csv(entries)
        case AuditExportFormat.SIEM_CEF:
            return _export_cef(entries)
        case AuditExportFormat.SARIF:
            return _export_sarif(entries)


def _export_jsonl(entries: list[AuditEntry]) -> str:
    lines = []
    for e in entries:
        lines.append(
            json.dumps(
                {
                    "entry_id": e.entry_id,
                    "timestamp": e.timestamp,
                    "event_type": e.event_type,
                    "tool_name": e.tool_name,
                    "agent_id": e.agent_id,
                    "request_id": e.request_id,
                    "trace_id": e.trace_id,
                    "action": e.action,
                    "outcome": e.outcome,
                    "details": e.details,
                    "content_hash": e.content_hash,
                },
                default=str,
            )
        )
    return "\n".join(lines)


def _export_csv(entries: list[AuditEntry]) -> str:
    output = io.StringIO()
    fieldnames = [
        "entry_id",
        "timestamp",
        "event_type",
        "tool_name",
        "agent_id",
        "action",
        "outcome",
        "content_hash",
    ]
    writer = csv.DictWriter(output, fieldnames=fieldnames, quoting=csv.QUOTE_ALL)
    writer.writeheader()
    for e in entries:
        writer.writerow(
            {
                "entry_id": e.entry_id,
                "timestamp": e.timestamp,
                "event_type": e.event_type,
                "tool_name": e.tool_name,
                "agent_id": e.agent_id,
                "action": e.action,
                "outcome": e.outcome,
                "content_hash": e.content_hash,
            }
        )
    return output.getvalue().rstrip("\r\n")


def _export_cef(entries: list[AuditEntry]) -> str:
    """Export in Common Event Format for SIEM ingestion."""
    lines = []
    for e in entries:
        severity = "5" if e.outcome == "blocked" else "3"
        cef = (
            f"CEF:0|MCPKernel|MCPKernel|0.1.0|{e.event_type}|{e.tool_name}|{severity}|"
            f"rt={int(e.timestamp * 1000)} "
            f"src={e.agent_id} "
            f"act={e.action} "
            f"outcome={e.outcome} "
            f"cs1={e.trace_id} cs1Label=TraceID "
            f"cs2={e.content_hash} cs2Label=ContentHash"
        )
        lines.append(cef)
    return "\n".join(lines)


def _export_sarif(entries: list[AuditEntry]) -> str:
    """Export audit entries as a SARIF 2.1.0 JSON document.

    SARIF (Static Analysis Results Interchange Format) is the OASIS standard
    consumed by GitHub Code Scanning, Microsoft Defender for Cloud, Snyk,
    Azure DevOps, and VS Code SARIF Viewer. Mapping rules:

    * ``policy_violation`` / ``taint_violation`` -> SARIF result (level=error)
    * ``allowed`` / ``audit`` events with no violation -> SARIF result (level=note)
    * ``blocked`` outcome -> level=error
    * ``warned`` outcome -> level=warning
    """
    from mcpkernel.audit.sarif import SARIFResult, generate_sarif

    level_for = {
        "blocked": "error",
        "denied": "error",
        "warned": "warning",
        "allowed": "note",
        "audited": "note",
    }

    results: list[SARIFResult] = []
    for e in entries:
        level = level_for.get(e.outcome.lower() if e.outcome else "", "note")
        msg = f"{e.event_type}: {e.action} on tool '{e.tool_name}' -> {e.outcome}"
        if isinstance(e.details, dict) and e.details:
            reason = e.details.get("reason") or e.details.get("rule_id") or ""
            if reason:
                msg = f"{msg} ({reason})"
        results.append(
            SARIFResult(
                rule_id=str(e.event_type) or "mcpkernel.audit",
                level=level,
                message=msg,
                file_path=e.tool_name or "",
                help_text=f"agent={e.agent_id} trace={e.trace_id}",
                help_uri="https://github.com/piyushptiwari1/mcpkernel/blob/main/docs/core/audit.md",
            )
        )

    return json.dumps(generate_sarif(results), indent=2, ensure_ascii=False)

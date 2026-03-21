"""Audit log exporters — SIEM-compatible formats."""

from __future__ import annotations

import csv
import io
import json
from enum import Enum
from typing import Any

from mcpguard.audit.logger import AuditEntry

__all__ = ["AuditExportFormat", "export_audit_logs"]


class AuditExportFormat(str, Enum):
    JSON_LINES = "jsonl"
    CSV = "csv"
    SIEM_CEF = "cef"  # Common Event Format


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


def _export_jsonl(entries: list[AuditEntry]) -> str:
    lines = []
    for e in entries:
        lines.append(json.dumps({
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
        }, default=str))
    return "\n".join(lines)


def _export_csv(entries: list[AuditEntry]) -> str:
    output = io.StringIO()
    fieldnames = [
        "entry_id", "timestamp", "event_type", "tool_name",
        "agent_id", "action", "outcome", "content_hash",
    ]
    writer = csv.DictWriter(output, fieldnames=fieldnames, quoting=csv.QUOTE_ALL)
    writer.writeheader()
    for e in entries:
        writer.writerow({
            "entry_id": e.entry_id,
            "timestamp": e.timestamp,
            "event_type": e.event_type,
            "tool_name": e.tool_name,
            "agent_id": e.agent_id,
            "action": e.action,
            "outcome": e.outcome,
            "content_hash": e.content_hash,
        })
    return output.getvalue().rstrip("\r\n")


def _export_cef(entries: list[AuditEntry]) -> str:
    """Export in Common Event Format for SIEM ingestion."""
    lines = []
    for e in entries:
        severity = "5" if e.outcome == "blocked" else "3"
        cef = (
            f"CEF:0|MCPGuard|MCPGuard|0.1.0|{e.event_type}|{e.tool_name}|{severity}|"
            f"rt={int(e.timestamp * 1000)} "
            f"src={e.agent_id} "
            f"act={e.action} "
            f"outcome={e.outcome} "
            f"cs1={e.trace_id} cs1Label=TraceID "
            f"cs2={e.content_hash} cs2Label=ContentHash"
        )
        lines.append(cef)
    return "\n".join(lines)

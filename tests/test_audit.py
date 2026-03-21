"""Tests for mcpguard.audit — logger, exporter."""

from __future__ import annotations

import pytest

from mcpguard.audit.logger import AuditEntry, AuditLogger
from mcpguard.audit.exporter import AuditExportFormat, export_audit_logs


class TestAuditEntry:
    def test_compute_hash(self):
        entry = AuditEntry(event_type="tool_call", tool_name="test_tool")
        h1 = entry.compute_hash()
        h2 = entry.compute_hash()
        assert h1 == h2
        assert len(h1) == 64

    def test_hash_changes_with_content(self):
        e1 = AuditEntry(event_type="tool_call", tool_name="tool_a")
        e2 = AuditEntry(event_type="tool_call", tool_name="tool_b")
        e1.compute_hash()
        e2.compute_hash()
        assert e1.content_hash != e2.content_hash


class TestAuditLogger:
    @pytest.mark.asyncio
    async def test_log_and_query(self, audit_db: AuditLogger):
        entry = AuditEntry(event_type="tool_call", tool_name="test_tool")
        entry_id = await audit_db.log(entry)
        assert entry_id == entry.entry_id

        entries = await audit_db.query(tool_name="test_tool")
        assert len(entries) >= 1

    @pytest.mark.asyncio
    async def test_query_by_event_type(self, audit_db: AuditLogger):
        await audit_db.log(AuditEntry(event_type="policy_violation", tool_name="t1"))
        await audit_db.log(AuditEntry(event_type="tool_call", tool_name="t2"))

        violations = await audit_db.query(event_type="policy_violation")
        assert all(e.event_type == "policy_violation" for e in violations)

    @pytest.mark.asyncio
    async def test_verify_integrity(self, audit_db: AuditLogger):
        await audit_db.log(AuditEntry(event_type="test", tool_name="t"))
        result = await audit_db.verify_integrity()
        assert result["integrity_valid"]

    @pytest.mark.asyncio
    async def test_query_limit(self, audit_db: AuditLogger):
        for i in range(10):
            await audit_db.log(AuditEntry(event_type="test", tool_name=f"t{i}"))
        entries = await audit_db.query(limit=5)
        assert len(entries) == 5


class TestAuditExporter:
    def test_export_jsonl(self):
        entries = [
            AuditEntry(event_type="tool_call", tool_name="test"),
            AuditEntry(event_type="policy_violation", tool_name="blocked"),
        ]
        for e in entries:
            e.compute_hash()
        output = export_audit_logs(entries, format=AuditExportFormat.JSON_LINES)
        lines = output.strip().split("\n")
        assert len(lines) == 2

    def test_export_csv(self):
        entries = [AuditEntry(event_type="test", tool_name="t")]
        entries[0].compute_hash()
        output = export_audit_logs(entries, format=AuditExportFormat.CSV)
        lines = output.strip().split("\n")
        assert len(lines) == 2  # Header + 1 row

    def test_export_cef(self):
        entries = [AuditEntry(event_type="test", tool_name="t")]
        entries[0].compute_hash()
        output = export_audit_logs(entries, format=AuditExportFormat.SIEM_CEF)
        assert output.startswith("CEF:0|MCPGuard")

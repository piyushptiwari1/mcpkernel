"""Tests for mcpguard.dee — envelope, trace store, replay, drift."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from mcpguard.dee.drift import DriftCategory, DriftReport
from mcpguard.dee.envelope import ExecutionTrace
from mcpguard.dee.snapshot import take_environment_snapshot
from mcpguard.proxy.interceptor import ExecutionResult

if TYPE_CHECKING:
    from mcpguard.dee.trace_store import TraceStore


class TestExecutionTrace:
    def test_trace_fields(self):
        result = ExecutionResult(content=[], is_error=False)
        trace = ExecutionTrace(
            trace_id="test-trace-1",
            tool_name="execute_code",
            agent_id="agent-1",
            input_hash="abc123",
            output_hash="def456",
            env_snapshot_hash="ghi789",
            timestamp=0.0,
            duration_seconds=0.0,
            result=result,
        )
        assert trace.trace_id == "test-trace-1"
        assert trace.tool_name == "execute_code"
        assert trace.duration_seconds == 0.0


class TestSnapshot:
    def test_take_snapshot(self, tmp_dir):
        # Create some files
        (tmp_dir / "test.py").write_text("print('hello')")
        snapshot = take_environment_snapshot(workspace_path=tmp_dir)
        assert isinstance(snapshot, str)
        assert len(snapshot) == 64  # SHA-256 hex

    def test_snapshot_deterministic(self, tmp_dir):
        (tmp_dir / "test.py").write_text("print('hello')")
        s1 = take_environment_snapshot(workspace_path=tmp_dir)
        s2 = take_environment_snapshot(workspace_path=tmp_dir)
        assert s1 == s2


class TestTraceStore:
    @pytest.mark.asyncio
    async def test_store_and_retrieve(self, trace_db: TraceStore):
        result = ExecutionResult(content=[], is_error=False)
        trace = ExecutionTrace(
            trace_id="store-test-1",
            tool_name="test_tool",
            agent_id="agent-1",
            input_hash="aaa",
            output_hash="bbb",
            env_snapshot_hash="ccc",
            timestamp=0.0,
            duration_seconds=0.0,
            result=result,
        )
        await trace_db.store(trace)
        retrieved = await trace_db.get("store-test-1")
        assert retrieved is not None
        assert retrieved["tool_name"] == "test_tool"

    @pytest.mark.asyncio
    async def test_list_traces(self, trace_db: TraceStore):
        result = ExecutionResult(content=[], is_error=False)
        for i in range(5):
            await trace_db.store(
                ExecutionTrace(
                    trace_id=f"list-{i}",
                    tool_name="tool",
                    agent_id="agent",
                    input_hash=f"in-{i}",
                    output_hash=f"out-{i}",
                    env_snapshot_hash="env",
                    timestamp=float(i),
                    duration_seconds=0.0,
                    result=result,
                )
            )
        traces = await trace_db.list_traces(limit=3)
        assert len(traces) == 3

    @pytest.mark.asyncio
    async def test_export_trace(self, trace_db: TraceStore):
        result = ExecutionResult(content=[], is_error=False)
        trace = ExecutionTrace(
            trace_id="export-1",
            tool_name="tool",
            agent_id="agent",
            input_hash="in",
            output_hash="out",
            env_snapshot_hash="env",
            timestamp=0.0,
            duration_seconds=0.0,
            result=result,
        )
        await trace_db.store(trace)
        exported = await trace_db.export_trace("export-1")
        assert exported is not None
        assert "export-1" in exported

    @pytest.mark.asyncio
    async def test_get_nonexistent(self, trace_db: TraceStore):
        result = await trace_db.get("nonexistent")
        assert result is None


class TestDrift:
    def test_drift_category_exists(self):
        assert DriftCategory.NONE is not None
        assert DriftCategory.RANDOM_SEED is not None

    def test_drift_report_fields(self):
        report = DriftReport(
            original_trace_id="orig",
            replay_trace_id="replay",
            category=DriftCategory.NONE,
            original_output_hash="aaa",
            replay_output_hash="aaa",
            details={},
        )
        assert report.category == DriftCategory.NONE

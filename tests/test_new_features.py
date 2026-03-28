"""Tests for new features: ContextHook, SandboxHook, ping(), policy watcher, trace retention."""

from __future__ import annotations

import time
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

from mcpkernel.proxy.interceptor import InterceptorContext, MCPToolCall


# ---------------------------------------------------------------------------
# ContextHook tests
# ---------------------------------------------------------------------------
class TestContextHook:
    """Tests for ContextHook — context minimization in the pipeline."""

    def _make_ctx(self, arguments: dict) -> InterceptorContext:
        call = MCPToolCall(
            request_id=1,
            tool_name="test_tool",
            arguments=arguments,
            raw_jsonrpc={"jsonrpc": "2.0", "method": "tools/call", "id": 1},
        )
        return InterceptorContext(call=call)

    @pytest.mark.asyncio
    async def test_small_context_not_pruned(self):
        """Small arguments below token budget are not modified."""
        from mcpkernel.proxy.hooks import ContextHook

        hook = ContextHook(strategy="moderate", max_context_tokens=4096)
        ctx = self._make_ctx({"key": "small value"})
        original_args = dict(ctx.call.arguments)

        await hook.pre_execution(ctx)

        assert ctx.call.arguments == original_args
        assert "context_pruned" not in ctx.extra

    @pytest.mark.asyncio
    async def test_large_context_is_pruned(self):
        """Arguments exceeding token budget are pruned."""
        from mcpkernel.proxy.hooks import ContextHook

        # Create arguments that exceed 32 tokens (128 chars)
        hook = ContextHook(strategy="aggressive", max_context_tokens=32)
        big_args = {f"field_{i}": f"value {'x' * 200}" for i in range(20)}
        ctx = self._make_ctx(big_args)

        await hook.pre_execution(ctx)

        assert ctx.extra.get("context_pruned") is True
        assert "context_reduction_ratio" in ctx.extra

    @pytest.mark.asyncio
    async def test_hook_metadata(self):
        """ContextHook has correct priority and name."""
        from mcpkernel.proxy.hooks import ContextHook

        hook = ContextHook()
        assert hook.PRIORITY == 850
        assert hook.NAME == "context"


# ---------------------------------------------------------------------------
# SandboxHook tests
# ---------------------------------------------------------------------------
class TestSandboxHook:
    """Tests for SandboxHook — sandbox execution when policy says 'sandbox'."""

    def _make_ctx(self, policy_decision: str = "allow") -> InterceptorContext:
        call = MCPToolCall(
            request_id=1,
            tool_name="run_code",
            arguments={"code": "print('hello')"},
            raw_jsonrpc={"jsonrpc": "2.0", "method": "tools/call", "id": 1},
        )
        ctx = InterceptorContext(call=call)
        ctx.policy_decision = policy_decision
        return ctx

    @pytest.mark.asyncio
    async def test_non_sandbox_policy_skipped(self):
        """SandboxHook does nothing when policy_decision is not 'sandbox'."""
        from mcpkernel.proxy.hooks import SandboxHook

        backend = AsyncMock()
        hook = SandboxHook(backend)
        ctx = self._make_ctx("allow")

        await hook.pre_execution(ctx)

        backend.execute_code.assert_not_called()
        assert ctx.result is None

    @pytest.mark.asyncio
    async def test_sandbox_execution(self):
        """SandboxHook executes in sandbox when policy_decision is 'sandbox'."""
        from mcpkernel.proxy.hooks import SandboxHook

        backend = AsyncMock()
        backend.execute_code.return_value = "sandbox output"
        hook = SandboxHook(backend, timeout=10)
        ctx = self._make_ctx("sandbox")

        await hook.pre_execution(ctx)

        backend.execute_code.assert_called_once()
        assert ctx.result is not None
        assert ctx.result.is_error is False
        assert ctx.extra["sandboxed"] is True

    @pytest.mark.asyncio
    async def test_sandbox_execution_error(self):
        """SandboxHook handles execution errors gracefully."""
        from mcpkernel.proxy.hooks import SandboxHook

        backend = AsyncMock()
        backend.execute_code.side_effect = RuntimeError("boom")
        hook = SandboxHook(backend)
        ctx = self._make_ctx("sandbox")

        await hook.pre_execution(ctx)

        assert ctx.result is not None
        assert ctx.result.is_error is True
        assert ctx.extra["sandboxed"] is True

    @pytest.mark.asyncio
    async def test_hook_metadata(self):
        """SandboxHook has correct priority and name."""
        from mcpkernel.proxy.hooks import SandboxHook

        hook = SandboxHook(AsyncMock())
        assert hook.PRIORITY == 750
        assert hook.NAME == "sandbox"


# ---------------------------------------------------------------------------
# Upstream ping() tests
# ---------------------------------------------------------------------------
class TestUpstreamPing:
    """Tests for UpstreamConnection.ping()."""

    @pytest.mark.asyncio
    async def test_ping_returns_false_when_disconnected(self):
        """ping() returns False when not connected."""
        from mcpkernel.proxy.upstream import UpstreamConnection

        config = MagicMock()
        config.name = "test"
        conn = UpstreamConnection(config)

        result = await conn.ping()
        assert result is False

    @pytest.mark.asyncio
    async def test_ping_returns_true_on_success(self):
        """ping() returns True when session responds."""
        from mcpkernel.proxy.upstream import UpstreamConnection

        config = MagicMock()
        config.name = "test"
        conn = UpstreamConnection(config)
        conn._session = AsyncMock()
        conn._session.send_ping = AsyncMock()

        result = await conn.ping()
        assert result is True
        conn._session.send_ping.assert_called_once()

    @pytest.mark.asyncio
    async def test_ping_returns_false_on_exception(self):
        """ping() returns False when session raises."""
        from mcpkernel.proxy.upstream import UpstreamConnection

        config = MagicMock()
        config.name = "test"
        conn = UpstreamConnection(config)
        conn._session = AsyncMock()
        conn._session.send_ping = AsyncMock(side_effect=RuntimeError("down"))

        result = await conn.ping()
        assert result is False


# ---------------------------------------------------------------------------
# CLI --transport tests
# ---------------------------------------------------------------------------
class TestCLITransport:
    """Tests for CLI serve --transport option."""

    def test_serve_has_transport_option(self):
        """The serve command accepts --transport."""
        import re

        from typer.testing import CliRunner

        from mcpkernel.cli import app

        runner = CliRunner()
        result = runner.invoke(app, ["serve", "--help"])
        # Strip ANSI escape sequences before checking
        clean = re.sub(r"\x1b\[[0-9;]*m", "", result.output)
        assert "--transport" in clean
        assert "http" in clean or "stdio" in clean


# ---------------------------------------------------------------------------
# Policy watcher tests
# ---------------------------------------------------------------------------
class TestPolicyWatcher:
    """Tests for policy hot-reload watcher."""

    def test_collect_yaml_files(self, tmp_path: Path):
        """_collect_yaml_files finds YAML files in dirs and direct paths."""
        from mcpkernel.policy.watcher import _collect_yaml_files

        (tmp_path / "a.yaml").write_text("rules: []")
        (tmp_path / "b.yml").write_text("rules: []")
        (tmp_path / "c.txt").write_text("not yaml")

        files = _collect_yaml_files([tmp_path])
        assert len(files) == 2

    def test_collect_yaml_files_direct_path(self, tmp_path: Path):
        """_collect_yaml_files handles direct file paths."""
        from mcpkernel.policy.watcher import _collect_yaml_files

        f = tmp_path / "policy.yaml"
        f.write_text("rules: []")

        files = _collect_yaml_files([f])
        assert len(files) == 1

    def test_collect_yaml_files_nonexistent(self):
        """_collect_yaml_files handles nonexistent paths gracefully."""
        from mcpkernel.policy.watcher import _collect_yaml_files

        files = _collect_yaml_files([Path("/nonexistent/path")])
        assert len(files) == 0

    @pytest.mark.asyncio
    async def test_reload_file(self, tmp_path: Path):
        """_reload_file reloads rules into the engine."""
        from mcpkernel.policy.engine import PolicyEngine
        from mcpkernel.policy.watcher import _reload_file

        engine = PolicyEngine()

        # Create a minimal valid policy file
        policy_file = tmp_path / "test.yaml"
        policy_file.write_text(
            """
rules:
  - id: test-rule
    name: Test Rule
    tool_pattern: "*"
    action: allow
    priority: 100
"""
        )

        await _reload_file(engine, policy_file)
        # Should have loaded the rule
        assert len(engine._rules) >= 1


# ---------------------------------------------------------------------------
# Trace retention tests
# ---------------------------------------------------------------------------
class TestTraceRetention:
    """Tests for TraceStore.cleanup_old_traces()."""

    @pytest.mark.asyncio
    async def test_cleanup_old_traces(self, tmp_path: Path):
        """cleanup_old_traces removes traces older than max_age_days."""
        from mcpkernel.dee.trace_store import TraceStore

        store = TraceStore(db_path=tmp_path / "traces.db")
        await store.open()

        # Insert a trace record directly with an old timestamp
        old_timestamp = time.time() - (100 * 86400)  # 100 days ago
        assert store._db is not None
        await store._db.execute(
            """INSERT INTO traces
               (trace_id, tool_name, agent_id, input_hash, output_hash,
                env_snapshot_hash, timestamp, duration_seconds, result_json,
                created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                "old-trace-id",
                "test_tool",
                "agent1",
                "ihash",
                "ohash",
                "ehash",
                old_timestamp,
                0.5,
                '{"content": [], "is_error": false}',
                old_timestamp,
            ),
        )
        # Insert a recent trace
        recent_timestamp = time.time()
        await store._db.execute(
            """INSERT INTO traces
               (trace_id, tool_name, agent_id, input_hash, output_hash,
                env_snapshot_hash, timestamp, duration_seconds, result_json,
                created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                "new-trace-id",
                "test_tool",
                "agent1",
                "ihash2",
                "ohash2",
                "ehash2",
                recent_timestamp,
                0.3,
                '{"content": [], "is_error": false}',
                recent_timestamp,
            ),
        )
        await store._db.commit()

        # Cleanup with 90-day max age
        deleted = await store.cleanup_old_traces(max_age_days=90)
        assert deleted == 1

        # The recent trace should still exist
        recent = await store.get("new-trace-id")
        assert recent is not None

        # The old trace should be gone
        old = await store.get("old-trace-id")
        assert old is None

        await store.close()

    @pytest.mark.asyncio
    async def test_cleanup_no_old_traces(self, tmp_path: Path):
        """cleanup_old_traces returns 0 when there are no old traces."""
        from mcpkernel.dee.trace_store import TraceStore

        store = TraceStore(db_path=tmp_path / "traces.db")
        await store.open()

        deleted = await store.cleanup_old_traces(max_age_days=90)
        assert deleted == 0

        await store.close()

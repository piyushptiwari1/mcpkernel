"""Tests for proxy pipeline hooks — Policy, Taint, Audit, DEE wiring."""

from __future__ import annotations

import pytest

from mcpguard.policy.engine import PolicyAction, PolicyEngine, PolicyRule
from mcpguard.proxy.hooks import AuditHook, DEEHook, PolicyHook, TaintHook
from mcpguard.proxy.interceptor import (
    ExecutionResult,
    InterceptorContext,
    InterceptorPipeline,
    MCPToolCall,
)
from mcpguard.taint.tracker import TaintTracker


def _make_ctx(tool_name: str = "test_tool", arguments: dict | None = None) -> InterceptorContext:
    call = MCPToolCall(
        request_id=1,
        tool_name=tool_name,
        arguments=arguments or {},
        raw_jsonrpc={"jsonrpc": "2.0", "id": 1},
    )
    return InterceptorContext(call=call)


# ---------------------------------------------------------------------------
# PolicyHook
# ---------------------------------------------------------------------------
class TestPolicyHook:
    @pytest.mark.asyncio
    async def test_allows_when_no_rules(self):
        engine = PolicyEngine()
        hook = PolicyHook(engine)
        ctx = _make_ctx()
        await hook.pre_execution(ctx)
        assert not ctx.aborted
        assert ctx.policy_decision == "allow"

    @pytest.mark.asyncio
    async def test_denies_matching_rule(self):
        engine = PolicyEngine()
        engine.add_rule(PolicyRule(
            id="block-shell",
            name="Block shell",
            action=PolicyAction.DENY,
            tool_patterns=["shell_.*"],
        ))
        hook = PolicyHook(engine)
        ctx = _make_ctx(tool_name="shell_exec")
        await hook.pre_execution(ctx)
        assert ctx.aborted
        assert "deny" in ctx.policy_decision

    @pytest.mark.asyncio
    async def test_respects_default_deny(self):
        engine = PolicyEngine(default_action=PolicyAction.DENY)
        hook = PolicyHook(engine)
        ctx = _make_ctx(tool_name="anything")
        await hook.pre_execution(ctx)
        assert ctx.aborted
        assert ctx.policy_decision == "deny"

    @pytest.mark.asyncio
    async def test_stores_decision_in_extra(self):
        engine = PolicyEngine()
        hook = PolicyHook(engine)
        ctx = _make_ctx()
        await hook.pre_execution(ctx)
        assert "policy_decision" in ctx.extra


# ---------------------------------------------------------------------------
# TaintHook
# ---------------------------------------------------------------------------
class TestTaintHook:
    @pytest.mark.asyncio
    async def test_no_detect_fn_is_noop(self):
        tracker = TaintTracker()
        hook = TaintHook(tracker, detect_fn=None)
        ctx = _make_ctx()
        await hook.pre_execution(ctx)
        assert len(ctx.taint_labels) == 0

    @pytest.mark.asyncio
    async def test_detects_tainted_sources(self):
        from mcpguard.taint.sources import detect_tainted_sources

        tracker = TaintTracker()
        hook = TaintHook(tracker, detect_fn=detect_tainted_sources)
        ctx = _make_ctx(arguments={"code": "api_key = 'AKIAIOSFODNN7EXAMPLE1234'"})
        await hook.pre_execution(ctx)
        assert len(ctx.taint_labels) > 0

    @pytest.mark.asyncio
    async def test_post_execution_adds_summary(self):
        tracker = TaintTracker()
        hook = TaintHook(tracker)
        ctx = _make_ctx()
        ctx.result = ExecutionResult(content=[{"type": "text", "text": "ok"}])
        await hook.post_execution(ctx)
        assert "taint_summary" in ctx.extra


# ---------------------------------------------------------------------------
# Pipeline Integration
# ---------------------------------------------------------------------------
class TestPipelineIntegration:
    @pytest.mark.asyncio
    async def test_hooks_run_in_priority_order(self):
        pipeline = InterceptorPipeline()
        engine = PolicyEngine()
        tracker = TaintTracker()

        policy_hook = PolicyHook(engine)
        taint_hook = TaintHook(tracker)

        pipeline.register(taint_hook)
        pipeline.register(policy_hook)

        # Policy has higher priority, should be first
        assert pipeline.hooks[0].NAME == "policy"
        assert pipeline.hooks[1].NAME == "taint"

    @pytest.mark.asyncio
    async def test_policy_abort_stops_pipeline(self):
        """When policy denies, subsequent hooks still run but context is aborted."""
        pipeline = InterceptorPipeline()
        engine = PolicyEngine(default_action=PolicyAction.DENY)
        policy_hook = PolicyHook(engine)
        pipeline.register(policy_hook)

        ctx = _make_ctx()
        await pipeline.run_pre_execution(ctx)
        assert ctx.aborted

    @pytest.mark.asyncio
    async def test_full_pre_execution_with_policy_and_taint(self):
        pipeline = InterceptorPipeline()
        engine = PolicyEngine()
        tracker = TaintTracker()

        from mcpguard.taint.sources import detect_tainted_sources

        pipeline.register(PolicyHook(engine))
        pipeline.register(TaintHook(tracker, detect_fn=detect_tainted_sources))

        ctx = _make_ctx(arguments={"data": "normal text, no secrets"})
        await pipeline.run_pre_execution(ctx)
        assert not ctx.aborted
        assert ctx.policy_decision == "allow"

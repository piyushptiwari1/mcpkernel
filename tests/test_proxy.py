"""Tests for mcpguard.proxy — interceptor, auth, rate limiter, transform."""

from __future__ import annotations

import asyncio
import time

import pytest

from mcpguard.proxy.interceptor import (
    ExecutionResult,
    HookPhase,
    InterceptorContext,
    InterceptorPipeline,
    MCPToolCall,
    PluginHook,
    build_jsonrpc_error,
    build_jsonrpc_response,
    parse_mcp_tool_call,
)
from mcpguard.proxy.auth import APIKeyAuth, NoAuth, create_auth_backend
from mcpguard.proxy.rate_limit import InMemoryRateLimiter
from mcpguard.proxy.transform import normalize_from_mcp, normalize_to_mcp


class TestMCPToolCall:
    def test_parse_tool_call(self, sample_jsonrpc_request):
        call = parse_mcp_tool_call(sample_jsonrpc_request)
        assert call.tool_name == "execute_code"
        assert call.arguments["code"] == "print('hello')"

    def test_build_response(self):
        result = ExecutionResult(
            content=[{"type": "text", "text": "output"}],
            is_error=False,
        )
        resp = build_jsonrpc_response(1, result)
        assert resp["jsonrpc"] == "2.0"
        assert resp["id"] == 1
        assert "result" in resp

    def test_build_error(self):
        resp = build_jsonrpc_error(1, -32600, "Invalid request")
        assert resp["error"]["code"] == -32600


class TestInterceptorPipeline:
    class _TestHook(PluginHook):
        PRIORITY = 50
        NAME = "test_hook"

        def __init__(self):
            self.pre_called = False
            self.post_called = False

        async def pre_execution(self, ctx: InterceptorContext) -> None:
            self.pre_called = True

        async def post_execution(self, ctx: InterceptorContext) -> None:
            self.post_called = True

    @pytest.mark.asyncio
    async def test_pipeline_lifecycle(self, sample_jsonrpc_request):
        pipeline = InterceptorPipeline()
        hook = self._TestHook()
        pipeline.register(hook)

        call = parse_mcp_tool_call(sample_jsonrpc_request)
        ctx = InterceptorContext(call=call)

        await pipeline.run_pre_execution(ctx)
        assert hook.pre_called

        ctx.result = ExecutionResult(content=[], is_error=False)
        await pipeline.run_post_execution(ctx)
        assert hook.post_called

    @pytest.mark.asyncio
    async def test_pipeline_abort(self, sample_jsonrpc_request):
        class AbortHook(PluginHook):
            PRIORITY = 10
            NAME = "abort"

            async def pre_execution(self, ctx: InterceptorContext) -> None:
                ctx.aborted = True
                ctx.abort_reason = "blocked"

        pipeline = InterceptorPipeline()
        pipeline.register(AbortHook())

        call = parse_mcp_tool_call(sample_jsonrpc_request)
        ctx = InterceptorContext(call=call)
        await pipeline.run_pre_execution(ctx)
        assert ctx.aborted


class TestAuth:
    @pytest.mark.asyncio
    async def test_no_auth(self):
        backend = NoAuth()
        creds = await backend.authenticate({})
        assert creds.identity == "anonymous"

    @pytest.mark.asyncio
    async def test_api_key_valid(self):
        backend = APIKeyAuth(valid_keys=["test-key-123"])
        creds = await backend.authenticate({"authorization": "Bearer test-key-123"})
        assert creds is not None

    @pytest.mark.asyncio
    async def test_api_key_invalid(self):
        from mcpguard.utils import AuthError
        backend = APIKeyAuth(valid_keys=["test-key-123"])
        with pytest.raises(AuthError):
            await backend.authenticate({"authorization": "Bearer wrong-key"})

    def test_create_backend_none(self):
        backend = create_auth_backend(None)
        assert isinstance(backend, NoAuth)


class TestRateLimiter:
    def test_allows_within_limit(self):
        limiter = InMemoryRateLimiter(requests_per_minute=10, burst_size=10)
        result = limiter.check("client1")
        assert result.allowed

    def test_blocks_over_limit(self):
        limiter = InMemoryRateLimiter(requests_per_minute=2, burst_size=2)
        limiter.check("client1")
        limiter.check("client1")
        result = limiter.check("client1")
        assert not result.allowed
        assert result.retry_after > 0


class TestTransform:
    def test_normalize_to_mcp(self):
        flat = {"tool": "execute_code", "code": "print(1)"}
        result = normalize_to_mcp(flat)
        assert result["method"] == "tools/call"
        assert result["params"]["name"] == "execute_code"

    def test_normalize_from_mcp(self):
        jsonrpc = {
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "content": [{"type": "text", "text": "output"}],
            },
        }
        result = normalize_from_mcp(jsonrpc)
        assert "content" in result

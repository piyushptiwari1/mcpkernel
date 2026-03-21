"""FastAPI-based proxy server — the central MCP/A2A gateway.

Exposes:
* ``POST /mcp``   — StreamableHTTP JSON-RPC endpoint
* ``GET  /health`` — liveness probe
* ``GET  /metrics``— Prometheus scrape target (delegated to observability)
"""

from __future__ import annotations

import contextlib
import json
from contextlib import asynccontextmanager
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

import uvicorn
from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from mcpguard.config import MCPGuardSettings, get_config
from mcpguard.proxy.auth import AuthCredentials, create_auth_backend
from mcpguard.proxy.interceptor import (
    ExecutionResult,
    InterceptorContext,
    InterceptorPipeline,
    build_jsonrpc_error,
    build_jsonrpc_response,
    parse_mcp_tool_call,
)
from mcpguard.proxy.rate_limit import InMemoryRateLimiter
from mcpguard.proxy.transform import normalize_to_mcp
from mcpguard.utils import AuthError, Timer, get_logger

logger = get_logger(__name__)

# Module-level singletons wired at startup
_pipeline = InterceptorPipeline()
_rate_limiter: InMemoryRateLimiter | None = None
_auth_backend = None
_settings: MCPGuardSettings | None = None
_execute_fn = None  # sandbox.execute_code callback


def get_pipeline() -> InterceptorPipeline:
    return _pipeline


# ---------------------------------------------------------------------------
# Lifespan
# ---------------------------------------------------------------------------
@asynccontextmanager
async def _lifespan(app: FastAPI) -> AsyncIterator[None]:
    global _rate_limiter, _auth_backend, _settings, _execute_fn
    _settings = get_config()

    # Wire auth backend
    _auth_backend = create_auth_backend(_settings.auth)

    # Wire rate limiter
    if _settings.rate_limit.enabled:
        _rate_limiter = InMemoryRateLimiter(
            requests_per_minute=_settings.rate_limit.requests_per_minute,
            burst_size=_settings.rate_limit.burst_size,
        )

    # Import sandbox execute_code lazily to avoid hard dependency on Docker SDK at import time
    from mcpguard.sandbox import create_backend

    backend = create_backend(_settings.sandbox)
    _execute_fn = backend.execute_code

    # --- Wire interceptor pipeline hooks ---
    # Policy engine
    from mcpguard.policy import PolicyAction, PolicyEngine, load_policy_file
    from mcpguard.proxy.hooks import AuditHook, DEEHook, EBPFHook, PolicyHook, TaintHook

    policy_engine = PolicyEngine(
        default_action=PolicyAction(_settings.policy.default_action),
    )
    for policy_path in _settings.policy.policy_paths:
        if policy_path.exists():
            rules = load_policy_file(policy_path)
            policy_engine.add_rules(rules)
    _pipeline.register(PolicyHook(policy_engine))

    # eBPF / network egress enforcement
    if _settings.ebpf.enabled:
        from mcpguard.ebpf import EBPFProbe, NetworkRedirector
        from mcpguard.ebpf.redirector import EgressRule

        egress_rule = EgressRule(
            allowed_domains=set(_settings.sandbox.allowed_egress_domains),
        )
        redirector = NetworkRedirector(egress_rule)
        probe = EBPFProbe()
        if probe.available:
            await probe.start()
        _pipeline.register(EBPFHook(redirector, probe=probe if probe.available else None))

    # Taint tracker
    from mcpguard.taint import TaintTracker, detect_tainted_sources

    taint_tracker = TaintTracker()
    _pipeline.register(TaintHook(taint_tracker, detect_fn=detect_tainted_sources))

    # DEE trace store
    from mcpguard.dee import TraceStore

    trace_store = TraceStore(db_path=str(_settings.dee.store_path))
    await trace_store.open()
    _pipeline.register(DEEHook(trace_store))

    # Audit logger
    from mcpguard.audit import AuditLogger

    audit_logger = AuditLogger(db_path=str(_settings.audit.log_path).replace(".jsonl", ".db"))
    await audit_logger.initialize()
    _pipeline.register(AuditHook(audit_logger))

    logger.info(
        "mcpguard proxy started",
        host=_settings.proxy.host,
        port=_settings.proxy.port,
        backend=_settings.sandbox.backend.value,
        hooks=[h.NAME for h in _pipeline.hooks],
    )
    yield

    # Cleanup
    await trace_store.close()
    logger.info("mcpguard proxy shutting down")


# ---------------------------------------------------------------------------
# App factory
# ---------------------------------------------------------------------------
def create_proxy_app(settings: MCPGuardSettings | None = None) -> FastAPI:
    """Build the FastAPI application."""
    if settings is not None:
        from mcpguard.config import load_config

        load_config(overrides=settings.model_dump() if not isinstance(settings, dict) else settings)

    app = FastAPI(
        title="mcpguard",
        version="0.1.0",
        description="Mandatory MCP/A2A execution gateway",
        lifespan=_lifespan,
    )

    real_settings = settings or get_config()
    app.add_middleware(
        CORSMiddleware,
        allow_origins=real_settings.proxy.cors_origins,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # ---- Routes ----

    @app.get("/health")
    async def health() -> dict[str, str]:
        return {"status": "ok", "service": "mcpguard"}

    @app.post("/mcp")
    async def mcp_endpoint(request: Request) -> Response:
        """Primary MCP JSON-RPC handler — every tool call passes through here."""
        # --- Request body size enforcement ---
        content_length = request.headers.get("content-length")
        max_size = real_settings.proxy.max_request_size_bytes
        if content_length is not None and int(content_length) > max_size:
            return JSONResponse(
                build_jsonrpc_error(0, -32001, "Request body too large"),
                status_code=413,
            )
        body = await request.body()
        if len(body) > max_size:
            return JSONResponse(
                build_jsonrpc_error(0, -32001, "Request body too large"),
                status_code=413,
            )
        try:
            raw = json.loads(body)
        except json.JSONDecodeError:
            return JSONResponse(build_jsonrpc_error(0, -32700, "Parse error"), status_code=400)

        # Normalize non-MCP requests
        raw = normalize_to_mcp(raw)

        # --- Auth ---
        if _auth_backend is not None:
            try:
                headers = {
                    k.decode() if isinstance(k, bytes) else k: v.decode() if isinstance(v, bytes) else v
                    for k, v in request.headers.items()
                }
                creds: AuthCredentials = await _auth_backend.authenticate(headers)
            except AuthError as exc:
                return JSONResponse(
                    build_jsonrpc_error(raw.get("id", 0), -32001, str(exc)),
                    status_code=401,
                )
        else:
            creds = AuthCredentials(identity="anonymous", scopes={"*"}, metadata={})

        # --- Rate limiting ---
        if _rate_limiter is not None:
            rl = _rate_limiter.check(creds.identity)
            if not rl.allowed:
                resp = JSONResponse(
                    build_jsonrpc_error(raw.get("id", 0), -32002, "Rate limit exceeded"),
                    status_code=429,
                )
                resp.headers["Retry-After"] = str(int(rl.retry_after) + 1)
                resp.headers["X-RateLimit-Limit"] = str(rl.limit)
                resp.headers["X-RateLimit-Remaining"] = str(rl.remaining)
                return resp

        # --- Parse tool call ---
        tool_call = parse_mcp_tool_call(raw)
        if tool_call is None:
            # Not a tools/call — forward as-is (list_tools, etc.)
            return JSONResponse({"jsonrpc": "2.0", "id": raw.get("id", 0), "result": {}})

        # --- Interceptor pipeline ---
        ctx = InterceptorContext(call=tool_call)
        ctx.extra["auth"] = creds

        # Pre-execution hooks
        await _pipeline.run_pre_execution(ctx)
        if ctx.aborted:
            return JSONResponse(
                build_jsonrpc_error(tool_call.request_id, -32003, ctx.abort_reason),
                status_code=403,
            )

        # --- Execute in sandbox ---
        with Timer() as t:
            try:
                exec_result = await _do_execute(tool_call)
            except Exception as exc:
                exec_result = ExecutionResult(
                    content=[{"type": "text", "text": str(exc)}],
                    is_error=True,
                )
        exec_result.duration_seconds = t.elapsed
        ctx.result = exec_result

        # Post-execution hooks
        await _pipeline.run_post_execution(ctx)

        # Log hooks (fire-and-forget)
        with contextlib.suppress(Exception):
            await _pipeline.run_log(ctx)

        return JSONResponse(build_jsonrpc_response(tool_call.request_id, exec_result))

    return app


async def _do_execute(call: Any) -> ExecutionResult:
    """Route the tool call to the configured sandbox backend."""
    if _execute_fn is None:
        return ExecutionResult(
            content=[{"type": "text", "text": "No sandbox backend configured"}],
            is_error=True,
        )
    result = await _execute_fn(
        code=json.dumps({"tool": call.tool_name, "arguments": call.arguments}),
        timeout=get_config().sandbox.default_timeout_seconds,
    )
    return ExecutionResult(**result.__dict__) if not isinstance(result, ExecutionResult) else result


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------
def start_proxy_server(settings: MCPGuardSettings | None = None) -> None:
    """Start the uvicorn server (blocking)."""
    cfg = settings or get_config()
    app = create_proxy_app(settings)
    uvicorn.run(
        app,
        host=cfg.proxy.host,
        port=cfg.proxy.port,
        workers=cfg.proxy.workers,
        log_level="info",
    )

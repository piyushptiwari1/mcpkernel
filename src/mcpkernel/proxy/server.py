"""Transparent MCP security proxy — serves the MCP protocol natively.

MCPKernel sits between MCP clients (agents, IDEs, Claude Desktop, Cursor)
and upstream MCP servers.  Every tool call flows through the security
pipeline (policy → taint → audit → DEE → observability) before being
forwarded to the real upstream server.

Transports:
* **Streamable HTTP** ``POST /mcp``  — primary MCP transport (SSE streaming)
* **SSE** ``GET /sse`` + ``POST /messages/`` — legacy MCP SSE transport
* **stdio** — for direct integration (e.g. Claude Desktop config)

REST Endpoints:
* ``GET /health``   — liveness probe with upstream status
* ``GET /metrics``  — Prometheus scrape target
* ``GET /tools``    — aggregated tool list (REST convenience)
* ``GET /status``   — detailed system status
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
from mcp.server.lowlevel.server import Server as MCPLowLevelServer
from mcp.types import TextContent

from mcpkernel.config import MCPKernelSettings, get_config
from mcpkernel.observability.metrics import MetricsCollector, get_metrics
from mcpkernel.proxy.auth import AuthCredentials, create_auth_backend
from mcpkernel.proxy.interceptor import (
    ExecutionResult,
    InterceptorContext,
    InterceptorPipeline,
    MCPToolCall,
    build_jsonrpc_error,
    build_jsonrpc_response,
    parse_mcp_tool_call,
)
from mcpkernel.proxy.rate_limit import InMemoryRateLimiter
from mcpkernel.proxy.transform import normalize_to_mcp
from mcpkernel.proxy.upstream import UpstreamManager
from mcpkernel.utils import AuthError, Timer, generate_request_id, get_logger

logger = get_logger(__name__)

# Module-level singletons wired at startup
_pipeline = InterceptorPipeline()
_rate_limiter: InMemoryRateLimiter | None = None
_auth_backend: Any = None
_settings: MCPKernelSettings | None = None
_upstream_manager: UpstreamManager | None = None
_metrics: MetricsCollector | None = None
_mcp_server: MCPLowLevelServer | None = None
_session_manager: Any = None


def get_pipeline() -> InterceptorPipeline:
    return _pipeline


def get_upstream_manager() -> UpstreamManager | None:
    return _upstream_manager


# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# Security pipeline execution
# ---------------------------------------------------------------------------
async def _run_security_pipeline(
    tool_name: str,
    arguments: dict[str, Any],
    raw_jsonrpc: dict[str, Any] | None = None,
) -> tuple[ExecutionResult, InterceptorContext]:
    """Run the full security pipeline for a tool call, then forward upstream."""
    tool_call = MCPToolCall(
        request_id=generate_request_id(),
        tool_name=tool_name,
        arguments=arguments or {},
        raw_jsonrpc=raw_jsonrpc or {},
    )
    ctx = InterceptorContext(call=tool_call)
    ctx.extra["auth"] = AuthCredentials(identity="anonymous", scopes={"*"}, metadata={})

    # Pre-execution hooks (policy, taint, ebpf checks)
    await _pipeline.run_pre_execution(ctx)
    if ctx.aborted:
        exec_result = ExecutionResult(
            content=[{"type": "text", "text": ctx.abort_reason}],
            is_error=True,
        )
        ctx.result = exec_result
        return exec_result, ctx

    # Forward to upstream
    with Timer() as t:
        exec_result = await _forward_to_upstream(tool_call)
    exec_result.duration_seconds = t.elapsed
    ctx.result = exec_result

    # Post-execution hooks (taint on response, DEE trace)
    await _pipeline.run_post_execution(ctx)

    # Log hooks (fire-and-forget)
    with contextlib.suppress(Exception):
        await _pipeline.run_log(ctx)

    # Metrics
    if _metrics:
        outcome = "blocked" if ctx.aborted else ("error" if exec_result.is_error else "success")
        _metrics.tool_calls_total.labels(tool_name=tool_name, outcome=outcome).inc()
        _metrics.tool_call_duration.labels(tool_name=tool_name).observe(exec_result.duration_seconds)

    return exec_result, ctx


async def _forward_to_upstream(call: MCPToolCall) -> ExecutionResult:
    """Forward tool call to the correct upstream MCP server."""
    if _upstream_manager is None or not _upstream_manager.connections:
        return ExecutionResult(
            content=[{"type": "text", "text": "No upstream MCP servers configured"}],
            is_error=True,
        )

    try:
        result = await _upstream_manager.call_tool(call.tool_name, call.arguments)
        content_list = []
        for item in result.content:
            if hasattr(item, "text"):
                content_list.append({"type": "text", "text": item.text})
            elif hasattr(item, "data"):
                content_list.append({"type": item.type, "data": item.data})
            else:
                content_list.append({"type": "text", "text": str(item)})

        return ExecutionResult(
            content=content_list,
            is_error=bool(result.isError) if result.isError is not None else False,
        )
    except Exception as exc:
        logger.error("upstream call failed", tool=call.tool_name, error=str(exc))
        return ExecutionResult(
            content=[{"type": "text", "text": f"Upstream error: {exc}"}],
            is_error=True,
        )


# ---------------------------------------------------------------------------
# Low-level MCP server setup (proxy mode)
# ---------------------------------------------------------------------------
def _create_mcp_server() -> MCPLowLevelServer:
    """Create a low-level MCP Server with proxy handlers.

    Uses the low-level Server API (not FastMCP) to avoid automatic
    schema introspection — since we're proxying, we need raw control
    over tool listing and call dispatch.
    """
    server = MCPLowLevelServer("mcpkernel")

    @server.list_tools()  # type: ignore[no-untyped-call, untyped-decorator]
    async def _list_tools() -> list[Any]:
        if _upstream_manager is None:
            return []
        return await _upstream_manager.list_all_tools()

    @server.call_tool()  # type: ignore[untyped-decorator]
    async def _call_tool(name: str, arguments: dict[str, Any] | None = None) -> list[TextContent]:
        args = arguments or {}
        exec_result, ctx = await _run_security_pipeline(name, args)
        if ctx.aborted:
            return [TextContent(type="text", text=f"[BLOCKED] {ctx.abort_reason}")]
        contents: list[TextContent] = []
        for c in exec_result.content:
            if isinstance(c, dict):
                contents.append(TextContent(type="text", text=c.get("text", str(c))))
            else:
                contents.append(TextContent(type="text", text=str(c)))
        return contents

    @server.list_resources()  # type: ignore[no-untyped-call, untyped-decorator]
    async def _list_resources() -> list[Any]:
        if _upstream_manager is None:
            return []
        return await _upstream_manager.list_all_resources()

    @server.read_resource()  # type: ignore[no-untyped-call, untyped-decorator]
    async def _read_resource(uri: Any) -> str:
        if _upstream_manager is None:
            return ""
        result = await _upstream_manager.read_resource(str(uri))
        for content in result.contents:
            if hasattr(content, "text"):
                return content.text
            if hasattr(content, "blob"):
                return content.blob
        return ""

    @server.list_prompts()  # type: ignore[no-untyped-call, untyped-decorator]
    async def _list_prompts() -> list[Any]:
        if _upstream_manager is None:
            return []
        return await _upstream_manager.list_all_prompts()

    @server.get_prompt()  # type: ignore[no-untyped-call, untyped-decorator]
    async def _get_prompt(name: str, arguments: dict[str, str] | None = None) -> Any:
        if _upstream_manager is None:
            from mcp.types import GetPromptResult, PromptMessage

            return GetPromptResult(
                messages=[
                    PromptMessage(
                        role="assistant",
                        content=TextContent(type="text", text="No upstream"),
                    )
                ]
            )
        return await _upstream_manager.get_prompt(name, arguments or {})

    return server


# ---------------------------------------------------------------------------
# Lifespan — wires everything
# ---------------------------------------------------------------------------
@asynccontextmanager
async def _lifespan(app: FastAPI) -> AsyncIterator[None]:
    global _rate_limiter, _auth_backend, _settings, _upstream_manager, _metrics, _mcp_server, _session_manager

    _settings = get_config()
    _metrics = get_metrics()

    # Set build info
    import sys

    from mcpkernel import __version__

    _metrics.set_build_info(
        __version__,
        f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
    )

    # Wire auth backend
    _auth_backend = create_auth_backend(_settings.auth)

    # Wire rate limiter
    if _settings.rate_limit.enabled:
        _rate_limiter = InMemoryRateLimiter(
            requests_per_minute=_settings.rate_limit.requests_per_minute,
            burst_size=_settings.rate_limit.burst_size,
        )

    # --- Connect to upstream MCP servers ---
    _upstream_manager = UpstreamManager()
    if _settings.upstream:
        await _upstream_manager.connect_all(_settings.upstream)
        logger.info(
            "upstream servers connected",
            count=len(_upstream_manager.connections),
            tools=len(_upstream_manager.all_tool_names),
        )
    else:
        logger.info("no upstream servers configured — proxy will return errors for tool calls")

    # --- Wire interceptor pipeline hooks ---
    from mcpkernel.policy import PolicyAction, PolicyEngine, load_policy_file
    from mcpkernel.proxy.hooks import (
        AuditHook,
        DEEHook,
        EBPFHook,
        ObservabilityHook,
        PolicyHook,
        TaintHook,
    )

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
        from mcpkernel.ebpf import EBPFProbe, NetworkRedirector
        from mcpkernel.ebpf.redirector import EgressRule

        egress_rule = EgressRule(
            allowed_domains=set(_settings.sandbox.allowed_egress_domains),
        )
        redirector = NetworkRedirector(egress_rule)
        probe = EBPFProbe()
        if probe.available:
            await probe.start()
        _pipeline.register(EBPFHook(redirector, probe=probe if probe.available else None))

    # Taint tracker with propagator
    from mcpkernel.taint import TaintPropagator, TaintTracker, detect_tainted_sources

    taint_tracker = TaintTracker()
    taint_propagator = TaintPropagator(taint_tracker)

    # Optional Guardrails AI validator for enhanced taint detection
    guardrails_validator = None
    if _settings.guardrails_ai.enabled:
        from mcpkernel.integrations.guardrails import GuardrailsConfig as GRConfig
        from mcpkernel.integrations.guardrails import GuardrailsValidator

        gr_config = GRConfig(
            enabled=True,
            pii_validator=_settings.guardrails_ai.pii_validator,
            toxic_content=_settings.guardrails_ai.toxic_content,
            secrets_validator=_settings.guardrails_ai.secrets_validator,
            on_fail=_settings.guardrails_ai.on_fail,
        )
        guardrails_validator = GuardrailsValidator(config=gr_config)

    _pipeline.register(
        TaintHook(
            taint_tracker,
            detect_fn=detect_tainted_sources,
            propagator=taint_propagator,
            guardrails_validator=guardrails_validator,
        )
    )

    # DEE trace store
    from mcpkernel.dee import TraceStore

    trace_store = TraceStore(db_path=str(_settings.dee.store_path))
    await trace_store.open()
    _pipeline.register(DEEHook(trace_store))

    # Audit logger
    from mcpkernel.audit import AuditLogger

    audit_logger = AuditLogger(db_path=str(_settings.audit.log_path).replace(".jsonl", ".db"))
    await audit_logger.initialize()
    _pipeline.register(AuditHook(audit_logger))

    # Optional Langfuse exporter for observability
    langfuse_exporter = None
    if _settings.langfuse.enabled and _settings.langfuse.public_key and _settings.langfuse.secret_key:
        from mcpkernel.integrations.langfuse import LangfuseConfig as LFConfig
        from mcpkernel.integrations.langfuse import LangfuseExporter

        lf_config = LFConfig(
            enabled=True,
            public_key=_settings.langfuse.public_key,
            secret_key=_settings.langfuse.secret_key,
            host=_settings.langfuse.host,
            project_name=_settings.langfuse.project_name,
            batch_size=_settings.langfuse.batch_size,
            flush_interval_seconds=_settings.langfuse.flush_interval_seconds,
            max_retries=_settings.langfuse.max_retries,
            timeout_seconds=_settings.langfuse.timeout_seconds,
        )
        langfuse_exporter = LangfuseExporter(config=lf_config)
        await langfuse_exporter.start()

    # Observability hook (metrics)
    _pipeline.register(ObservabilityHook(_metrics, langfuse_exporter=langfuse_exporter))

    # --- Build native MCP server ---
    _mcp_server = _create_mcp_server()

    # Create and start the StreamableHTTPSessionManager directly.
    # We manage its lifecycle here so the task group is alive for the
    # entire duration of the FastAPI app (sub-app lifespans are NOT
    # propagated by Starlette, so we cannot rely on streamable_http_app()).
    from mcp.server.streamable_http_manager import StreamableHTTPSessionManager

    _session_manager = StreamableHTTPSessionManager(app=_mcp_server)

    async with _session_manager.run():
        logger.info(
            "mcpkernel proxy started",
            host=_settings.proxy.host,
            port=_settings.proxy.port,
            mode="proxy" if _settings.upstream else "standalone",
            upstream_count=len(_upstream_manager.connections),
            hooks=[h.NAME for h in _pipeline.hooks],
        )
        yield

    # Cleanup (runs after session manager shuts down)
    if langfuse_exporter:
        await langfuse_exporter.shutdown()
    await _upstream_manager.disconnect_all()
    await trace_store.close()
    await audit_logger.close()
    logger.info("mcpkernel proxy shutting down")


# ---------------------------------------------------------------------------
# App factory
# ---------------------------------------------------------------------------
def create_proxy_app(settings: MCPKernelSettings | None = None) -> FastAPI:
    """Build the FastAPI application with MCP protocol support.

    REST endpoints are served by FastAPI directly.
    MCP protocol (streamable HTTP + SSE) is served by mounting
    the FastMCP Starlette app.
    """
    if settings is not None:
        from mcpkernel.config import load_config

        load_config(overrides=settings.model_dump() if not isinstance(settings, dict) else settings)

    app = FastAPI(
        title="mcpkernel",
        version="0.1.1",
        description="Transparent MCP security proxy — policy, taint, audit for every tool call",
        lifespan=_lifespan,
    )

    real_settings = settings or get_config()
    app.add_middleware(
        CORSMiddleware,
        allow_origins=real_settings.proxy.cors_origins,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # ---- REST Endpoints ----

    @app.get("/health")
    async def health() -> dict[str, Any]:
        upstream_status = {}
        if _upstream_manager:
            for name, conn in _upstream_manager.connections.items():
                upstream_status[name] = {
                    "connected": conn.connected,
                    "tools": len(conn.tools),
                }
        return {
            "status": "ok",
            "service": "mcpkernel",
            "version": "0.1.1",
            "mode": "proxy" if real_settings.upstream else "standalone",
            "upstream": upstream_status,
            "hooks": [h.NAME for h in _pipeline.hooks] if _pipeline.hooks else [],
        }

    @app.get("/metrics")
    async def metrics_endpoint() -> Response:
        """Prometheus metrics scrape target."""
        metrics = get_metrics()
        return Response(content=metrics.export_prometheus(), media_type="text/plain; version=0.0.4")

    @app.get("/tools")
    async def tools_list() -> dict[str, Any]:
        """REST endpoint for listing all available tools."""
        if _upstream_manager is None:
            return {"tools": []}
        all_tools = await _upstream_manager.list_all_tools()
        return {
            "tools": [
                {
                    "name": t.name,
                    "description": t.description or "",
                    "server": _upstream_manager.get_server_for_tool(t.name).name  # type: ignore[union-attr]
                    if _upstream_manager.get_server_for_tool(t.name)
                    else "unknown",
                }
                for t in all_tools
            ]
        }

    @app.get("/status")
    async def status() -> dict[str, Any]:
        """Detailed system status."""
        return {
            "service": "mcpkernel",
            "version": "0.1.1",
            "pipeline_hooks": [{"name": h.NAME, "priority": h.PRIORITY} for h in _pipeline.hooks]
            if _pipeline.hooks
            else [],
            "upstream_servers": {
                name: {
                    "connected": conn.connected,
                    "tool_count": len(conn.tools),
                    "tools": [t.name for t in conn.tools],
                }
                for name, conn in (_upstream_manager.connections if _upstream_manager else {}).items()
            },
            "taint_mode": real_settings.taint.mode.value,
            "policy_default": real_settings.policy.default_action,
        }

    # ---- Legacy JSON-RPC endpoint (backward compat) ----

    @app.post("/mcp/legacy")
    async def mcp_legacy_endpoint(request: Request) -> Response:
        """Legacy JSON-RPC handler for backward compatibility.

        Clients that cannot use the standard MCP transport can POST
        raw JSON-RPC to this endpoint.
        """
        max_size = real_settings.proxy.max_request_size_bytes
        content_length = request.headers.get("content-length")
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

        raw = normalize_to_mcp(raw)

        # Auth
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

        # Rate limiting
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

        method = raw.get("method", "")

        if method == "tools/call":
            tool_call = parse_mcp_tool_call(raw)
            if tool_call is None:
                return JSONResponse(
                    build_jsonrpc_error(raw.get("id", 0), -32600, "Invalid tools/call params"),
                    status_code=400,
                )
            exec_result, ctx = await _run_security_pipeline(
                tool_call.tool_name, tool_call.arguments, tool_call.raw_jsonrpc
            )
            if ctx.aborted:
                return JSONResponse(
                    build_jsonrpc_error(tool_call.request_id, -32003, ctx.abort_reason),
                    status_code=403,
                )
            return JSONResponse(build_jsonrpc_response(tool_call.request_id, exec_result))

        if method == "tools/list":
            if _upstream_manager is None:
                tools = []
            else:
                tools = await _upstream_manager.list_all_tools()
            return JSONResponse(
                {
                    "jsonrpc": "2.0",
                    "id": raw.get("id", 0),
                    "result": {
                        "tools": [
                            {
                                "name": t.name,
                                "description": t.description or "",
                                **({"inputSchema": t.inputSchema} if t.inputSchema else {}),
                            }
                            for t in tools
                        ],
                    },
                }
            )

        return JSONResponse(
            build_jsonrpc_error(raw.get("id", 0), -32601, f"Method not found: {method}"),
            status_code=400,
        )

    # ---- Mount native MCP protocol ----
    # The StreamableHTTPSessionManager is started in the lifespan and stored
    # in _session_manager.  We mount a thin ASGI wrapper at "/mcp" that
    # delegates directly to session_manager.handle_request().
    # FastAPI routes (/health, /tools, /metrics, /status, /mcp/legacy)
    # are matched first; /mcp is the catch-all for native MCP protocol.

    class _LazyMCPMount:
        """ASGI app that delegates to the StreamableHTTPSessionManager.

        The session manager is created during lifespan, so this wrapper
        delays the lookup until the first request arrives.
        """

        async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
            if _session_manager is not None:
                await _session_manager.handle_request(scope, receive, send)
            else:
                # MCP server not ready yet
                if scope["type"] == "http":
                    from starlette.responses import JSONResponse as StarletteJSON

                    resp = StarletteJSON({"error": "MCP server not initialized"}, status_code=503)
                    await resp(scope, receive, send)

    app.mount("/mcp", _LazyMCPMount())  # type: ignore[arg-type]

    return app


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------
def start_proxy_server(settings: MCPKernelSettings | None = None) -> None:
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


async def start_stdio_server(settings: MCPKernelSettings | None = None) -> None:
    """Start MCPKernel as a stdio MCP server (for Claude Desktop / Cursor config)."""
    global _settings, _upstream_manager, _pipeline, _metrics, _mcp_server

    from mcpkernel.config import load_config

    _settings = load_config(config_path=getattr(settings, "config_path", None) if settings else None)
    _metrics = get_metrics()

    # Connect to upstream servers
    _upstream_manager = UpstreamManager()
    if _settings.upstream:
        await _upstream_manager.connect_all(_settings.upstream)

    # Wire pipeline
    from mcpkernel.policy import PolicyAction, PolicyEngine, load_policy_file
    from mcpkernel.proxy.hooks import AuditHook, DEEHook, ObservabilityHook, PolicyHook, TaintHook

    policy_engine = PolicyEngine(default_action=PolicyAction(_settings.policy.default_action))
    for policy_path in _settings.policy.policy_paths:
        if policy_path.exists():
            rules = load_policy_file(policy_path)
            policy_engine.add_rules(rules)
    _pipeline.register(PolicyHook(policy_engine))

    from mcpkernel.taint import TaintPropagator, TaintTracker, detect_tainted_sources

    taint_tracker = TaintTracker()

    # Optional Guardrails AI validator
    guardrails_validator_stdio = None
    if _settings.guardrails_ai.enabled:
        from mcpkernel.integrations.guardrails import GuardrailsConfig as GRConfig
        from mcpkernel.integrations.guardrails import GuardrailsValidator

        gr_config = GRConfig(
            enabled=True,
            pii_validator=_settings.guardrails_ai.pii_validator,
            toxic_content=_settings.guardrails_ai.toxic_content,
            secrets_validator=_settings.guardrails_ai.secrets_validator,
            on_fail=_settings.guardrails_ai.on_fail,
        )
        guardrails_validator_stdio = GuardrailsValidator(config=gr_config)

    _pipeline.register(
        TaintHook(
            taint_tracker,
            detect_fn=detect_tainted_sources,
            propagator=TaintPropagator(taint_tracker),
            guardrails_validator=guardrails_validator_stdio,
        )
    )

    from mcpkernel.dee import TraceStore

    trace_store = TraceStore(db_path=str(_settings.dee.store_path))
    await trace_store.open()
    _pipeline.register(DEEHook(trace_store))

    from mcpkernel.audit import AuditLogger

    audit_logger = AuditLogger(db_path=str(_settings.audit.log_path).replace(".jsonl", ".db"))
    await audit_logger.initialize()
    _pipeline.register(AuditHook(audit_logger))

    # Optional Langfuse exporter
    langfuse_exporter_stdio = None
    if _settings.langfuse.enabled and _settings.langfuse.public_key and _settings.langfuse.secret_key:
        from mcpkernel.integrations.langfuse import LangfuseConfig as LFConfig
        from mcpkernel.integrations.langfuse import LangfuseExporter

        lf_config = LFConfig(
            enabled=True,
            public_key=_settings.langfuse.public_key,
            secret_key=_settings.langfuse.secret_key,
            host=_settings.langfuse.host,
            project_name=_settings.langfuse.project_name,
        )
        langfuse_exporter_stdio = LangfuseExporter(config=lf_config)
        await langfuse_exporter_stdio.start()

    _pipeline.register(ObservabilityHook(_metrics, langfuse_exporter=langfuse_exporter_stdio))

    # Build MCP server
    _mcp_server = _create_mcp_server()

    logger.info("starting mcpkernel stdio server")

    from mcp.server.stdio import stdio_server

    async with stdio_server() as (read_stream, write_stream):
        await _mcp_server.run(read_stream, write_stream, _mcp_server.create_initialization_options())

    # Cleanup
    if langfuse_exporter_stdio:
        await langfuse_exporter_stdio.shutdown()
    await _upstream_manager.disconnect_all()
    await trace_store.close()
    await audit_logger.close()

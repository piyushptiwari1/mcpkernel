"""High-level Python API for MCPKernel.

Provides :class:`MCPKernelProxy` for programmatic use and :func:`protect`
as a one-line decorator for securing tool functions.

Usage::

    from mcpkernel.api import MCPKernelProxy

    proxy = MCPKernelProxy(
        upstream=["http://localhost:3000/mcp"],
        policy="strict",
        taint=True,
    )
    await proxy.start()
    result = await proxy.call_tool("read_file", {"path": "data.csv"})
    await proxy.stop()
"""

from __future__ import annotations

import functools
from pathlib import Path
from typing import Any

from mcpkernel.utils import generate_request_id, get_logger

logger = get_logger(__name__)

# Built-in policy presets (name → config dict)
POLICY_PRESETS: dict[str, dict[str, Any]] = {
    "permissive": {
        "default_action": "allow",
        "description": "Audit everything, block nothing. Good for development.",
    },
    "standard": {
        "default_action": "audit",
        "description": "Block known-dangerous patterns, audit the rest.",
    },
    "strict": {
        "default_action": "deny",
        "description": "Deny-by-default. Only explicitly allowed tools pass.",
    },
    "owasp-asi-2026": {
        "default_action": "deny",
        "description": "Full OWASP ASI 2026 compliance rule set.",
        "policy_paths": ["policies/owasp_asi_2026_strict.yaml"],
    },
}


class MCPKernelProxy:
    """Programmatic interface to the MCPKernel security pipeline.

    This is the primary Python API. Users create an instance, call
    :meth:`start`, then route tool calls through :meth:`call_tool`.

    Parameters
    ----------
    upstream:
        List of upstream MCP server URLs or config dicts.
    policy:
        Either a preset name (``"permissive"``, ``"standard"``, ``"strict"``,
        ``"owasp-asi-2026"``), a path to a YAML policy file, or ``None``
        for defaults.
    taint:
        Enable taint detection (secrets, PII) on tool arguments.
    audit:
        Enable append-only audit logging.
    sandbox:
        Enable sandbox execution for ``"sandbox"`` policy decisions.
    context_pruning:
        Enable context minimization for large arguments.
    config_path:
        Optional path to a YAML config file (overrides all other kwargs).
    host:
        HTTP bind address (only used if :meth:`serve` is called).
    port:
        HTTP bind port (only used if :meth:`serve` is called).
    """

    def __init__(
        self,
        *,
        upstream: list[str | dict[str, Any]] | None = None,
        policy: str | Path | None = "standard",
        taint: bool = True,
        audit: bool = True,
        sandbox: bool = False,
        context_pruning: bool = False,
        config_path: Path | str | None = None,
        host: str = "127.0.0.1",
        port: int = 8080,
    ) -> None:
        self._upstream_specs = upstream or []
        self._policy_spec = policy
        self._taint_enabled = taint
        self._audit_enabled = audit
        self._sandbox_enabled = sandbox
        self._context_pruning = context_pruning
        self._config_path = Path(config_path) if config_path else None
        self._host = host
        self._port = port

        # Runtime state (set during start)
        self._settings: Any = None
        self._pipeline: Any = None
        self._upstream_manager: Any = None
        self._policy_engine: Any = None
        self._trace_store: Any = None
        self._audit_logger: Any = None
        self._started = False

    @property
    def started(self) -> bool:
        """Whether the proxy has been started."""
        return self._started

    @property
    def policy_preset(self) -> str | None:
        """The active policy preset name, if any."""
        if isinstance(self._policy_spec, str) and self._policy_spec in POLICY_PRESETS:
            return self._policy_spec
        return None

    @property
    def hooks(self) -> list[str]:
        """Names of registered pipeline hooks."""
        if self._pipeline is None:
            return []
        return [h.NAME for h in self._pipeline.hooks]

    @property
    def tool_names(self) -> set[str]:
        """Tool names available from upstream servers."""
        if self._upstream_manager is None:
            return set()
        return self._upstream_manager.all_tool_names

    async def start(self) -> None:
        """Initialize the security pipeline and connect to upstreams.

        This must be called before :meth:`call_tool`.
        """
        if self._started:
            return

        from mcpkernel.config import load_config
        from mcpkernel.proxy.interceptor import InterceptorPipeline
        from mcpkernel.proxy.upstream import UpstreamManager

        # Build settings from config file or kwargs
        if self._config_path:
            self._settings = load_config(config_path=self._config_path)
        else:
            self._settings = self._build_settings()

        # Create pipeline
        self._pipeline = InterceptorPipeline()

        # Wire policy engine
        from mcpkernel.policy import PolicyAction, PolicyEngine, load_policy_file

        default_action = self._settings.policy.default_action
        self._policy_engine = PolicyEngine(default_action=PolicyAction(default_action))

        for policy_path in self._settings.policy.policy_paths:
            p = Path(policy_path)
            if p.exists():
                rules = load_policy_file(p)
                self._policy_engine.add_rules(rules)

        from mcpkernel.proxy.hooks import PolicyHook

        self._pipeline.register(PolicyHook(self._policy_engine))

        # Load built-in preset rules (in-memory, not file-based)
        if self.policy_preset and self.policy_preset != "owasp-asi-2026":
            from mcpkernel.presets import get_preset_rules

            preset_rules = get_preset_rules(self.policy_preset)
            self._policy_engine.add_rules(preset_rules)

        # Wire context hook
        if self._settings.context.enabled:
            from mcpkernel.proxy.hooks import ContextHook

            self._pipeline.register(
                ContextHook(
                    strategy=self._settings.context.strategy.value,
                    max_context_tokens=self._settings.context.max_context_tokens,
                )
            )

        # Wire taint hook
        if self._taint_enabled:
            from mcpkernel.proxy.hooks import TaintHook
            from mcpkernel.taint import TaintPropagator, TaintTracker, detect_tainted_sources

            tracker = TaintTracker()
            propagator = TaintPropagator(tracker)
            self._pipeline.register(TaintHook(tracker, detect_fn=detect_tainted_sources, propagator=propagator))

        # Wire DEE trace store
        from mcpkernel.dee import TraceStore
        from mcpkernel.proxy.hooks import DEEHook

        self._trace_store = TraceStore(db_path=str(self._settings.dee.store_path))
        await self._trace_store.open()
        self._pipeline.register(DEEHook(self._trace_store))

        # Wire audit hook
        if self._audit_enabled:
            from mcpkernel.audit import AuditLogger
            from mcpkernel.proxy.hooks import AuditHook

            db_path = str(self._settings.audit.log_path).replace(".jsonl", ".db")
            self._audit_logger = AuditLogger(db_path=db_path)
            await self._audit_logger.initialize()
            self._pipeline.register(AuditHook(self._audit_logger))

        # Wire sandbox hook
        if self._sandbox_enabled:
            from mcpkernel.proxy.hooks import SandboxHook
            from mcpkernel.sandbox import create_backend

            backend = create_backend(self._settings.sandbox)
            self._pipeline.register(SandboxHook(backend, timeout=self._settings.sandbox.default_timeout_seconds))

        # Wire observability
        from mcpkernel.observability.metrics import get_metrics
        from mcpkernel.proxy.hooks import ObservabilityHook

        self._pipeline.register(ObservabilityHook(get_metrics()))

        # Connect upstream servers
        self._upstream_manager = UpstreamManager()
        if self._settings.upstream:
            await self._upstream_manager.connect_all(self._settings.upstream)

        self._started = True
        logger.info(
            "MCPKernelProxy started",
            hooks=self.hooks,
            upstream_count=len(self._upstream_manager.connections),
            tools=len(self.tool_names),
        )

    async def stop(self) -> None:
        """Shut down the pipeline and disconnect from upstreams."""
        if not self._started:
            return

        if self._upstream_manager:
            await self._upstream_manager.disconnect_all()
        if self._trace_store:
            await self._trace_store.close()
        if self._audit_logger:
            await self._audit_logger.close()

        self._started = False
        logger.info("MCPKernelProxy stopped")

    async def call_tool(
        self,
        tool_name: str,
        arguments: dict[str, Any] | None = None,
        *,
        agent_id: str = "api",
    ) -> dict[str, Any]:
        """Route a tool call through the security pipeline.

        Parameters
        ----------
        tool_name:
            Name of the MCP tool to call.
        arguments:
            Tool call arguments.
        agent_id:
            Caller identity for audit.

        Returns
        -------
        dict with ``content`` (list), ``is_error`` (bool), and optional metadata.

        Raises
        ------
        mcpkernel.PolicyViolation:
            If the policy engine denies the call.
        RuntimeError:
            If the proxy is not started.
        """
        if not self._started:
            msg = "MCPKernelProxy not started. Call await proxy.start() first."
            raise RuntimeError(msg)

        from mcpkernel.proxy.interceptor import ExecutionResult, InterceptorContext, MCPToolCall
        from mcpkernel.utils import PolicyViolation

        call = MCPToolCall(
            request_id=generate_request_id(),
            tool_name=tool_name,
            arguments=arguments or {},
            raw_jsonrpc={"method": "tools/call", "params": {"name": tool_name}},
        )
        ctx = InterceptorContext(call=call)
        ctx.extra["auth"] = type("Auth", (), {"identity": agent_id})()

        # Pre-execution hooks
        await self._pipeline.run_pre_execution(ctx)

        if ctx.aborted:
            raise PolicyViolation("policy-deny", ctx.abort_reason)

        # Execute: if sandbox didn't already produce a result, forward upstream
        if ctx.result is None:
            upstream_result = await self._upstream_manager.call_tool(tool_name, arguments)
            ctx.result = ExecutionResult(
                content=[{"type": c.type, "text": getattr(c, "text", str(c))} for c in upstream_result.content],
                is_error=upstream_result.isError or False,
            )

        # Post-execution hooks
        await self._pipeline.run_post_execution(ctx)

        # Log hooks
        await self._pipeline.run_log(ctx)

        return {
            "content": ctx.result.content,
            "is_error": ctx.result.is_error,
            "trace_id": ctx.result.trace_id,
            "metadata": ctx.result.metadata,
        }

    async def list_tools(self) -> list[dict[str, Any]]:
        """List all tools available from upstream servers."""
        if not self._started:
            msg = "MCPKernelProxy not started."
            raise RuntimeError(msg)

        tools = await self._upstream_manager.list_all_tools()
        return [
            {
                "name": t.name,
                "description": getattr(t, "description", ""),
                "input_schema": getattr(t, "inputSchema", {}),
            }
            for t in tools
        ]

    def _build_settings(self) -> Any:
        """Build MCPKernelSettings from constructor kwargs."""
        from mcpkernel.config import MCPKernelSettings, UpstreamServerConfig

        overrides: dict[str, Any] = {
            "proxy": {"host": self._host, "port": self._port},
            "taint": {"mode": "light" if self._taint_enabled else "off"},
            "audit": {"enabled": self._audit_enabled},
            "context": {"enabled": self._context_pruning},
        }

        # Resolve policy
        if isinstance(self._policy_spec, Path) or (
            isinstance(self._policy_spec, str) and self._policy_spec not in POLICY_PRESETS
        ):
            # Treat as file path
            path = Path(self._policy_spec) if isinstance(self._policy_spec, str) else self._policy_spec
            overrides["policy"] = {"policy_paths": [str(path)], "default_action": "deny"}
        elif isinstance(self._policy_spec, str) and self._policy_spec in POLICY_PRESETS:
            preset = POLICY_PRESETS[self._policy_spec]
            overrides["policy"] = {
                "default_action": preset["default_action"],
                "policy_paths": preset.get("policy_paths", []),
            }

        settings = MCPKernelSettings()

        # Apply overrides
        for section_key, section_vals in overrides.items():
            if not isinstance(section_vals, dict):
                continue
            current = getattr(settings, section_key, None)
            if current is None:
                continue
            for k, v in section_vals.items():
                if hasattr(current, k):
                    setattr(current, k, v)

        # Build upstream configs
        upstream_configs = []
        for spec in self._upstream_specs:
            if isinstance(spec, str):
                upstream_configs.append(UpstreamServerConfig(name=f"server-{len(upstream_configs)}", url=spec))
            elif isinstance(spec, dict):
                upstream_configs.append(UpstreamServerConfig(**spec))
        settings.upstream = upstream_configs

        return settings

    async def __aenter__(self) -> MCPKernelProxy:
        await self.start()
        return self

    async def __aexit__(self, *exc: Any) -> None:
        await self.stop()


def protect(
    *,
    policy: str | Path = "standard",
    taint: bool = True,
    audit: bool = True,
    sandbox: bool = False,
) -> Any:
    """Decorator that wraps a tool function with MCPKernel security.

    The decorated function's arguments are routed through the MCPKernel
    security pipeline (policy check, taint scan, audit logging) before
    the original function executes.

    Usage::

        from mcpkernel import protect

        @protect(policy="strict", taint=True)
        async def read_data(path: str) -> str:
            return Path(path).read_text()

    Parameters
    ----------
    policy:
        Policy preset name or path to YAML file.
    taint:
        Enable taint detection on arguments.
    audit:
        Enable audit logging.
    sandbox:
        Enable sandbox execution.
    """
    _proxy: MCPKernelProxy | None = None

    def decorator(fn: Any) -> Any:
        @functools.wraps(fn)
        async def wrapper(*args: Any, **kwargs: Any) -> Any:
            nonlocal _proxy

            # Lazy-init the proxy on first call
            if _proxy is None or not _proxy.started:
                _proxy = MCPKernelProxy(
                    policy=policy,
                    taint=taint,
                    audit=audit,
                    sandbox=sandbox,
                )
                await _proxy.start()

                # Register cleanup to avoid resource leaks
                import asyncio
                import atexit

                _p = _proxy  # capture for closure

                def _cleanup() -> None:
                    try:
                        loop = asyncio.get_event_loop()
                        if loop.is_running():
                            loop.create_task(_p.stop())  # noqa: RUF006
                        else:
                            asyncio.run(_p.stop())
                    except Exception:
                        logger.debug("protect() cleanup failed", exc_info=True)

                atexit.register(_cleanup)

            # Build a tool call from function arguments
            import inspect

            sig = inspect.signature(fn)
            bound = sig.bind(*args, **kwargs)
            bound.apply_defaults()
            arguments = dict(bound.arguments)
            tool_name = fn.__name__

            from mcpkernel.proxy.interceptor import ExecutionResult, InterceptorContext, MCPToolCall
            from mcpkernel.utils import PolicyViolation

            call = MCPToolCall(
                request_id=generate_request_id(),
                tool_name=tool_name,
                arguments=arguments,
                raw_jsonrpc={"method": "tools/call", "params": {"name": tool_name}},
            )
            ctx = InterceptorContext(call=call)
            ctx.extra["auth"] = type("Auth", (), {"identity": f"protect:{tool_name}"})()

            # Run pre-execution checks
            await _proxy._pipeline.run_pre_execution(ctx)

            if ctx.aborted:
                raise PolicyViolation("policy-deny", ctx.abort_reason)

            # Call the original function
            if inspect.iscoroutinefunction(fn):
                result = await fn(*args, **kwargs)
            else:
                result = fn(*args, **kwargs)

            # Run post-execution + log with the result
            ctx.result = ExecutionResult(
                content=[{"type": "text", "text": str(result)}],
                is_error=False,
            )
            await _proxy._pipeline.run_post_execution(ctx)
            await _proxy._pipeline.run_log(ctx)

            return result

        return wrapper

    return decorator

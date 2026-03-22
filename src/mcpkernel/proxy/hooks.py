"""Built-in plugin hooks — wire Policy, Taint, Audit, and DEE into the proxy pipeline."""

from __future__ import annotations

from typing import Any

from mcpkernel.proxy.interceptor import InterceptorContext, PluginHook
from mcpkernel.utils import get_logger

logger = get_logger(__name__)


class PolicyHook(PluginHook):
    """Pre-execution hook: evaluate tool call against policy rules."""

    PRIORITY = 1000  # Runs first — policy is the primary gate
    NAME = "policy"

    def __init__(self, engine: Any) -> None:
        self._engine = engine

    async def pre_execution(self, ctx: InterceptorContext) -> None:
        decision = self._engine.evaluate(
            ctx.call.tool_name,
            ctx.call.arguments,
            taint_labels=ctx.taint_labels,
        )
        ctx.policy_decision = decision.action.value
        ctx.extra["policy_decision"] = decision

        if not decision.allowed:
            ctx.aborted = True
            ctx.abort_reason = f"Policy denied: {', '.join(decision.reasons)}"
            logger.warning(
                "policy hook blocked call",
                tool=ctx.call.tool_name,
                action=decision.action.value,
                reasons=decision.reasons,
            )
        else:
            logger.debug(
                "policy hook allowed call",
                tool=ctx.call.tool_name,
                action=decision.action.value,
            )


class TaintHook(PluginHook):
    """Pre-execution hook: scan arguments for tainted sources (secrets, PII)."""

    PRIORITY = 900  # Runs after policy, before execution
    NAME = "taint"

    def __init__(self, tracker: Any, *, detect_fn: Any = None) -> None:
        self._tracker = tracker
        self._detect_fn = detect_fn

    async def pre_execution(self, ctx: InterceptorContext) -> None:
        if self._detect_fn is None:
            return
        detections = self._detect_fn(ctx.call.arguments)
        for det in detections:
            ctx.taint_labels.add(det.label.value)
            self._tracker.mark(
                det.matched_text,
                det.label,
                source_id=ctx.call.correlation_id,
                metadata={"field": det.field_path, "tool": ctx.call.tool_name},
            )
        if detections:
            logger.info(
                "taint detected in arguments",
                tool=ctx.call.tool_name,
                labels=[d.label.value for d in detections],
                count=len(detections),
            )

    async def post_execution(self, ctx: InterceptorContext) -> None:
        if ctx.result is not None:
            ctx.extra["taint_summary"] = self._tracker.summary()


class AuditHook(PluginHook):
    """Log hook: record every tool call in the append-only audit log."""

    PRIORITY = 100  # Runs in log phase, order less critical
    NAME = "audit"

    def __init__(self, audit_logger: Any) -> None:
        self._logger = audit_logger

    async def log(self, ctx: InterceptorContext) -> None:
        from mcpkernel.audit.logger import AuditEntry

        auth = ctx.extra.get("auth")
        agent_id = auth.identity if auth else "unknown"
        outcome = "blocked" if ctx.aborted else ("error" if ctx.result and ctx.result.is_error else "success")

        entry = AuditEntry(
            event_type="tool_call",
            tool_name=ctx.call.tool_name,
            agent_id=agent_id,
            request_id=str(ctx.call.request_id),
            trace_id=ctx.result.trace_id or "" if ctx.result else "",
            action=ctx.policy_decision,
            outcome=outcome,
            details={
                "correlation_id": ctx.call.correlation_id,
                "taint_labels": sorted(ctx.taint_labels),
                "arguments_keys": sorted(ctx.call.arguments.keys()),
            },
        )
        await self._logger.log(entry)


class DEEHook(PluginHook):
    """Post-execution hook: wrap result in a deterministic execution envelope."""

    PRIORITY = 800  # Runs after execution, before log
    NAME = "dee"

    def __init__(self, trace_store: Any) -> None:
        self._store = trace_store

    async def post_execution(self, ctx: InterceptorContext) -> None:
        if ctx.result is None or ctx.result.is_error:
            return

        from mcpkernel.dee.envelope import wrap_execution

        async def _passthrough_execute(call: Any) -> Any:
            return ctx.result

        try:
            trace = await wrap_execution(
                ctx.call,
                _passthrough_execute,
                agent_id=(ctx.extra.get("auth", None) and ctx.extra["auth"].identity) or "unknown",
                sign=False,
            )
            ctx.result.trace_id = trace.trace_id
            await self._store.store(trace)
            logger.debug("dee envelope stored", trace_id=trace.trace_id)
        except Exception:
            logger.warning("dee hook failed (non-fatal)", exc_info=True)


class EBPFHook(PluginHook):
    """Pre-execution hook: enforce network egress policy via NetworkRedirector."""

    PRIORITY = 950  # Runs after policy, before taint
    NAME = "ebpf"

    def __init__(self, redirector: Any, *, probe: Any = None) -> None:
        self._redirector = redirector
        self._probe = probe

    async def pre_execution(self, ctx: InterceptorContext) -> None:
        for _key, value in ctx.call.arguments.items():
            if not isinstance(value, str):
                continue
            host, port = _extract_host_port(value)
            if host and not self._redirector.check_egress(host, port):
                ctx.aborted = True
                ctx.abort_reason = f"eBPF egress blocked: {host}:{port}"
                logger.warning("ebpf hook blocked egress", host=host, port=port, tool=ctx.call.tool_name)
                return

    async def log(self, ctx: InterceptorContext) -> None:
        if self._probe is not None:
            events = self._probe.events
            if events:
                ctx.extra["ebpf_events"] = len(events)
                self._probe.clear_events()


def _extract_host_port(value: str) -> tuple[str, int]:
    """Best-effort extraction of host and port from a URL string."""
    import urllib.parse

    try:
        parsed = urllib.parse.urlparse(value)
        if parsed.hostname:
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
            return parsed.hostname, port
    except Exception:  # noqa: S110
        pass
    return "", 0

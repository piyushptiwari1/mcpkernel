"""Built-in plugin hooks — wire Policy, Taint, Audit, DEE, Context, and Sandbox into the proxy pipeline."""

from __future__ import annotations

import json
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

    def __init__(
        self,
        tracker: Any,
        *,
        detect_fn: Any = None,
        propagator: Any = None,
        guardrails_validator: Any = None,
    ) -> None:
        self._tracker = tracker
        self._detect_fn = detect_fn
        self._propagator = propagator
        self._guardrails = guardrails_validator

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

        # Enhanced detection via Guardrails AI (if available)
        if self._guardrails is not None and self._guardrails.available:
            try:
                gr_detections = await self._guardrails.validate_dict(
                    ctx.call.arguments,
                    field_prefix=ctx.call.tool_name,
                )
                for gdet in gr_detections:
                    ctx.taint_labels.add(gdet.label.value)
                    self._tracker.mark(
                        gdet.matched_text,
                        gdet.label,
                        source_id=ctx.call.correlation_id,
                        metadata={
                            "field": gdet.field_path,
                            "tool": ctx.call.tool_name,
                            "validator": gdet.validator_name,
                        },
                    )
                if gr_detections:
                    logger.info(
                        "guardrails taint detected",
                        tool=ctx.call.tool_name,
                        labels=[d.label.value for d in gr_detections],
                        count=len(gr_detections),
                    )
            except Exception:
                logger.debug("guardrails validation failed (non-fatal)", exc_info=True)

    async def post_execution(self, ctx: InterceptorContext) -> None:
        if ctx.result is not None:
            ctx.extra["taint_summary"] = self._tracker.summary()
            # Propagate taint through result content if propagator available
            if self._propagator is not None and ctx.result.content:
                self._propagator.propagate_through_call(
                    ctx.call.tool_name,
                    ctx.call.arguments,
                    ctx.result.content,
                )


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


class ObservabilityHook(PluginHook):
    """Log hook: increment Prometheus metrics counters for every tool call."""

    PRIORITY = 50  # Runs after audit in log phase
    NAME = "observability"

    def __init__(self, metrics: Any, *, langfuse_exporter: Any = None) -> None:
        self._metrics = metrics
        self._langfuse = langfuse_exporter

    async def pre_execution(self, ctx: InterceptorContext) -> None:
        if self._metrics:
            self._metrics.active_connections.inc()

    async def post_execution(self, ctx: InterceptorContext) -> None:
        if self._metrics:
            self._metrics.active_connections.dec()
            # Record policy decision
            decision = ctx.extra.get("policy_decision")
            if decision and hasattr(decision, "action"):
                rule_id = decision.rule_id if hasattr(decision, "rule_id") else "default"
                self._metrics.policy_decisions.labels(
                    action=decision.action.value,
                    rule_id=str(rule_id),
                ).inc()

            # Record taint detections
            for label in ctx.taint_labels:
                self._metrics.taint_detections.labels(label=label, pattern="auto").inc()

    async def log(self, ctx: InterceptorContext) -> None:
        if self._metrics:
            self._metrics.audit_entries.labels(event_type="tool_call").inc()

        # Export to Langfuse if configured
        if self._langfuse is not None:
            try:
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
                        "taint_labels": sorted(ctx.taint_labels),
                    },
                )
                await self._langfuse.export_audit_entry(entry)
            except Exception:
                logger.debug("langfuse export failed (non-fatal)", exc_info=True)


class ContextHook(PluginHook):
    """Pre-execution hook: prune large arguments via context minimization."""

    PRIORITY = 850  # After taint (900), before DEE (800)
    NAME = "context"

    def __init__(
        self,
        *,
        strategy: str = "moderate",
        max_context_tokens: int = 4096,
    ) -> None:
        from mcpkernel.context.pruning import PruningStrategy

        self._strategy = PruningStrategy(strategy)
        self._max_tokens = max_context_tokens

    async def pre_execution(self, ctx: InterceptorContext) -> None:
        args_size = len(json.dumps(ctx.call.arguments, default=str))
        # Rough estimate: 1 token ≈ 4 chars
        estimated_tokens = args_size // 4

        if estimated_tokens <= self._max_tokens:
            return

        from mcpkernel.context.pruning import prune_context

        result = prune_context(
            ctx.call.arguments,
            strategy=self._strategy,
            query_terms=[ctx.call.tool_name],
            max_tokens=self._max_tokens,
        )
        ctx.extra["context_pruned"] = True
        ctx.extra["context_reduction_ratio"] = result.reduction_ratio
        ctx.extra["context_pruned_fields"] = result.pruned_fields

        # Replace arguments with reduced content
        from mcpkernel.proxy.interceptor import MCPToolCall

        ctx.call = MCPToolCall(
            request_id=ctx.call.request_id,
            tool_name=ctx.call.tool_name,
            arguments=result.reduced_content,
            raw_jsonrpc=ctx.call.raw_jsonrpc,
            correlation_id=ctx.call.correlation_id,
            timestamp=ctx.call.timestamp,
        )
        logger.info(
            "context pruned",
            tool=ctx.call.tool_name,
            reduction=f"{result.reduction_ratio:.1%}",
            pruned_fields=result.pruned_fields,
        )


class SandboxHook(PluginHook):
    """Pre-execution hook: execute tool call in sandbox when policy decision is 'sandbox'."""

    PRIORITY = 750  # After context (850), before DEE (800)
    NAME = "sandbox"

    def __init__(self, backend: Any, *, timeout: int = 30) -> None:
        self._backend = backend
        self._timeout = timeout

    async def pre_execution(self, ctx: InterceptorContext) -> None:
        if ctx.policy_decision != "sandbox":
            return

        from mcpkernel.proxy.interceptor import ExecutionResult

        try:
            sandbox_result = await self._backend.execute_code(
                json.dumps(ctx.call.arguments, default=str),
                timeout=self._timeout,
            )
            ctx.result = ExecutionResult(
                content=[{"type": "text", "text": str(sandbox_result)}],
                is_error=False,
                metadata={"sandboxed": True},
            )
            ctx.extra["sandboxed"] = True
            logger.info(
                "tool call executed in sandbox",
                tool=ctx.call.tool_name,
                timeout=self._timeout,
            )
        except Exception as exc:
            ctx.result = ExecutionResult(
                content=[{"type": "text", "text": f"Sandbox execution failed: {exc}"}],
                is_error=True,
                metadata={"sandboxed": True, "error": str(exc)},
            )
            ctx.extra["sandboxed"] = True
            logger.warning(
                "sandbox execution failed",
                tool=ctx.call.tool_name,
                error=str(exc),
            )

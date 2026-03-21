"""Prometheus metrics collector for MCPGuard."""

from __future__ import annotations

from prometheus_client import CollectorRegistry, Counter, Gauge, Histogram, Info, generate_latest

from mcpguard.utils import get_logger

logger = get_logger(__name__)

# Default registry
_REGISTRY = CollectorRegistry()


class MetricsCollector:
    """Central metrics collector exposing Prometheus-compatible metrics."""

    def __init__(self, registry: CollectorRegistry | None = None) -> None:
        reg = registry or _REGISTRY

        self.tool_calls_total = Counter(
            "mcpguard_tool_calls_total",
            "Total MCP tool calls processed",
            ["tool_name", "outcome"],
            registry=reg,
        )
        self.tool_call_duration = Histogram(
            "mcpguard_tool_call_duration_seconds",
            "Tool call execution duration",
            ["tool_name"],
            buckets=[0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0],
            registry=reg,
        )
        self.policy_decisions = Counter(
            "mcpguard_policy_decisions_total",
            "Policy evaluation outcomes",
            ["action", "rule_id"],
            registry=reg,
        )
        self.taint_detections = Counter(
            "mcpguard_taint_detections_total",
            "Taint source detections",
            ["label", "pattern"],
            registry=reg,
        )
        self.sandbox_executions = Counter(
            "mcpguard_sandbox_executions_total",
            "Sandbox code executions",
            ["backend", "outcome"],
            registry=reg,
        )
        self.active_connections = Gauge(
            "mcpguard_active_connections",
            "Current active client connections",
            registry=reg,
        )
        self.audit_entries = Counter(
            "mcpguard_audit_entries_total",
            "Total audit log entries",
            ["event_type"],
            registry=reg,
        )
        self.rate_limit_hits = Counter(
            "mcpguard_rate_limit_hits_total",
            "Rate limit enforcement events",
            registry=reg,
        )
        self.build_info = Info(
            "mcpguard",
            "MCPGuard build information",
            registry=reg,
        )
        self._registry = reg

    def set_build_info(self, version: str, python_version: str) -> None:
        self.build_info.info({"version": version, "python_version": python_version})

    def export_prometheus(self) -> bytes:
        """Export metrics in Prometheus text format."""
        return generate_latest(self._registry)


# Singleton
_collector: MetricsCollector | None = None


def get_metrics() -> MetricsCollector:
    global _collector
    if _collector is None:
        _collector = MetricsCollector()
    return _collector

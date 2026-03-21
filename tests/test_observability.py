"""Tests for mcpguard.observability — metrics, health."""

from __future__ import annotations

import pytest

from prometheus_client import CollectorRegistry

from mcpguard.observability.metrics import MetricsCollector
from mcpguard.observability.health import HealthCheck, HealthStatus, ComponentHealth
from mcpguard.observability.tracing import TracingSetup, setup_tracing


class TestMetrics:
    def test_tool_call_counter(self):
        registry = CollectorRegistry()
        metrics = MetricsCollector(registry=registry)
        metrics.tool_calls_total.labels(tool_name="test", outcome="success").inc()
        output = metrics.export_prometheus()
        assert b"mcpguard_tool_calls_total" in output

    def test_build_info(self):
        registry = CollectorRegistry()
        metrics = MetricsCollector(registry=registry)
        metrics.set_build_info("0.1.0", "3.12")
        output = metrics.export_prometheus()
        assert b"mcpguard_info" in output


class TestHealthCheck:
    @pytest.mark.asyncio
    async def test_healthy_when_all_pass(self):
        health = HealthCheck()

        async def _ok():
            return ComponentHealth("test", HealthStatus.HEALTHY)

        health.register("test", _ok)
        report = await health.check()
        assert report.status == HealthStatus.HEALTHY

    @pytest.mark.asyncio
    async def test_unhealthy_on_failure(self):
        health = HealthCheck()

        async def _fail():
            raise RuntimeError("down")

        health.register("db", _fail)
        report = await health.check()
        assert report.status == HealthStatus.UNHEALTHY

    @pytest.mark.asyncio
    async def test_degraded_status(self):
        health = HealthCheck()

        async def _ok():
            return ComponentHealth("svc1", HealthStatus.HEALTHY)

        async def _degraded():
            return ComponentHealth("svc2", HealthStatus.DEGRADED)

        health.register("svc1", _ok)
        health.register("svc2", _degraded)
        report = await health.check()
        assert report.status == HealthStatus.DEGRADED


class TestTracing:
    def test_disabled_tracing(self):
        config = TracingSetup(enabled=False)
        result = setup_tracing(config)
        assert result is None

"""Health check aggregator for MCPGuard components."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable


class HealthStatus(StrEnum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"


@dataclass
class ComponentHealth:
    name: str
    status: HealthStatus
    details: dict[str, Any] = field(default_factory=dict)


@dataclass
class HealthReport:
    status: HealthStatus
    components: list[ComponentHealth]
    version: str = ""


class HealthCheck:
    """Aggregate health status from registered components."""

    def __init__(self, version: str = "0.1.0") -> None:
        self._version = version
        self._checks: dict[str, Callable[[], Awaitable[ComponentHealth]]] = {}

    def register(self, name: str, check: Callable[[], Awaitable[ComponentHealth]]) -> None:
        self._checks[name] = check

    async def check(self) -> HealthReport:
        components = []
        for name, check_fn in self._checks.items():
            try:
                result = await check_fn()
                components.append(result)
            except Exception as exc:
                components.append(
                    ComponentHealth(
                        name=name,
                        status=HealthStatus.UNHEALTHY,
                        details={"error": str(exc)},
                    )
                )

        # Overall status: worst component wins
        if any(c.status == HealthStatus.UNHEALTHY for c in components):
            overall = HealthStatus.UNHEALTHY
        elif any(c.status == HealthStatus.DEGRADED for c in components):
            overall = HealthStatus.DEGRADED
        else:
            overall = HealthStatus.HEALTHY

        return HealthReport(
            status=overall,
            components=components,
            version=self._version,
        )

"""OpenTelemetry tracing setup for MCPKernel."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from mcpkernel.utils import get_logger

logger = get_logger(__name__)


@dataclass
class TracingSetup:
    """Configuration holder for OTEL tracing."""

    service_name: str = "mcpkernel"
    otlp_endpoint: str = ""
    otlp_protocol: str = "grpc"
    sample_rate: float = 1.0
    enabled: bool = True


def setup_tracing(config: TracingSetup) -> Any | None:
    """Initialize OpenTelemetry tracing with OTLP export.

    Returns the TracerProvider or None if tracing is disabled.
    """
    if not config.enabled:
        logger.info("tracing disabled")
        return None

    try:
        from opentelemetry import trace
        from opentelemetry.sdk.resources import SERVICE_NAME, Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor

        resource = Resource.create({SERVICE_NAME: config.service_name})
        provider = TracerProvider(resource=resource)

        if config.otlp_endpoint:
            if config.otlp_protocol == "grpc":
                from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import (
                    OTLPSpanExporter as GrpcExporter,
                )

                exporter = GrpcExporter(endpoint=config.otlp_endpoint)
            else:
                from opentelemetry.exporter.otlp.proto.http.trace_exporter import (  
                    OTLPSpanExporter as HttpExporter,
                )

                exporter = HttpExporter(endpoint=config.otlp_endpoint)
            provider.add_span_processor(BatchSpanProcessor(exporter))

        trace.set_tracer_provider(provider)
        logger.info(
            "tracing initialized",
            service=config.service_name,
            endpoint=config.otlp_endpoint or "none",
        )
        return provider

    except ImportError:
        logger.warning("opentelemetry SDK not installed — tracing unavailable")
        return None

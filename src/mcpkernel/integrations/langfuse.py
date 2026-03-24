"""Langfuse integration — export MCPKernel audit entries and DEE traces.

Langfuse (https://langfuse.com) is an open-source LLM observability platform.
This module provides a production-grade async exporter that ships MCPKernel's
audit log entries and DEE execution traces to Langfuse for visualization,
analytics, and debugging.

Usage::

    exporter = LangfuseExporter(
        public_key="pk-lf-...",
        secret_key="sk-lf-...",
        host="https://cloud.langfuse.com",   # or self-hosted
    )
    await exporter.export_audit_entries(entries)
    await exporter.export_dee_traces(traces)
    await exporter.flush()
    await exporter.shutdown()
"""

from __future__ import annotations

import asyncio
import contextlib
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from mcpkernel.utils import generate_request_id, get_logger

if TYPE_CHECKING:
    from mcpkernel.audit.logger import AuditEntry

logger = get_logger(__name__)


@dataclass
class LangfuseConfig:
    """Configuration for Langfuse exporter."""

    enabled: bool = False
    public_key: str = ""
    secret_key: str = ""
    host: str = "https://cloud.langfuse.com"
    project_name: str = "mcpkernel"
    batch_size: int = 50
    flush_interval_seconds: float = 5.0
    max_retries: int = 3
    timeout_seconds: float = 10.0


class LangfuseExporter:
    """Async exporter that ships audit entries and DEE traces to Langfuse.

    Uses Langfuse's REST API directly (via httpx) to avoid synchronous SDK
    constraints.  Batches events and flushes periodically or when the batch
    is full.

    Parameters
    ----------
    public_key:
        Langfuse public API key (``pk-lf-...``).
    secret_key:
        Langfuse secret API key (``sk-lf-...``).
    host:
        Langfuse API host URL.
    config:
        Optional full configuration dataclass. Overrides individual params.
    """

    def __init__(
        self,
        public_key: str = "",
        secret_key: str = "",
        host: str = "https://cloud.langfuse.com",
        *,
        config: LangfuseConfig | None = None,
    ) -> None:
        cfg = config or LangfuseConfig(
            public_key=public_key,
            secret_key=secret_key,
            host=host.rstrip("/"),
            enabled=bool(public_key and secret_key),
        )
        self._config = cfg
        self._batch: list[dict[str, Any]] = []
        self._lock = asyncio.Lock()
        self._flush_task: asyncio.Task[None] | None = None
        self._client: Any = None
        self._started = False

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------
    async def start(self) -> None:
        """Start the background flush loop and HTTP client."""
        if self._started or not self._config.enabled:
            return

        import httpx

        self._client = httpx.AsyncClient(
            base_url=self._config.host,
            auth=(self._config.public_key, self._config.secret_key),
            timeout=self._config.timeout_seconds,
            headers={"Content-Type": "application/json"},
        )
        self._flush_task = asyncio.create_task(self._periodic_flush())
        self._started = True
        logger.info(
            "langfuse exporter started",
            host=self._config.host,
            project=self._config.project_name,
        )

    async def shutdown(self) -> None:
        """Flush remaining events and close the HTTP client."""
        if not self._started:
            return
        if self._flush_task:
            self._flush_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._flush_task
        await self.flush()
        if self._client:
            await self._client.aclose()
        self._started = False
        logger.info("langfuse exporter shut down")

    # ------------------------------------------------------------------
    # Export methods
    # ------------------------------------------------------------------
    async def export_audit_entry(self, entry: AuditEntry) -> None:
        """Convert a single audit entry to a Langfuse event and enqueue it."""
        if not self._config.enabled:
            return

        event = _audit_entry_to_langfuse_event(entry, self._config.project_name)
        async with self._lock:
            self._batch.append(event)

        if len(self._batch) >= self._config.batch_size:
            await self.flush()

    async def export_audit_entries(self, entries: list[AuditEntry]) -> None:
        """Export a batch of audit entries."""
        for entry in entries:
            await self.export_audit_entry(entry)

    async def export_dee_trace(self, trace: dict[str, Any]) -> None:
        """Convert a DEE trace dict to Langfuse span events and enqueue."""
        if not self._config.enabled:
            return

        events = _dee_trace_to_langfuse_events(trace, self._config.project_name)
        async with self._lock:
            self._batch.extend(events)

        if len(self._batch) >= self._config.batch_size:
            await self.flush()

    async def export_dee_traces(self, traces: list[dict[str, Any]]) -> None:
        """Export a batch of DEE traces."""
        for trace in traces:
            await self.export_dee_trace(trace)

    # ------------------------------------------------------------------
    # Flush
    # ------------------------------------------------------------------
    async def flush(self) -> None:
        """Send all queued events to Langfuse's /api/public/ingestion endpoint."""
        if not self._client:
            return

        async with self._lock:
            if not self._batch:
                return
            to_send = list(self._batch)
            self._batch.clear()

        payload = {"batch": to_send}
        retries = 0

        while retries <= self._config.max_retries:
            try:
                resp = await self._client.post("/api/public/ingestion", json=payload)
                if resp.status_code in (200, 207):
                    logger.debug("langfuse flush ok", count=len(to_send))
                    return
                if resp.status_code == 429:
                    wait = min(2**retries, 30)
                    logger.warning("langfuse rate-limited, retrying", wait=wait)
                    await asyncio.sleep(wait)
                    retries += 1
                    continue
                logger.error(
                    "langfuse ingestion failed",
                    status=resp.status_code,
                    body=resp.text[:200],
                )
                return
            except Exception as exc:
                retries += 1
                if retries > self._config.max_retries:
                    logger.error("langfuse flush failed after retries", error=str(exc))
                    return
                await asyncio.sleep(min(2**retries, 30))

    async def _periodic_flush(self) -> None:
        """Background task that flushes every ``flush_interval_seconds``."""
        while True:
            await asyncio.sleep(self._config.flush_interval_seconds)
            await self.flush()


# ---------------------------------------------------------------------------
# Conversion helpers
# ---------------------------------------------------------------------------
def _audit_entry_to_langfuse_event(
    entry: AuditEntry,
    project: str,
) -> dict[str, Any]:
    """Convert an AuditEntry to a Langfuse ingestion event.

    Maps to Langfuse's ``trace-create`` or ``event-create`` type depending
    on the event_type:
    - ``tool_call`` → trace with generation span
    - everything else → standalone event
    """
    trace_id = entry.trace_id or entry.entry_id

    if entry.event_type == "tool_call":
        return {
            "id": generate_request_id(),
            "type": "trace-create",
            "timestamp": _epoch_to_iso(entry.timestamp),
            "body": {
                "id": trace_id,
                "name": f"tool:{entry.tool_name}",
                "userId": entry.agent_id or "anonymous",
                "metadata": {
                    "mcpkernel_entry_id": entry.entry_id,
                    "action": entry.action,
                    "outcome": entry.outcome,
                    "content_hash": entry.content_hash,
                    "project": project,
                },
                "tags": [
                    f"tool:{entry.tool_name}",
                    f"outcome:{entry.outcome}",
                    entry.action,
                ],
            },
        }

    return {
        "id": generate_request_id(),
        "type": "event-create",
        "timestamp": _epoch_to_iso(entry.timestamp),
        "body": {
            "traceId": trace_id,
            "name": entry.event_type,
            "metadata": {
                "mcpkernel_entry_id": entry.entry_id,
                "tool_name": entry.tool_name,
                "action": entry.action,
                "outcome": entry.outcome,
                "details": entry.details,
                "content_hash": entry.content_hash,
            },
        },
    }


def _dee_trace_to_langfuse_events(
    trace: dict[str, Any],
    project: str,
) -> list[dict[str, Any]]:
    """Convert a DEE trace dict to Langfuse trace + span events.

    Creates:
    1. A ``trace-create`` for the overall execution
    2. A ``span-create`` for the tool call execution span
    """
    trace_id = trace.get("trace_id", generate_request_id())
    tool_name = trace.get("tool_name", "unknown")
    duration = trace.get("duration_seconds", 0.0)
    ts = trace.get("timestamp", time.time())

    events: list[dict[str, Any]] = []

    # Trace header
    events.append(
        {
            "id": generate_request_id(),
            "type": "trace-create",
            "timestamp": _epoch_to_iso(ts),
            "body": {
                "id": trace_id,
                "name": f"dee:{tool_name}",
                "metadata": {
                    "input_hash": trace.get("input_hash", ""),
                    "output_hash": trace.get("output_hash", ""),
                    "signed": trace.get("signed", False),
                    "project": project,
                },
                "tags": ["dee", f"tool:{tool_name}"],
            },
        }
    )

    # Execution span
    start_time = _epoch_to_iso(ts)
    end_time = _epoch_to_iso(ts + duration)
    events.append(
        {
            "id": generate_request_id(),
            "type": "span-create",
            "timestamp": start_time,
            "body": {
                "traceId": trace_id,
                "name": f"execute:{tool_name}",
                "startTime": start_time,
                "endTime": end_time,
                "input": trace.get("input_preview", {}),
                "output": trace.get("output_preview", {}),
                "metadata": {
                    "input_hash": trace.get("input_hash", ""),
                    "output_hash": trace.get("output_hash", ""),
                    "replay_safe": trace.get("replay_safe", True),
                },
            },
        }
    )

    return events


def _epoch_to_iso(epoch: float) -> str:
    """Convert epoch seconds to ISO 8601 string for Langfuse API."""
    import datetime

    return datetime.datetime.fromtimestamp(epoch, tz=datetime.UTC).isoformat()

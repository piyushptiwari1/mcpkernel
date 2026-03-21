"""Immutable trace store backed by SQLite (WAL mode)."""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import TYPE_CHECKING, Any

import aiosqlite

from mcpguard.utils import get_logger

if TYPE_CHECKING:
    from mcpguard.dee.envelope import ExecutionTrace

logger = get_logger(__name__)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS traces (
    trace_id        TEXT PRIMARY KEY,
    tool_name       TEXT NOT NULL,
    agent_id        TEXT NOT NULL,
    input_hash      TEXT NOT NULL,
    output_hash     TEXT NOT NULL,
    env_snapshot_hash TEXT NOT NULL,
    timestamp       REAL NOT NULL,
    duration_seconds REAL NOT NULL,
    result_json     TEXT NOT NULL,
    sigstore_bundle TEXT,
    metadata_json   TEXT,
    created_at      REAL NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_traces_tool ON traces(tool_name);
CREATE INDEX IF NOT EXISTS idx_traces_agent ON traces(agent_id);
CREATE INDEX IF NOT EXISTS idx_traces_ts ON traces(timestamp);
"""


class TraceStore:
    """Append-only SQLite store for execution traces.

    Uses WAL mode for concurrent read access and single-writer safety.
    """

    def __init__(self, db_path: Path | str = "dee_store/traces.db") -> None:
        self._db_path = Path(db_path)
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._db: aiosqlite.Connection | None = None

    async def open(self) -> None:
        """Open the database connection and ensure the schema exists."""
        self._db = await aiosqlite.connect(str(self._db_path))
        await self._db.execute("PRAGMA journal_mode=WAL")
        await self._db.execute("PRAGMA synchronous=NORMAL")
        await self._db.executescript(_SCHEMA)
        await self._db.commit()
        logger.info("trace store opened", path=str(self._db_path))

    async def close(self) -> None:
        if self._db:
            await self._db.close()
            self._db = None

    async def store(self, trace: ExecutionTrace) -> None:
        """Insert an immutable trace record."""
        if self._db is None:
            await self.open()
        assert self._db is not None

        result_json = json.dumps(
            {
                "content": trace.result.content,
                "is_error": trace.result.is_error,
                "structured_content": trace.result.structured_content,
                "metadata": trace.result.metadata,
            },
            default=str,
        )
        metadata_json = json.dumps(trace.metadata, default=str) if trace.metadata else None

        await self._db.execute(
            """
            INSERT INTO traces
                (trace_id, tool_name, agent_id, input_hash, output_hash,
                 env_snapshot_hash, timestamp, duration_seconds, result_json,
                 sigstore_bundle, metadata_json, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                trace.trace_id,
                trace.tool_name,
                trace.agent_id,
                trace.input_hash,
                trace.output_hash,
                trace.env_snapshot_hash,
                trace.timestamp,
                trace.duration_seconds,
                result_json,
                trace.sigstore_bundle,
                metadata_json,
                time.time(),
            ),
        )
        await self._db.commit()
        logger.debug("trace stored", trace_id=trace.trace_id)

    async def get(self, trace_id: str) -> dict[str, Any] | None:
        """Retrieve a trace by ID."""
        if self._db is None:
            await self.open()
        assert self._db is not None

        async with self._db.execute("SELECT * FROM traces WHERE trace_id = ?", (trace_id,)) as cursor:
            row = await cursor.fetchone()
            if row is None:
                return None
            columns = [d[0] for d in cursor.description]
            return dict(zip(columns, row, strict=False))

    async def list_traces(
        self,
        *,
        tool_name: str | None = None,
        agent_id: str | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """List traces with optional filters."""
        if self._db is None:
            await self.open()
        assert self._db is not None

        conditions: list[str] = []
        params: list[Any] = []
        if tool_name:
            conditions.append("tool_name = ?")
            params.append(tool_name)
        if agent_id:
            conditions.append("agent_id = ?")
            params.append(agent_id)

        where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
        query = f"SELECT * FROM traces {where} ORDER BY timestamp DESC LIMIT ?"  # noqa: S608
        params.append(limit)

        async with self._db.execute(query, params) as cursor:
            rows = await cursor.fetchall()
            columns = [d[0] for d in cursor.description]
            return [dict(zip(columns, row, strict=False)) for row in rows]

    async def export_trace(self, trace_id: str, *, fmt: str = "json") -> str:
        """Export a trace for audit purposes."""
        record = await self.get(trace_id)
        if record is None:
            raise KeyError(f"Trace not found: {trace_id}")
        return json.dumps(record, indent=2, default=str)

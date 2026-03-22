"""Append-only audit logger with optional Sigstore signing."""

from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass, field
from typing import Any

import aiosqlite

from mcpkernel.utils import generate_request_id, get_logger, sha256_hex

logger = get_logger(__name__)


@dataclass
class AuditEntry:
    """A single audit log entry."""

    entry_id: str = field(default_factory=generate_request_id)
    timestamp: float = field(default_factory=time.time)
    event_type: str = ""
    tool_name: str = ""
    agent_id: str = ""
    request_id: str = ""
    trace_id: str = ""
    action: str = ""
    outcome: str = ""
    details: dict[str, Any] = field(default_factory=dict)
    content_hash: str = ""

    def compute_hash(self) -> str:
        """Deterministic hash of this entry's contents."""
        payload = json.dumps(
            {k: v for k, v in asdict(self).items() if k != "content_hash"},
            sort_keys=True,
            default=str,
        )
        self.content_hash = sha256_hex(payload.encode())
        return self.content_hash


class AuditLogger:
    """Append-only audit logger backed by SQLite.

    Entries are immutable — updates are not supported. Each entry is
    hashed for tamper detection.
    """

    def __init__(self, db_path: str = "mcpkernel_audit.db") -> None:
        self._db_path = db_path
        self._db: aiosqlite.Connection | None = None

    async def initialize(self) -> None:
        self._db = await aiosqlite.connect(self._db_path)
        await self._db.execute("PRAGMA journal_mode=WAL")
        await self._db.execute("PRAGMA synchronous=NORMAL")
        await self._db.execute("""
            CREATE TABLE IF NOT EXISTS audit_log (
                entry_id TEXT PRIMARY KEY,
                timestamp REAL NOT NULL,
                event_type TEXT NOT NULL,
                tool_name TEXT,
                agent_id TEXT,
                request_id TEXT,
                trace_id TEXT,
                action TEXT,
                outcome TEXT,
                details TEXT,
                content_hash TEXT NOT NULL
            )
        """)
        await self._db.execute("CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp)")
        await self._db.execute("CREATE INDEX IF NOT EXISTS idx_audit_tool ON audit_log(tool_name)")
        await self._db.commit()
        logger.info("audit logger initialized", db=self._db_path)

    async def log(self, entry: AuditEntry) -> str:
        """Append an audit entry. Returns the entry_id."""
        if not self._db:
            await self.initialize()
        assert self._db is not None

        entry.compute_hash()
        await self._db.execute(
            """INSERT INTO audit_log
               (entry_id, timestamp, event_type, tool_name, agent_id,
                request_id, trace_id, action, outcome, details, content_hash)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                entry.entry_id,
                entry.timestamp,
                entry.event_type,
                entry.tool_name,
                entry.agent_id,
                entry.request_id,
                entry.trace_id,
                entry.action,
                entry.outcome,
                json.dumps(entry.details, default=str),
                entry.content_hash,
            ),
        )
        await self._db.commit()
        logger.debug("audit entry logged", entry_id=entry.entry_id, event_type=entry.event_type)
        return entry.entry_id

    async def query(
        self,
        *,
        event_type: str | None = None,
        tool_name: str | None = None,
        since: float | None = None,
        limit: int = 100,
    ) -> list[AuditEntry]:
        """Query audit entries with optional filters."""
        if not self._db:
            await self.initialize()
        assert self._db is not None

        conditions = []
        params: list[Any] = []

        if event_type:
            conditions.append("event_type = ?")
            params.append(event_type)
        if tool_name:
            conditions.append("tool_name = ?")
            params.append(tool_name)
        if since is not None:
            conditions.append("timestamp >= ?")
            params.append(since)

        where = " AND ".join(conditions) if conditions else "1=1"
        params.append(limit)

        cursor = await self._db.execute(
            f"SELECT * FROM audit_log WHERE {where} ORDER BY timestamp DESC LIMIT ?",  # noqa: S608
            params,
        )
        rows = await cursor.fetchall()

        entries = []
        for row in rows:
            entries.append(
                AuditEntry(
                    entry_id=row[0],
                    timestamp=row[1],
                    event_type=row[2],
                    tool_name=row[3],
                    agent_id=row[4],
                    request_id=row[5],
                    trace_id=row[6],
                    action=row[7],
                    outcome=row[8],
                    details=json.loads(row[9]) if row[9] else {},
                    content_hash=row[10],
                )
            )
        return entries

    async def verify_integrity(self) -> dict[str, Any]:
        """Verify all entries' hashes match their contents."""
        if not self._db:
            await self.initialize()
        assert self._db is not None

        cursor = await self._db.execute("SELECT COUNT(*) FROM audit_log")
        row = await cursor.fetchone()
        total: int = row[0] if row else 0

        cursor = await self._db.execute("SELECT * FROM audit_log")
        rows = await cursor.fetchall()

        tampered = 0
        for row in rows:
            entry = AuditEntry(
                entry_id=row[0],
                timestamp=row[1],
                event_type=row[2],
                tool_name=row[3],
                agent_id=row[4],
                request_id=row[5],
                trace_id=row[6],
                action=row[7],
                outcome=row[8],
                details=json.loads(row[9]) if row[9] else {},
            )
            computed = entry.compute_hash()
            if computed != row[10]:
                tampered += 1

        return {
            "total_entries": total,
            "tampered_entries": tampered,
            "integrity_valid": tampered == 0,
        }

    async def close(self) -> None:
        if self._db:
            await self._db.close()
            self._db = None

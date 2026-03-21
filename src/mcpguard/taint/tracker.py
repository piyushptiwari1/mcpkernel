"""Core taint label and tracking engine."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from mcpguard.utils import generate_request_id, get_logger

logger = get_logger(__name__)


class TaintLabel(StrEnum):
    """Categories of taint applied to data flowing through MCP calls."""

    SECRET = "secret"  # noqa: S105
    PII = "pii"
    LLM_OUTPUT = "llm_output"
    USER_INPUT = "user_input"
    UNTRUSTED_EXTERNAL = "untrusted_external"
    CUSTOM = "custom"


@dataclass
class TaintedValue:
    """A value annotated with taint labels and provenance chain."""

    value: Any
    labels: set[TaintLabel]
    source_id: str
    provenance: list[str] = field(default_factory=list)
    timestamp: float = field(default_factory=time.time)
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def is_tainted(self) -> bool:
        return len(self.labels) > 0

    def add_label(self, label: TaintLabel) -> None:
        self.labels.add(label)

    def clear_label(self, label: TaintLabel, *, sanitizer: str = "unknown") -> None:
        """Remove a taint label — requires explicit sanitizer justification."""
        self.labels.discard(label)
        self.provenance.append(f"cleared:{label.value}:by:{sanitizer}")
        logger.info("taint label cleared", label=label.value, sanitizer=sanitizer, source_id=self.source_id)


class TaintTracker:
    """Session-scoped taint state across MCP tool calls.

    Tracks which values are tainted, propagates taint through tool
    call chains, and provides query APIs for the policy engine.
    """

    def __init__(self) -> None:
        self._tainted: dict[str, TaintedValue] = {}
        self._sanitizers: set[str] = set()

    def mark(
        self,
        data: Any,
        label: TaintLabel,
        *,
        source_id: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> TaintedValue:
        """Mark a value as tainted with the given label."""
        sid = source_id or generate_request_id()
        tv = TaintedValue(
            value=data,
            labels={label},
            source_id=sid,
            provenance=[f"marked:{label.value}"],
            metadata=metadata or {},
        )
        self._tainted[sid] = tv
        logger.debug("data marked as tainted", label=label.value, source_id=sid)
        return tv

    def get(self, source_id: str) -> TaintedValue | None:
        return self._tainted.get(source_id)

    def get_all_tainted(self) -> list[TaintedValue]:
        return [tv for tv in self._tainted.values() if tv.is_tainted]

    def get_by_label(self, label: TaintLabel) -> list[TaintedValue]:
        return [tv for tv in self._tainted.values() if label in tv.labels]

    def clear(self, source_id: str, label: TaintLabel, *, sanitizer: str) -> None:
        """Clear a specific taint label with audit trail."""
        tv = self._tainted.get(source_id)
        if tv:
            tv.clear_label(label, sanitizer=sanitizer)
            self._sanitizers.add(sanitizer)

    def register_sanitizer(self, name: str) -> None:
        """Register a known sanitizer for allowlist checking."""
        self._sanitizers.add(name)

    def is_known_sanitizer(self, name: str) -> bool:
        return name in self._sanitizers

    @property
    def active_taint_count(self) -> int:
        return sum(1 for tv in self._tainted.values() if tv.is_tainted)

    def summary(self) -> dict[str, Any]:
        """Return a summary of current taint state."""
        by_label: dict[str, int] = {}
        for tv in self._tainted.values():
            for label in tv.labels:
                by_label[label.value] = by_label.get(label.value, 0) + 1
        return {
            "total_tracked": len(self._tainted),
            "active_tainted": self.active_taint_count,
            "by_label": by_label,
            "sanitizers": sorted(self._sanitizers),
        }

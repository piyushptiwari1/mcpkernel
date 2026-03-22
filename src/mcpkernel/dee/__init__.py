"""Deterministic Execution Envelope — provable replay + drift detection."""

from mcpkernel.dee.drift import DriftCategory, detect_drift
from mcpkernel.dee.envelope import ExecutionTrace, wrap_execution
from mcpkernel.dee.replay import replay, validate_replay_integrity
from mcpkernel.dee.trace_store import TraceStore

__all__ = [
    "DriftCategory",
    "ExecutionTrace",
    "TraceStore",
    "detect_drift",
    "replay",
    "validate_replay_integrity",
    "wrap_execution",
]

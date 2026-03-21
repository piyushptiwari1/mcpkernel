"""Deterministic Execution Envelope — provable replay + drift detection."""

from mcpguard.dee.drift import DriftCategory, detect_drift
from mcpguard.dee.envelope import ExecutionTrace, wrap_execution
from mcpguard.dee.replay import replay, validate_replay_integrity
from mcpguard.dee.trace_store import TraceStore

__all__ = [
    "DriftCategory",
    "ExecutionTrace",
    "TraceStore",
    "detect_drift",
    "replay",
    "validate_replay_integrity",
    "wrap_execution",
]

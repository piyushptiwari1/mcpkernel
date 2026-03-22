"""Non-determinism drift detection and categorization."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum, auto
from typing import TYPE_CHECKING, Any

from mcpkernel.dee.replay import replay
from mcpkernel.utils import DriftDetected, get_logger

if TYPE_CHECKING:
    from mcpkernel.dee.envelope import ExecutionTrace
    from mcpkernel.dee.trace_store import TraceStore

logger = get_logger(__name__)


class DriftCategory(Enum):
    """Classification of non-determinism causes."""

    NONE = auto()
    RANDOM_SEED = auto()
    CLOCK_DEPENDENCY = auto()
    NETWORK_CALL = auto()
    FILESYSTEM_CHANGE = auto()
    ENVIRONMENT_CHANGE = auto()
    UNKNOWN = auto()


@dataclass
class DriftReport:
    """Detailed drift analysis results."""

    original_trace_id: str
    replay_trace_id: str
    category: DriftCategory
    original_output_hash: str
    replay_output_hash: str
    details: dict[str, Any]


async def detect_drift(
    trace_id: str,
    store: TraceStore,
    execute_fn: Any,
    *,
    num_replays: int = 3,
) -> DriftReport:
    """Replay a trace multiple times and categorize any drift.

    Strategy:
    - If all replays produce the same hash but differ from original → ENVIRONMENT_CHANGE
    - If replays differ from each other → RANDOM_SEED or CLOCK_DEPENDENCY
    - If all match → NONE
    """
    original = await store.get(trace_id)
    if original is None:
        raise DriftDetected(f"Trace not found: {trace_id}")

    replay_hashes: list[str] = []
    last_replay: ExecutionTrace | None = None

    for _i in range(num_replays):
        new_trace = await replay(trace_id, store, execute_fn)
        replay_hashes.append(new_trace.output_hash)
        last_replay = new_trace

    assert last_replay is not None

    original_hash = original["output_hash"]
    all_match_original = all(h == original_hash for h in replay_hashes)
    replays_consistent = len(set(replay_hashes)) == 1

    if all_match_original:
        category = DriftCategory.NONE
    elif replays_consistent and replay_hashes[0] != original_hash:
        # Replays agree with each other but not with original — environment changed
        category = DriftCategory.ENVIRONMENT_CHANGE
    elif not replays_consistent:
        # Replays disagree — non-deterministic code
        category = _classify_nondeterminism(original, replay_hashes)
    else:
        category = DriftCategory.UNKNOWN

    report = DriftReport(
        original_trace_id=trace_id,
        replay_trace_id=last_replay.trace_id,
        category=category,
        original_output_hash=original_hash,
        replay_output_hash=last_replay.output_hash,
        details={
            "num_replays": num_replays,
            "replay_hashes": replay_hashes,
            "replays_consistent": replays_consistent,
            "all_match_original": all_match_original,
        },
    )

    logger.info(
        "drift detection complete",
        trace_id=trace_id,
        category=category.name,
        match=all_match_original,
    )
    return report


def _classify_nondeterminism(
    original: dict[str, Any],
    replay_hashes: list[str],
) -> DriftCategory:
    """Heuristic classification of non-determinism cause.

    Examines the original result for common patterns.
    """
    import json

    result_json = original.get("result_json", "{}")
    result_text = json.dumps(result_json).lower()

    if any(kw in result_text for kw in ("random", "uuid", "shuffle")):
        return DriftCategory.RANDOM_SEED
    if any(kw in result_text for kw in ("time", "datetime", "timestamp", "now")):
        return DriftCategory.CLOCK_DEPENDENCY
    if any(kw in result_text for kw in ("http", "request", "fetch", "curl")):
        return DriftCategory.NETWORK_CALL
    if any(kw in result_text for kw in ("file", "path", "read", "write")):
        return DriftCategory.FILESYSTEM_CHANGE

    return DriftCategory.UNKNOWN

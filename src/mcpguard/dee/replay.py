"""Deterministic replay engine — re-execute and compare hashes."""

from __future__ import annotations

import json
from typing import Any, Callable, Awaitable

from mcpguard.dee.envelope import ExecutionTrace, wrap_execution
from mcpguard.dee.trace_store import TraceStore
from mcpguard.proxy.interceptor import MCPToolCall
from mcpguard.utils import ReplayError, get_logger

logger = get_logger(__name__)


async def replay(
    trace_id: str,
    store: TraceStore,
    execute_fn: Callable[..., Awaitable[Any]],
) -> ExecutionTrace:
    """Replay a previously recorded execution and return the new trace.

    Steps:
      1. Load the original trace from the store
      2. Reconstruct the MCPToolCall from stored data
      3. Re-execute via *execute_fn* inside wrap_execution
      4. Return the new trace (caller should compare hashes)
    """
    record = await store.get(trace_id)
    if record is None:
        raise ReplayError(f"Trace not found: {trace_id}")

    # Reconstruct the original tool call
    result_data = json.loads(record["result_json"])
    call = MCPToolCall(
        request_id=f"replay-{trace_id}",
        tool_name=record["tool_name"],
        arguments=json.loads(record.get("metadata_json", "{}")).get("arguments", {}),
        raw_jsonrpc={
            "jsonrpc": "2.0",
            "id": f"replay-{trace_id}",
            "method": "tools/call",
            "params": {
                "name": record["tool_name"],
                "arguments": json.loads(record.get("metadata_json", "{}")).get("arguments", {}),
            },
        },
    )

    new_trace = await wrap_execution(
        call,
        execute_fn,
        agent_id=record["agent_id"],
        env_snapshot_hash=record["env_snapshot_hash"],
        sign=False,  # Don't sign replays by default
    )

    logger.info(
        "replay complete",
        original_trace_id=trace_id,
        new_trace_id=new_trace.trace_id,
        original_output_hash=record["output_hash"],
        new_output_hash=new_trace.output_hash,
        match=record["output_hash"] == new_trace.output_hash,
    )
    return new_trace


async def validate_replay_integrity(
    original_trace_id: str,
    replay_trace: ExecutionTrace,
    store: TraceStore,
) -> bool:
    """Compare a replayed trace against the original — True if hashes match."""
    record = await store.get(original_trace_id)
    if record is None:
        raise ReplayError(f"Original trace not found: {original_trace_id}")

    return record["output_hash"] == replay_trace.output_hash

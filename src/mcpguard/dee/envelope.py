"""Core DEE wrapper — snapshot → hash → execute → hash → sign → commit."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from mcpguard.utils import generate_trace_id, get_logger, sha256_json

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

    from mcpguard.proxy.interceptor import ExecutionResult, MCPToolCall

logger = get_logger(__name__)


@dataclass
class ExecutionTrace:
    """Immutable record of a single tool-call execution."""

    trace_id: str
    tool_name: str
    agent_id: str
    input_hash: str
    output_hash: str
    env_snapshot_hash: str
    timestamp: float
    duration_seconds: float
    result: ExecutionResult
    sigstore_bundle: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


async def wrap_execution(
    call: MCPToolCall,
    execute_fn: Callable[..., Awaitable[ExecutionResult]],
    *,
    agent_id: str = "default",
    env_snapshot_hash: str = "",
    sign: bool = True,
) -> ExecutionTrace:
    """Run a tool call inside a deterministic envelope.

    Steps:
      1. Hash the inputs (tool name + arguments)
      2. Optionally capture environment snapshot hash
      3. Execute the tool via *execute_fn*
      4. Hash the outputs
      5. Sign the trace with Sigstore (if *sign* is True)
      6. Return the immutable ``ExecutionTrace``
    """
    trace_id = generate_trace_id()
    ts = time.time()

    # 1. Input hash
    input_data = {"tool": call.tool_name, "arguments": call.arguments}
    input_hash = sha256_json(input_data)

    # 2. Execute
    start = time.perf_counter()
    result = await execute_fn(call)
    duration = time.perf_counter() - start

    # 3. Output hash
    output_data = {
        "content": result.content,
        "is_error": result.is_error,
        "structured_content": result.structured_content,
    }
    output_hash = sha256_json(output_data)

    # 4. Sign (optional)
    bundle: str | None = None
    if sign:
        bundle = await _sign_trace(trace_id, input_hash, output_hash, env_snapshot_hash)

    trace = ExecutionTrace(
        trace_id=trace_id,
        tool_name=call.tool_name,
        agent_id=agent_id,
        input_hash=input_hash,
        output_hash=output_hash,
        env_snapshot_hash=env_snapshot_hash,
        timestamp=ts,
        duration_seconds=duration,
        result=result,
        sigstore_bundle=bundle,
    )

    logger.info(
        "dee.wrap_execution complete",
        trace_id=trace_id,
        tool=call.tool_name,
        input_hash=input_hash[:16],
        output_hash=output_hash[:16],
        duration=f"{duration:.3f}s",
    )
    return trace


async def _sign_trace(
    trace_id: str,
    input_hash: str,
    output_hash: str,
    env_hash: str,
) -> str | None:
    """Sign the trace payload with Sigstore.

    Returns the base64-encoded Sigstore bundle, or ``None`` on failure.
    """
    payload = f"{trace_id}:{input_hash}:{output_hash}:{env_hash}"
    try:
        from sigstore.sign import SigningContext

        ctx = SigningContext.production()
        with ctx.signer() as signer:
            result = signer.sign_artifact(payload.encode())
            # Serialize bundle to JSON string
            bundle_json: str = result.bundle.to_json()
            return bundle_json
    except ImportError:
        logger.debug("sigstore not installed — trace signing disabled")
        return None
    except Exception:
        logger.warning("sigstore signing failed", trace_id=trace_id, exc_info=True)
        return None

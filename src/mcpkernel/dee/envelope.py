"""Core DEE wrapper — snapshot → hash → execute → hash → sign → commit."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from mcpkernel.utils import generate_trace_id, get_logger, sha256_json

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

    from mcpkernel.proxy.interceptor import ExecutionResult, MCPToolCall

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
        metadata={
            "arguments": call.arguments,
            "correlation_id": call.correlation_id,
        },
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

    Signing flow
    ------------
    1. If ``SIGSTORE_ID_TOKEN`` is present in the environment (set by CI
       providers like GitHub Actions, GitLab, Buildkite), use it directly
       as the workload-identity OIDC token. This is the production path.
    2. Otherwise fall back to Sigstore's default identity discovery
       (interactive OAuth), which only works in a TTY-attached session.

    When ``MCPKERNEL_DEE__REQUIRE_SIGN=true`` is set, this function raises
    rather than silently degrading — used for production deployments that
    must never emit unsigned envelopes.

    Returns the JSON-serialized Sigstore bundle, or ``None`` on failure
    (when not required).
    """
    import os

    payload = f"{trace_id}:{input_hash}:{output_hash}:{env_hash}"
    require_sign = os.environ.get("MCPKERNEL_DEE__REQUIRE_SIGN", "").lower() in ("1", "true", "yes")
    id_token_str = os.environ.get("SIGSTORE_ID_TOKEN")

    try:
        from sigstore.sign import SigningContext

        ctx = SigningContext.production()
        identity: object | None = None
        if id_token_str:
            try:
                from sigstore.oidc import IdentityToken

                identity = IdentityToken(id_token_str)
            except Exception:  # pragma: no cover - sigstore API drift
                logger.warning("failed to parse SIGSTORE_ID_TOKEN, falling back to default identity")
                identity = None

        with ctx.signer(identity_token=identity) if identity else ctx.signer() as signer:
            result = signer.sign_artifact(payload.encode())
            bundle_json: str = result.bundle.to_json()
            # C.4: assert Sigstore Bundle v0.3 format (MCP 2025-11-25 /
            # sigstore-python >=3.0). Bundles advertise their schema via
            # the ``mediaType`` field — anything else is a downgrade and
            # must be rejected when REQUIRE_SIGN is set.
            try:
                import json as _json

                media_type = _json.loads(bundle_json).get("mediaType", "")
            except Exception:
                media_type = ""
            if "bundle.v0.3" not in media_type:
                if require_sign:
                    msg = f"Sigstore bundle is not v0.3 (got mediaType={media_type!r}); refusing per REQUIRE_SIGN."
                    raise RuntimeError(msg)
                logger.warning("sigstore bundle is not v0.3", media_type=media_type, trace_id=trace_id)
            return bundle_json
    except ImportError as exc:
        if require_sign:
            msg = "MCPKERNEL_DEE__REQUIRE_SIGN=true but the 'sigstore' package is not installed"
            raise RuntimeError(msg) from exc
        logger.debug("sigstore not installed — trace signing disabled")
        return None
    except Exception:
        if require_sign:
            logger.error("sigstore signing failed and REQUIRE_SIGN is set", trace_id=trace_id, exc_info=True)
            raise
        logger.warning("sigstore signing failed", trace_id=trace_id, exc_info=True)
        return None

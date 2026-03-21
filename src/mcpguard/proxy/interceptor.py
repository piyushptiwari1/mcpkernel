"""Proxy interceptor — Kong-inspired phase-based plugin pipeline.

Every MCP ``tools/call`` and A2A message flows through this pipeline:
  pre_execution → execution → post_execution → log
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any

from mcpguard.utils import generate_request_id, get_logger

logger = get_logger(__name__)


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------
class HookPhase(Enum):
    PRE_EXECUTION = auto()
    POST_EXECUTION = auto()
    LOG = auto()


@dataclass(frozen=True)
class MCPToolCall:
    """Parsed representation of an MCP ``tools/call`` JSON-RPC request."""

    request_id: str | int
    tool_name: str
    arguments: dict[str, Any]
    raw_jsonrpc: dict[str, Any]
    correlation_id: str = field(default_factory=generate_request_id)
    timestamp: float = field(default_factory=time.time)


@dataclass
class ExecutionResult:
    """Result of a tool-call execution."""

    content: list[dict[str, Any]]
    is_error: bool = False
    structured_content: dict[str, Any] | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    duration_seconds: float = 0.0
    trace_id: str | None = None


@dataclass
class InterceptorContext:
    """Mutable context threaded through the plugin pipeline."""

    call: MCPToolCall
    result: ExecutionResult | None = None
    policy_decision: str = "allow"
    taint_labels: set[str] = field(default_factory=set)
    extra: dict[str, Any] = field(default_factory=dict)
    aborted: bool = False
    abort_reason: str = ""


# ---------------------------------------------------------------------------
# Plugin hook interface
# ---------------------------------------------------------------------------
class PluginHook:
    """Base class for interceptor plugin hooks.

    Plugins declare a *priority* (higher = runs first) and implement one or
    more phase methods.  Inspired by Kong's plugin handler lifecycle.
    """

    PRIORITY: int = 100
    NAME: str = "base"

    async def pre_execution(self, ctx: InterceptorContext) -> None:
        """Runs before the tool call is forwarded to the sandbox."""

    async def post_execution(self, ctx: InterceptorContext) -> None:
        """Runs after the sandbox returns a result."""

    async def log(self, ctx: InterceptorContext) -> None:
        """Runs after the response has been sent (fire-and-forget logging)."""


# ---------------------------------------------------------------------------
# Pipeline
# ---------------------------------------------------------------------------
class InterceptorPipeline:
    """Ordered pipeline of plugin hooks executed for every tool call."""

    def __init__(self) -> None:
        self._hooks: list[PluginHook] = []

    def register(self, hook: PluginHook) -> None:
        """Add a hook and re-sort by descending priority."""
        self._hooks.append(hook)
        self._hooks.sort(key=lambda h: h.PRIORITY, reverse=True)

    def unregister(self, name: str) -> None:
        """Remove hook(s) matching *name*."""
        self._hooks = [h for h in self._hooks if name != h.NAME]

    @property
    def hooks(self) -> list[PluginHook]:
        return list(self._hooks)

    async def run_pre_execution(self, ctx: InterceptorContext) -> None:
        for hook in self._hooks:
            if ctx.aborted:
                break
            try:
                await hook.pre_execution(ctx)
            except Exception:
                logger.exception("pre_execution hook failed", hook=hook.NAME)
                raise

    async def run_post_execution(self, ctx: InterceptorContext) -> None:
        for hook in self._hooks:
            try:
                await hook.post_execution(ctx)
            except Exception:
                logger.exception("post_execution hook failed", hook=hook.NAME)
                raise

    async def run_log(self, ctx: InterceptorContext) -> None:
        for hook in self._hooks:
            try:
                await hook.log(ctx)
            except Exception:
                logger.warning("log hook failed (non-fatal)", hook=hook.NAME, exc_info=True)


# ---------------------------------------------------------------------------
# JSON-RPC parsing helpers
# ---------------------------------------------------------------------------
def parse_mcp_tool_call(raw: dict[str, Any]) -> MCPToolCall | None:
    """Try to parse a JSON-RPC dict as an MCP ``tools/call``.

    Returns ``None`` if the message is not a tool call.
    """
    if raw.get("method") != "tools/call":
        return None
    params = raw.get("params", {})
    return MCPToolCall(
        request_id=raw.get("id", 0),
        tool_name=params.get("name", ""),
        arguments=params.get("arguments", {}),
        raw_jsonrpc=raw,
    )


def build_jsonrpc_response(request_id: str | int, result: ExecutionResult) -> dict[str, Any]:
    """Build a JSON-RPC 2.0 response from an :class:`ExecutionResult`."""
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "result": {
            "content": result.content,
            "isError": result.is_error,
            **({"structuredContent": result.structured_content} if result.structured_content else {}),
            **({"_meta": result.metadata} if result.metadata else {}),
        },
    }


def build_jsonrpc_error(request_id: str | int, code: int, message: str) -> dict[str, Any]:
    """Build a JSON-RPC 2.0 error response."""
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "error": {
            "code": code,
            "message": message,
        },
    }

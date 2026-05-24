"""OpenTelemetry GenAI + MCP semantic conventions.

This module pins the canonical attribute names that MCPKernel emits on spans
and metrics so that any observability backend (Langfuse, Datadog, Grafana
Tempo, Honeycomb, Phoenix, New Relic) can consume them without per-vendor
adapters.

Sources
-------
* GenAI semantic conventions:
  https://opentelemetry.io/docs/specs/semconv/gen-ai/
* MCP semantic conventions:
  https://opentelemetry.io/docs/specs/semconv/gen-ai/mcp/ (experimental)
* The conventions are experimental — enable them with::

      OTEL_SEMCONV_STABILITY_OPT_IN=gen_ai_latest_experimental

The keys are kept as module-level constants (not enums) so they can be used
directly as kwargs to ``span.set_attribute`` / ``span.set_attributes``
without ``.value`` access — matching the upstream OTel Python SDK idioms.
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# GenAI core attributes (stable namespace: gen_ai.*)
# ---------------------------------------------------------------------------

GEN_AI_SYSTEM = "gen_ai.system"
"""Identifier for the GenAI system. For MCPKernel this is the upstream LLM
or agent system label, e.g. ``"anthropic"``, ``"openai"``, ``"mcp"``."""

GEN_AI_OPERATION_NAME = "gen_ai.operation.name"
"""Logical operation name. Standardised values include ``chat``, ``embeddings``,
``tool.execution``, ``agent.invocation``."""

GEN_AI_AGENT_ID = "gen_ai.agent.id"
GEN_AI_AGENT_NAME = "gen_ai.agent.name"
GEN_AI_AGENT_DESCRIPTION = "gen_ai.agent.description"

GEN_AI_REQUEST_MODEL = "gen_ai.request.model"
GEN_AI_RESPONSE_MODEL = "gen_ai.response.model"

GEN_AI_USAGE_INPUT_TOKENS = "gen_ai.usage.input_tokens"
GEN_AI_USAGE_OUTPUT_TOKENS = "gen_ai.usage.output_tokens"

# ---------------------------------------------------------------------------
# GenAI tool attributes
# ---------------------------------------------------------------------------

GEN_AI_TOOL_NAME = "gen_ai.tool.name"
GEN_AI_TOOL_DESCRIPTION = "gen_ai.tool.description"
GEN_AI_TOOL_CALL_ID = "gen_ai.tool.call.id"
GEN_AI_TOOL_TYPE = "gen_ai.tool.type"  # e.g. "function", "mcp", "code_interpreter"

# ---------------------------------------------------------------------------
# MCP-specific attributes (experimental)
# ---------------------------------------------------------------------------

MCP_METHOD_NAME = "mcp.method.name"
"""JSON-RPC method, e.g. ``tools/call``, ``tools/list``, ``resources/read``."""

MCP_REQUEST_ID = "mcp.request.id"
MCP_SESSION_ID = "mcp.session.id"
MCP_TRANSPORT = "mcp.transport"  # "stdio" | "sse" | "streamable-http"
MCP_SERVER_NAME = "mcp.server.name"
MCP_SERVER_VERSION = "mcp.server.version"
MCP_PROTOCOL_VERSION = "mcp.protocol.version"  # e.g. "2025-11-25"

# ---------------------------------------------------------------------------
# MCPKernel-specific extension attributes (namespaced to avoid collision)
# ---------------------------------------------------------------------------

MCPKERNEL_POLICY_DECISION = "mcpkernel.policy.decision"  # "allow" | "deny" | "sandbox" | "audit"
MCPKERNEL_POLICY_RULE_ID = "mcpkernel.policy.rule.id"
MCPKERNEL_TAINT_LABELS = "mcpkernel.taint.labels"  # comma-joined label list
MCPKERNEL_TAINT_SEVERITY = "mcpkernel.taint.severity"
MCPKERNEL_SANDBOX_BACKEND = "mcpkernel.sandbox.backend"  # "docker" | "firecracker" | ...
MCPKERNEL_DEE_TRACE_ID = "mcpkernel.dee.trace.id"
MCPKERNEL_DEE_REPLAY_MATCH = "mcpkernel.dee.replay.match"  # bool

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def gen_ai_tool_attributes(
    *,
    tool_name: str,
    tool_call_id: str | None = None,
    tool_type: str = "mcp",
    description: str | None = None,
) -> dict[str, str]:
    """Build a dict of GenAI tool attributes suitable for ``span.set_attributes``.

    Returns only keys whose values are non-empty so we don't pollute spans
    with empty strings.
    """
    attrs: dict[str, str] = {
        GEN_AI_TOOL_NAME: tool_name,
        GEN_AI_TOOL_TYPE: tool_type,
        GEN_AI_OPERATION_NAME: "tool.execution",
    }
    if tool_call_id:
        attrs[GEN_AI_TOOL_CALL_ID] = tool_call_id
    if description:
        attrs[GEN_AI_TOOL_DESCRIPTION] = description
    return attrs


def mcp_request_attributes(
    *,
    method: str,
    request_id: str | None = None,
    session_id: str | None = None,
    transport: str | None = None,
    protocol_version: str | None = None,
    server_name: str | None = None,
) -> dict[str, str]:
    """Build a dict of MCP request attributes."""
    attrs: dict[str, str] = {MCP_METHOD_NAME: method}
    if request_id:
        attrs[MCP_REQUEST_ID] = request_id
    if session_id:
        attrs[MCP_SESSION_ID] = session_id
    if transport:
        attrs[MCP_TRANSPORT] = transport
    if protocol_version:
        attrs[MCP_PROTOCOL_VERSION] = protocol_version
    if server_name:
        attrs[MCP_SERVER_NAME] = server_name
    return attrs


__all__ = [
    "GEN_AI_AGENT_DESCRIPTION",
    "GEN_AI_AGENT_ID",
    "GEN_AI_AGENT_NAME",
    "GEN_AI_OPERATION_NAME",
    "GEN_AI_REQUEST_MODEL",
    "GEN_AI_RESPONSE_MODEL",
    "GEN_AI_SYSTEM",
    "GEN_AI_TOOL_CALL_ID",
    "GEN_AI_TOOL_DESCRIPTION",
    "GEN_AI_TOOL_NAME",
    "GEN_AI_TOOL_TYPE",
    "GEN_AI_USAGE_INPUT_TOKENS",
    "GEN_AI_USAGE_OUTPUT_TOKENS",
    "MCPKERNEL_DEE_REPLAY_MATCH",
    "MCPKERNEL_DEE_TRACE_ID",
    "MCPKERNEL_POLICY_DECISION",
    "MCPKERNEL_POLICY_RULE_ID",
    "MCPKERNEL_SANDBOX_BACKEND",
    "MCPKERNEL_TAINT_LABELS",
    "MCPKERNEL_TAINT_SEVERITY",
    "MCP_METHOD_NAME",
    "MCP_PROTOCOL_VERSION",
    "MCP_REQUEST_ID",
    "MCP_SERVER_NAME",
    "MCP_SERVER_VERSION",
    "MCP_SESSION_ID",
    "MCP_TRANSPORT",
    "gen_ai_tool_attributes",
    "mcp_request_attributes",
]

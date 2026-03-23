"""Proxy hook that validates tool calls against an agent manifest definition.

When active, this hook checks every MCP tool call against the agent's declared
tool schemas and annotations (read-only, requires_confirmation).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from mcpkernel.agent_manifest.tool_validator import ToolSchemaValidator
from mcpkernel.proxy.interceptor import InterceptorContext, PluginHook
from mcpkernel.utils import get_logger

if TYPE_CHECKING:
    from mcpkernel.agent_manifest.loader import AgentManifestDefinition

logger = get_logger(__name__)


class AgentManifestHook(PluginHook):
    """Pre-execution hook: validate tool calls against agent manifest tool schemas."""

    PRIORITY = 950  # Runs after policy (1000) but before taint (900)
    NAME = "agent_manifest"

    def __init__(self, definition: AgentManifestDefinition) -> None:
        self._definition = definition
        self._validator = ToolSchemaValidator(definition)
        self._allowed_tools: set[str] = set()
        for tool in definition.tools_list:
            self._allowed_tools.add(tool)
            self._allowed_tools.add(tool.replace("-", "_"))

    async def pre_execution(self, ctx: InterceptorContext) -> None:
        tool_name = ctx.call.tool_name

        # Check tool is declared in agent.yaml
        if self._allowed_tools and tool_name not in self._allowed_tools:
            ctx.aborted = True
            ctx.abort_reason = (
                f"agent_manifest: tool '{tool_name}' not declared in agent.yaml for agent '{self._definition.name}'"
            )
            logger.warning(
                "agent_manifest hook blocked undeclared tool",
                tool=tool_name,
                agent=self._definition.name,
            )
            return

        # Validate arguments against tool schema
        if self._validator.has_schema(tool_name):
            errors = self._validator.validate(tool_name, ctx.call.arguments)
            if errors:
                ctx.aborted = True
                ctx.abort_reason = f"agent_manifest: schema validation failed for '{tool_name}': " + "; ".join(errors)
                logger.warning(
                    "agent_manifest hook schema validation failed",
                    tool=tool_name,
                    errors=errors,
                )
                return

            # Add annotations as metadata
            if self._validator.requires_confirmation(tool_name):
                ctx.extra["manifest_requires_confirmation"] = True
            if self._validator.is_read_only(tool_name):
                ctx.extra["manifest_read_only"] = True

        ctx.extra["manifest_agent"] = self._definition.name
        ctx.extra["manifest_version"] = self._definition.version

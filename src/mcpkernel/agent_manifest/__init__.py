"""Agent manifest integration — load agent definitions and enforce them at runtime.

Inspired by the open gitagent specification (MIT-licensed). MCPKernel reads
``agent.yaml`` manifests and converts compliance declarations into runtime
policy rules, tool-schema validation, and proxy hooks.
"""

from __future__ import annotations

__all__ = [
    "AgentManifestDefinition",
    "ToolSchemaValidator",
    "load_agent_manifest",
    "manifest_to_policy_rules",
]

from mcpkernel.agent_manifest.loader import AgentManifestDefinition, load_agent_manifest
from mcpkernel.agent_manifest.policy_bridge import manifest_to_policy_rules
from mcpkernel.agent_manifest.tool_validator import ToolSchemaValidator

"""Validate MCP tool calls against agent manifest tool schemas.

When an agent manifest declares ``tools/*.yaml`` with ``input_schema``, this
validator checks that incoming MCP tool-call arguments conform to the declared
JSON Schema (type, required fields, enum constraints).
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from mcpkernel.utils import get_logger

if TYPE_CHECKING:
    from mcpkernel.agent_manifest.loader import AgentManifestDefinition, ToolSchema

logger = get_logger(__name__)


class ToolSchemaValidator:
    """Validate MCP tool-call arguments against agent manifest tool schemas.

    Parameters
    ----------
    definition:
        The parsed agent manifest definition containing tool schemas.
    """

    def __init__(self, definition: AgentManifestDefinition) -> None:
        self._schemas: dict[str, ToolSchema] = {}
        for schema in definition.tool_schemas:
            self._schemas[schema.name] = schema
            # Also index by snake_case variant
            snake_name = schema.name.replace("-", "_")
            if snake_name != schema.name:
                self._schemas[snake_name] = schema

    @property
    def known_tools(self) -> list[str]:
        """Return list of tool names with registered schemas."""
        return list({s.name for s in self._schemas.values()})

    def has_schema(self, tool_name: str) -> bool:
        """Check if a tool schema exists for the given name."""
        return tool_name in self._schemas

    def validate(self, tool_name: str, arguments: dict[str, Any]) -> list[str]:
        """Validate tool-call arguments against the declared schema.

        Parameters
        ----------
        tool_name:
            The MCP tool name from the ``tools/call`` request.
        arguments:
            The arguments dict from the tool call.

        Returns
        -------
        list[str]
            A list of validation error messages. Empty if valid.
        """
        schema = self._schemas.get(tool_name)
        if schema is None:
            return [f"Tool '{tool_name}' not declared in agent.yaml"]

        input_schema = schema.input_schema
        if not input_schema:
            return []  # No schema = anything goes

        errors: list[str] = []

        # Check required fields
        required = input_schema.get("required", [])
        for field_name in required:
            if field_name not in arguments:
                errors.append(f"Missing required field: {field_name}")

        # Check property types
        properties = input_schema.get("properties", {})
        for arg_name, arg_value in arguments.items():
            if arg_name not in properties:
                continue  # Extra fields are OK (open schema)

            prop_def = properties[arg_name]
            type_errors = _check_type(arg_name, arg_value, prop_def)
            errors.extend(type_errors)

        if errors:
            logger.warning(
                "tool schema validation failed",
                tool=tool_name,
                error_count=len(errors),
                errors=errors,
            )

        return errors

    def is_read_only(self, tool_name: str) -> bool:
        """Check if a tool is annotated as read-only."""
        schema = self._schemas.get(tool_name)
        if schema is None:
            return False
        return bool(schema.annotations.get("read_only", False))

    def requires_confirmation(self, tool_name: str) -> bool:
        """Check if a tool requires user confirmation before execution."""
        schema = self._schemas.get(tool_name)
        if schema is None:
            return False
        return bool(schema.annotations.get("requires_confirmation", False))


def _check_type(field_name: str, value: Any, prop_def: dict[str, Any]) -> list[str]:
    """Check a single value against its declared JSON Schema type."""
    errors: list[str] = []
    expected_type = prop_def.get("type")

    if expected_type is None:
        return errors

    type_map: dict[str, type | tuple[type, ...]] = {
        "string": str,
        "integer": int,
        "number": (int, float),
        "boolean": bool,
        "array": list,
        "object": dict,
    }

    python_type = type_map.get(expected_type)
    if python_type and not isinstance(value, python_type):
        errors.append(f"Field '{field_name}': expected {expected_type}, got {type(value).__name__}")

    # Enum check
    if "enum" in prop_def and value not in prop_def["enum"]:
        errors.append(f"Field '{field_name}': value '{value}' not in allowed values {prop_def['enum']}")

    return errors

"""Dangerous sink definitions — block tainted data from reaching unsafe operations."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from mcpkernel.taint.tracker import TaintedValue, TaintLabel
from mcpkernel.utils import TaintViolation, get_logger

logger = get_logger(__name__)


class SinkAction(StrEnum):
    """Action to take when tainted data reaches a sink."""

    BLOCK = "block"
    WARN = "warn"
    LOG = "log"
    ALLOW = "allow"


@dataclass
class SinkDefinition:
    """A dangerous operation that tainted data should not reach."""

    name: str
    description: str
    blocked_labels: set[TaintLabel]
    action: SinkAction = SinkAction.BLOCK


# Built-in sink definitions
BUILTIN_SINKS: dict[str, SinkDefinition] = {
    "http_post": SinkDefinition(
        name="http_post",
        description="Outbound HTTP POST request",
        blocked_labels={TaintLabel.SECRET, TaintLabel.PII},
    ),
    "file_write": SinkDefinition(
        name="file_write",
        description="Write to file system",
        blocked_labels={TaintLabel.SECRET},
    ),
    "db_query": SinkDefinition(
        name="db_query",
        description="Database query execution",
        blocked_labels={TaintLabel.SECRET, TaintLabel.PII, TaintLabel.USER_INPUT},
    ),
    "shell_exec": SinkDefinition(
        name="shell_exec",
        description="Shell command execution",
        blocked_labels={TaintLabel.SECRET, TaintLabel.USER_INPUT, TaintLabel.UNTRUSTED_EXTERNAL},
    ),
    "eval_exec": SinkDefinition(
        name="eval_exec",
        description="Dynamic code evaluation (eval/exec)",
        blocked_labels={TaintLabel.SECRET, TaintLabel.USER_INPUT, TaintLabel.UNTRUSTED_EXTERNAL, TaintLabel.LLM_OUTPUT},
    ),
    "email_send": SinkDefinition(
        name="email_send",
        description="Outbound email",
        blocked_labels={TaintLabel.SECRET},
    ),
}


def check_sink_operation(
    tainted_values: list[TaintedValue],
    sink_type: str,
    *,
    custom_sinks: dict[str, SinkDefinition] | None = None,
    override_action: SinkAction | None = None,
) -> SinkAction:
    """Check if any tainted values violate sink rules.

    Returns the action to take.  Raises :class:`TaintViolation` if
    action is BLOCK.
    """
    all_sinks = {**BUILTIN_SINKS, **(custom_sinks or {})}
    sink_def = all_sinks.get(sink_type)

    if sink_def is None:
        return SinkAction.ALLOW

    action = override_action or sink_def.action

    for tv in tainted_values:
        violating_labels = tv.labels & sink_def.blocked_labels
        if violating_labels:
            logger.warning(
                "taint sink violation",
                sink=sink_type,
                labels=[lbl.value for lbl in violating_labels],
                source_id=tv.source_id,
                action=action.value,
            )
            if action == SinkAction.BLOCK:
                raise TaintViolation(
                    source_type=", ".join(lbl.value for lbl in violating_labels),
                    sink_type=sink_type,
                    details={
                        "source_id": tv.source_id,
                        "sink_definition": sink_def.name,
                        "blocked_labels": [lbl.value for lbl in violating_labels],
                    },
                )
            return action

    return SinkAction.ALLOW

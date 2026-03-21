"""Cross-tool taint propagation — track taint flow across MCP hops."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from mcpguard.taint.sources import detect_tainted_sources
from mcpguard.taint.tracker import TaintLabel, TaintTracker
from mcpguard.utils import get_logger

logger = get_logger(__name__)


@dataclass
class PropagationEdge:
    """A single taint propagation step between tool calls."""

    from_tool: str
    to_tool: str
    labels: set[TaintLabel]
    field_path: str = ""


class TaintPropagator:
    """Track taint flow across a session of MCP tool calls.

    For each tool call, scans inputs for tainted data, executes, then
    marks outputs if any inputs were tainted (conservative propagation).
    """

    def __init__(self, tracker: TaintTracker) -> None:
        self._tracker = tracker
        self._edges: list[PropagationEdge] = []
        self._call_history: list[str] = []

    def propagate_through_call(
        self,
        tool_name: str,
        input_args: dict[str, Any],
        output_content: list[dict[str, Any]],
    ) -> set[TaintLabel]:
        """Check inputs for taint, propagate to outputs.

        Returns the set of taint labels applied to the output.
        """
        self._call_history.append(tool_name)

        # 1. Detect new taint sources in inputs
        detections = detect_tainted_sources(input_args)
        input_labels: set[TaintLabel] = set()

        for det in detections:
            tv = self._tracker.mark(
                data=det.matched_text,
                label=det.label,
                metadata={"tool": tool_name, "field": det.field_path, "pattern": det.pattern_name},
            )
            input_labels.add(det.label)

        # 2. Check if any previously tracked tainted values appear in inputs
        for tv in self._tracker.get_all_tainted():
            if isinstance(tv.value, str) and _value_in_args(tv.value, input_args):
                input_labels.update(tv.labels)

        # 3. Conservative propagation: if inputs are tainted, mark all outputs
        output_labels: set[TaintLabel] = set()
        if input_labels:
            for content_item in output_content:
                text = content_item.get("text", "")
                if text:
                    out_tv = self._tracker.mark(
                        data=text,
                        label=TaintLabel.LLM_OUTPUT,
                        metadata={"propagated_from": tool_name, "original_labels": [lbl.value for lbl in input_labels]},
                    )
                    out_tv.labels.update(input_labels)
                    output_labels.update(out_tv.labels)

            # Record propagation edge
            prev_tool = self._call_history[-2] if len(self._call_history) >= 2 else "input"
            self._edges.append(
                PropagationEdge(
                    from_tool=prev_tool,
                    to_tool=tool_name,
                    labels=input_labels,
                )
            )

            logger.info(
                "taint propagated through tool call",
                tool=tool_name,
                input_labels=[lbl.value for lbl in input_labels],
                output_labels=[lbl.value for lbl in output_labels],
            )

        return output_labels

    @property
    def edges(self) -> list[PropagationEdge]:
        return list(self._edges)

    @property
    def flow_graph(self) -> dict[str, Any]:
        """Return a serializable representation of the taint flow graph."""
        return {
            "call_history": list(self._call_history),
            "edges": [
                {
                    "from": e.from_tool,
                    "to": e.to_tool,
                    "labels": [lbl.value for lbl in e.labels],
                }
                for e in self._edges
            ],
            "taint_summary": self._tracker.summary(),
        }


def _value_in_args(value: str, args: dict[str, Any]) -> bool:
    """Check if a tainted value string appears anywhere in the arguments."""
    if len(value) < 4:
        return False  # Avoid false positives on short strings

    def _search(obj: Any) -> bool:
        if isinstance(obj, str):
            return value in obj
        if isinstance(obj, dict):
            return any(_search(v) for v in obj.values())
        if isinstance(obj, list):
            return any(_search(item) for item in obj)
        return False

    return _search(args)

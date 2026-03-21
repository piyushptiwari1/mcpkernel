"""Taint flow report generation — Mermaid-compatible flow graphs."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from mcpguard.taint.propagation import TaintPropagator


def generate_taint_report(propagator: TaintPropagator) -> dict[str, Any]:
    """Generate a comprehensive taint report with flow graph.

    Returns a dict containing:
    - ``summary``: aggregate statistics
    - ``flow_graph``: serializable edge list
    - ``mermaid``: Mermaid diagram source
    """
    graph = propagator.flow_graph
    mermaid = _to_mermaid(graph)

    return {
        "summary": graph.get("taint_summary", {}),
        "flow_graph": graph,
        "mermaid": mermaid,
    }


def _to_mermaid(graph: dict[str, Any]) -> str:
    """Convert a taint flow graph to Mermaid diagram syntax."""
    lines = ["graph LR"]

    for edge in graph.get("edges", []):
        from_node = edge["from"].replace(" ", "_")
        to_node = edge["to"].replace(" ", "_")
        labels = ", ".join(edge.get("labels", []))
        lines.append(f"    {from_node} -->|{labels}| {to_node}")

    if len(lines) == 1:
        lines.append("    no_taint[No taint detected]")

    return "\n".join(lines)

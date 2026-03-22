"""eBPF-hybrid taint tracking — source/sink/propagation for agent tool calls."""

from mcpkernel.taint.propagation import TaintPropagator
from mcpkernel.taint.report import generate_taint_report
from mcpkernel.taint.sinks import SinkAction, SinkDefinition, check_sink_operation
from mcpkernel.taint.sources import SourcePattern, detect_tainted_sources
from mcpkernel.taint.static_analysis import StaticTaintReport, static_taint_analysis
from mcpkernel.taint.tracker import TaintedValue, TaintLabel, TaintTracker

__all__ = [
    "SinkAction",
    "SinkDefinition",
    "SourcePattern",
    "StaticTaintReport",
    "TaintLabel",
    "TaintPropagator",
    "TaintTracker",
    "TaintedValue",
    "check_sink_operation",
    "detect_tainted_sources",
    "generate_taint_report",
    "static_taint_analysis",
]

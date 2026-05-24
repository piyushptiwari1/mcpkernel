"""eBPF-hybrid taint tracking — source/sink/propagation for agent tool calls."""

from mcpkernel.taint.flow_analyzer import (
    FlowCategory,
    FlowFinding,
    FlowSeverity,
    ToolFlowProfile,
    ToxicFlowAnalyzer,
    analyze_tool_manifest,
)
from mcpkernel.taint.propagation import TaintPropagator
from mcpkernel.taint.report import generate_taint_report
from mcpkernel.taint.sinks import SinkAction, SinkDefinition, check_sink_operation
from mcpkernel.taint.sources import SourcePattern, detect_tainted_sources
from mcpkernel.taint.static_analysis import StaticTaintReport, static_taint_analysis
from mcpkernel.taint.tracker import TaintedValue, TaintLabel, TaintTracker

__all__ = [
    "FlowCategory",
    "FlowFinding",
    "FlowSeverity",
    "SinkAction",
    "SinkDefinition",
    "SourcePattern",
    "StaticTaintReport",
    "TaintLabel",
    "TaintPropagator",
    "TaintTracker",
    "TaintedValue",
    "ToolFlowProfile",
    "ToxicFlowAnalyzer",
    "analyze_tool_manifest",
    "check_sink_operation",
    "detect_tainted_sources",
    "generate_taint_report",
    "static_taint_analysis",
]

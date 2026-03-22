"""Context minimization — reduce token usage while preserving semantic relevance."""

from mcpkernel.context.dependency_graph import DependencyGraph, build_dependency_graph
from mcpkernel.context.pruning import PruningStrategy, prune_context
from mcpkernel.context.reducer import ContextReducer, ReductionResult

__all__ = [
    "ContextReducer",
    "DependencyGraph",
    "PruningStrategy",
    "ReductionResult",
    "build_dependency_graph",
    "prune_context",
]

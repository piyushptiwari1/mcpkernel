"""Dependency graph extraction — identify which fields depend on others."""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from typing import Any

from mcpguard.utils import get_logger

logger = get_logger(__name__)


@dataclass
class DependencyNode:
    """A node in the context dependency graph."""

    name: str
    node_type: str  # "function", "variable", "import", "class"
    references: set[str] = field(default_factory=set)


@dataclass
class DependencyGraph:
    """DAG of dependencies between context elements."""

    nodes: dict[str, DependencyNode] = field(default_factory=dict)

    def add_node(self, name: str, node_type: str) -> DependencyNode:
        if name not in self.nodes:
            self.nodes[name] = DependencyNode(name=name, node_type=node_type)
        return self.nodes[name]

    def add_edge(self, from_name: str, to_name: str) -> None:
        if from_name in self.nodes:
            self.nodes[from_name].references.add(to_name)

    def reachable_from(self, name: str) -> set[str]:
        """All names transitively reachable from the given node."""
        visited: set[str] = set()
        stack = [name]
        while stack:
            current = stack.pop()
            if current in visited:
                continue
            visited.add(current)
            node = self.nodes.get(current)
            if node:
                stack.extend(node.references - visited)
        return visited

    def to_dict(self) -> dict[str, Any]:
        return {
            name: {
                "type": node.node_type,
                "references": sorted(node.references),
            }
            for name, node in self.nodes.items()
        }


def build_dependency_graph(code: str) -> DependencyGraph:
    """Build a dependency graph from Python source code using AST analysis."""
    graph = DependencyGraph()

    try:
        tree = ast.parse(code)
    except SyntaxError:
        return graph

    # First pass: collect definitions
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            graph.add_node(node.name, "function")
        elif isinstance(node, ast.ClassDef):
            graph.add_node(node.name, "class")
        elif isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    graph.add_node(target.id, "variable")
        elif isinstance(node, ast.Import):
            for alias in node.names:
                name = alias.asname or alias.name
                graph.add_node(name, "import")
        elif isinstance(node, ast.ImportFrom):
            for alias in node.names:
                name = alias.asname or alias.name
                graph.add_node(name, "import")

    # Second pass: collect references
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            _collect_references(node, node.name, graph)
        elif isinstance(node, ast.ClassDef):
            _collect_references(node, node.name, graph)

    return graph


def _collect_references(
    parent_node: ast.AST,
    parent_name: str,
    graph: DependencyGraph,
) -> None:
    """Walk a function/class body and record Name references as edges."""
    for child in ast.walk(parent_node):
        if isinstance(child, ast.Name) and child.id in graph.nodes and child.id != parent_name:
            graph.add_edge(parent_name, child.id)

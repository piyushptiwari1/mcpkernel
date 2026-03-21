"""Tests for mcpguard.context — reducer, dependency graph, pruning."""

from __future__ import annotations

from mcpguard.context.dependency_graph import DependencyGraph, build_dependency_graph
from mcpguard.context.pruning import PruningStrategy, prune_context
from mcpguard.context.reducer import ContextReducer


class TestContextReducer:
    def test_no_reduction_needed(self):
        reducer = ContextReducer(max_tokens=10000)
        context = {"key": "small value"}
        result = reducer.reduce(context)
        assert result.reduction_ratio == 0.0
        assert result.reduced_content == context

    def test_reduction_applied(self):
        reducer = ContextReducer(max_tokens=50, relevance_threshold=0.0)
        context = {f"field_{i}": "x" * 100 for i in range(10)}
        result = reducer.reduce(context)
        assert result.reduced_tokens <= result.original_tokens
        assert len(result.pruned_fields) > 0

    def test_query_term_relevance(self):
        reducer = ContextReducer(max_tokens=100, relevance_threshold=0.0)
        context = {
            "relevant": "python code execution sandbox",
            "irrelevant": "unrelated data about cooking recipes",
        }
        result = reducer.reduce(context, query_terms=["python", "code"])
        assert "relevant" in result.preserved_fields


class TestDependencyGraph:
    def test_empty_graph(self):
        graph = DependencyGraph()
        assert len(graph.nodes) == 0

    def test_add_node(self):
        graph = DependencyGraph()
        node = graph.add_node("func1", "function")
        assert node.name == "func1"

    def test_add_edge(self):
        graph = DependencyGraph()
        graph.add_node("func1", "function")
        graph.add_node("var1", "variable")
        graph.add_edge("func1", "var1")
        assert "var1" in graph.nodes["func1"].references

    def test_reachable(self):
        graph = DependencyGraph()
        graph.add_node("a", "function")
        graph.add_node("b", "function")
        graph.add_node("c", "variable")
        graph.add_edge("a", "b")
        graph.add_edge("b", "c")
        reachable = graph.reachable_from("a")
        assert "c" in reachable

    def test_build_from_code(self):
        code = """
import os

MAX_SIZE = 100

def process(data):
    return data[:MAX_SIZE]

def main():
    result = process("hello")
    print(result)
"""
        graph = build_dependency_graph(code)
        assert "process" in graph.nodes
        assert "main" in graph.nodes
        assert "MAX_SIZE" in graph.nodes


class TestPruning:
    def test_aggressive_pruning(self):
        context = {f"f{i}": "x" * 500 for i in range(20)}
        result = prune_context(context, strategy=PruningStrategy.AGGRESSIVE)
        assert result.reduced_tokens < result.original_tokens

    def test_conservative_pruning(self):
        context = {"small": "data"}
        result = prune_context(context, strategy=PruningStrategy.CONSERVATIVE)
        assert result.reduction_ratio == 0.0  # Small data, no pruning needed

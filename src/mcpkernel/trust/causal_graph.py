"""Causal Trust Graph — directed acyclic graph of tool-call causality.

Each node represents a tool invocation; edges encode data-flow causality.
The graph supports:
  - Forward taint propagation (standard)
  - Retroactive invalidation (novel: back-propagate compromise)
  - Trust score computation via decay + verification events
  - Minimum privilege derivation from observed causal chains
"""

from __future__ import annotations

import math
import time
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from mcpkernel.utils import generate_request_id, get_logger

logger = get_logger(__name__)


class NodeStatus(StrEnum):
    """Trust status of a causal node."""

    TRUSTED = "trusted"
    DEGRADED = "degraded"
    SUSPICIOUS = "suspicious"
    COMPROMISED = "compromised"
    INVALIDATED = "invalidated"


@dataclass
class TrustScore:
    """Mathematical trust score with decay.

    Trust follows: T(t) = T₀ · e^{-λ(t - t₀)} · Π w(vᵢ)

    Where:
      T₀    = initial trust (0.0 to 1.0)
      λ     = decay rate (higher = faster erosion)
      t₀    = time of last verification
      w(vᵢ) = weight of each verification event (0.0 to 1.0)
    """

    initial: float = 1.0
    decay_rate: float = 0.01  # λ — per-second decay
    last_verified_at: float = field(default_factory=time.time)
    verification_weights: list[float] = field(default_factory=list)
    min_threshold: float = 0.3  # below this = SUSPICIOUS
    compromise_threshold: float = 0.1  # below this = COMPROMISED

    def current(self, now: float | None = None) -> float:
        """Compute current trust score with exponential decay."""
        t = now or time.time()
        elapsed = max(0.0, t - self.last_verified_at)
        base = self.initial * math.exp(-self.decay_rate * elapsed)
        weight_product = 1.0
        for w in self.verification_weights:
            weight_product *= max(0.0, min(1.0, w))
        return max(0.0, min(1.0, base * weight_product))

    def status(self, now: float | None = None) -> NodeStatus:
        """Determine trust status from current score."""
        score = self.current(now)
        if score >= 0.7:
            return NodeStatus.TRUSTED
        if score >= self.min_threshold:
            return NodeStatus.DEGRADED
        if score >= self.compromise_threshold:
            return NodeStatus.SUSPICIOUS
        return NodeStatus.COMPROMISED

    def verify(self, weight: float = 1.0) -> None:
        """Record a verification event, resetting decay timer."""
        self.last_verified_at = time.time()
        self.verification_weights.append(max(0.0, min(1.0, weight)))

    def penalize(self, factor: float = 0.5) -> None:
        """Apply a penalty that reduces trust immediately."""
        self.verification_weights.append(max(0.0, min(1.0, factor)))


@dataclass
class TrustNode:
    """A node in the Causal Trust Graph representing a tool invocation."""

    node_id: str = field(default_factory=generate_request_id)
    tool_name: str = ""
    server_name: str = ""
    timestamp: float = field(default_factory=time.time)
    trust: TrustScore = field(default_factory=TrustScore)
    status: NodeStatus = NodeStatus.TRUSTED
    taint_labels: set[str] = field(default_factory=set)
    permissions_used: set[str] = field(default_factory=set)
    input_hash: str = ""
    output_hash: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def update_status(self, now: float | None = None) -> NodeStatus:
        """Recompute status from trust score."""
        if self.status == NodeStatus.INVALIDATED:
            return self.status  # invalidation is permanent
        self.status = self.trust.status(now)
        return self.status


@dataclass
class CausalEdge:
    """A directed edge encoding data-flow causality between tool calls."""

    source_id: str
    target_id: str
    edge_type: str = "data_flow"  # data_flow | control_flow | delegation
    data_fields: list[str] = field(default_factory=list)
    taint_propagated: set[str] = field(default_factory=set)
    timestamp: float = field(default_factory=time.time)
    weight: float = 1.0  # causal strength


class CausalTrustGraph:
    """Directed acyclic graph of tool-call causality with trust scoring.

    This is the core data structure of the CTG framework. It tracks
    which tool outputs caused which subsequent tool inputs, enabling:
    1. Forward taint propagation
    2. Retroactive taint invalidation
    3. Minimum privilege computation
    4. Behavioral anomaly detection via topology analysis
    """

    def __init__(self, decay_rate: float = 0.01) -> None:
        self._nodes: dict[str, TrustNode] = {}
        self._edges: list[CausalEdge] = []
        self._adjacency: dict[str, list[str]] = {}  # forward: source → [targets]
        self._reverse_adj: dict[str, list[str]] = {}  # backward: target → [sources]
        self._decay_rate = decay_rate
        self._invalidated: set[str] = set()

    # ---- Node operations ----

    def add_node(
        self,
        tool_name: str,
        server_name: str = "",
        *,
        initial_trust: float = 1.0,
        permissions: set[str] | None = None,
        input_hash: str = "",
        output_hash: str = "",
        taint_labels: set[str] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> TrustNode:
        """Register a tool invocation as a node in the causal graph."""
        node = TrustNode(
            tool_name=tool_name,
            server_name=server_name,
            trust=TrustScore(
                initial=initial_trust,
                decay_rate=self._decay_rate,
            ),
            permissions_used=permissions or set(),
            input_hash=input_hash,
            output_hash=output_hash,
            taint_labels=taint_labels or set(),
            metadata=metadata or {},
        )
        self._nodes[node.node_id] = node
        self._adjacency.setdefault(node.node_id, [])
        self._reverse_adj.setdefault(node.node_id, [])
        logger.debug(
            "ctg_node_added",
            node_id=node.node_id,
            tool=tool_name,
            server=server_name,
        )
        return node

    def get_node(self, node_id: str) -> TrustNode | None:
        return self._nodes.get(node_id)

    # ---- Edge operations ----

    def add_edge(
        self,
        source_id: str,
        target_id: str,
        *,
        edge_type: str = "data_flow",
        data_fields: list[str] | None = None,
        weight: float = 1.0,
    ) -> CausalEdge | None:
        """Add a causal edge from source to target node."""
        if source_id not in self._nodes or target_id not in self._nodes:
            logger.warning(
                "ctg_edge_invalid_nodes",
                source=source_id,
                target=target_id,
            )
            return None

        edge = CausalEdge(
            source_id=source_id,
            target_id=target_id,
            edge_type=edge_type,
            data_fields=data_fields or [],
            weight=weight,
        )

        # Propagate taint forward along the edge
        source_node = self._nodes[source_id]
        if source_node.taint_labels:
            edge.taint_propagated = set(source_node.taint_labels)
            target_node = self._nodes[target_id]
            target_node.taint_labels |= source_node.taint_labels

        self._edges.append(edge)
        self._adjacency.setdefault(source_id, []).append(target_id)
        self._reverse_adj.setdefault(target_id, []).append(source_id)

        logger.debug(
            "ctg_edge_added",
            source=source_id,
            target=target_id,
            type=edge_type,
            taint=list(edge.taint_propagated),
        )
        return edge

    # ---- Trust operations ----

    def verify_node(self, node_id: str, weight: float = 1.0) -> bool:
        """Record a verification event for a node, resetting decay."""
        node = self._nodes.get(node_id)
        if not node:
            return False
        node.trust.verify(weight)
        node.update_status()
        logger.info("ctg_node_verified", node_id=node_id, new_score=node.trust.current())
        return True

    def penalize_node(self, node_id: str, factor: float = 0.5) -> bool:
        """Apply a trust penalty to a node."""
        node = self._nodes.get(node_id)
        if not node:
            return False
        node.trust.penalize(factor)
        node.update_status()
        logger.info("ctg_node_penalized", node_id=node_id, new_score=node.trust.current())
        return True

    def update_all_statuses(self, now: float | None = None) -> dict[str, NodeStatus]:
        """Recompute trust status for all non-invalidated nodes."""
        results = {}
        for nid, node in self._nodes.items():
            if node.status != NodeStatus.INVALIDATED:
                node.update_status(now)
            results[nid] = node.status
        return results

    # ---- Retroactive invalidation (novel) ----

    def invalidate_node(self, node_id: str) -> list[str]:
        """Mark a node as compromised and retroactively invalidate all
        downstream nodes that depend on its output.

        Returns the list of all invalidated node IDs (cascade).
        """
        if node_id not in self._nodes:
            return []

        invalidated: list[str] = []
        queue = [node_id]
        visited: set[str] = set()

        while queue:
            current = queue.pop(0)
            if current in visited:
                continue
            visited.add(current)

            node = self._nodes.get(current)
            if node and node.status != NodeStatus.INVALIDATED:
                node.status = NodeStatus.INVALIDATED
                node.taint_labels.add("retroactive_invalidation")
                self._invalidated.add(current)
                invalidated.append(current)
                logger.warning(
                    "ctg_node_invalidated",
                    node_id=current,
                    tool=node.tool_name,
                    cascade_from=node_id,
                )

            # Propagate to all downstream (forward) nodes
            for downstream in self._adjacency.get(current, []):
                if downstream not in visited:
                    queue.append(downstream)

        return invalidated

    # ---- Causal analysis ----

    def get_causal_chain(self, node_id: str) -> list[str]:
        """Get the full causal ancestry of a node (backward traversal)."""
        chain: list[str] = []
        visited: set[str] = set()
        queue = [node_id]

        while queue:
            current = queue.pop(0)
            if current in visited:
                continue
            visited.add(current)
            chain.append(current)
            for parent in self._reverse_adj.get(current, []):
                if parent not in visited:
                    queue.append(parent)

        return chain

    def get_downstream(self, node_id: str) -> list[str]:
        """Get all nodes transitively downstream of a node."""
        downstream: list[str] = []
        visited: set[str] = set()
        queue = self._adjacency.get(node_id, [])[:]

        while queue:
            current = queue.pop(0)
            if current in visited:
                continue
            visited.add(current)
            downstream.append(current)
            for child in self._adjacency.get(current, []):
                if child not in visited:
                    queue.append(child)

        return downstream

    # ---- Minimum privilege computation (novel) ----

    def compute_minimum_privileges(self, server_name: str) -> set[str]:
        """Derive the minimum permission set for a server by observing
        what permissions it actually used across all its nodes.

        This is the inverse of traditional approaches: instead of
        granting permissions and restricting, we observe actual usage
        and compute the provably minimal set.
        """
        permissions: set[str] = set()
        for node in self._nodes.values():
            if node.server_name == server_name and node.status != NodeStatus.INVALIDATED:
                permissions |= node.permissions_used
        return permissions

    # ---- Graph statistics ----

    @property
    def node_count(self) -> int:
        return len(self._nodes)

    @property
    def edge_count(self) -> int:
        return len(self._edges)

    @property
    def invalidated_count(self) -> int:
        return len(self._invalidated)

    def get_trust_summary(self, now: float | None = None) -> dict[str, Any]:
        """Get a summary of the entire trust graph."""
        statuses: dict[str, int] = {}
        low_trust: list[dict[str, Any]] = []

        for node in self._nodes.values():
            node.update_status(now)
            status_str = node.status.value
            statuses[status_str] = statuses.get(status_str, 0) + 1

            score = node.trust.current(now)
            if score < 0.5:
                low_trust.append({
                    "node_id": node.node_id,
                    "tool": node.tool_name,
                    "server": node.server_name,
                    "score": round(score, 4),
                    "status": status_str,
                })

        return {
            "total_nodes": self.node_count,
            "total_edges": self.edge_count,
            "invalidated": self.invalidated_count,
            "status_distribution": statuses,
            "low_trust_nodes": low_trust,
        }

    def to_dict(self) -> dict[str, Any]:
        """Serialize the graph for export/audit."""
        return {
            "nodes": {
                nid: {
                    "tool": n.tool_name,
                    "server": n.server_name,
                    "status": n.status.value,
                    "trust_score": round(n.trust.current(), 4),
                    "taint_labels": sorted(n.taint_labels),
                    "permissions": sorted(n.permissions_used),
                    "timestamp": n.timestamp,
                }
                for nid, n in self._nodes.items()
            },
            "edges": [
                {
                    "source": e.source_id,
                    "target": e.target_id,
                    "type": e.edge_type,
                    "taint_propagated": sorted(e.taint_propagated),
                    "weight": e.weight,
                }
                for e in self._edges
            ],
            "summary": self.get_trust_summary(),
        }

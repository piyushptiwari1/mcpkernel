"""Retroactive Taint Invalidation Engine.

When a tool/server/data source is later discovered to be compromised,
this engine traces all downstream effects through the Causal Trust Graph
and marks them as tainted — even if they already passed earlier checks.

Novel contribution:
  - Standard taint analysis propagates forward at call time.
  - Retroactive taint propagates backward in time: "this source was
    compromised at t₀, therefore all data derived after t₀ is suspect."
  - Integrates with the CTG for causal chain discovery and the
    TaintTracker for taint label management.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from mcpkernel.taint.tracker import TaintLabel, TaintTracker
from mcpkernel.utils import get_logger

if TYPE_CHECKING:
    from mcpkernel.trust.causal_graph import CausalTrustGraph

logger = get_logger(__name__)


@dataclass
class InvalidationEvent:
    """Record of a retroactive invalidation."""

    source_node_id: str
    compromised_at: float
    affected_node_ids: list[str]
    taint_labels_applied: list[str]
    reason: str
    timestamp: float = field(default_factory=time.time)


class RetroactiveTaintEngine:
    """Propagates taint backward through time via the Causal Trust Graph.

    Usage:
      1. Construct with a CausalTrustGraph and optional TaintTracker
      2. Call invalidate_source() when a source is found to be compromised
      3. The engine traverses all downstream nodes and applies taint
      4. Optionally triggers trust score penalties on affected nodes
    """

    def __init__(
        self,
        graph: CausalTrustGraph,
        taint_tracker: TaintTracker | None = None,
    ) -> None:
        self._graph = graph
        self._tracker = taint_tracker or TaintTracker()
        self._events: list[InvalidationEvent] = []

    def invalidate_source(
        self,
        source_node_id: str,
        *,
        reason: str = "compromised_source",
        taint_label: TaintLabel = TaintLabel.UNTRUSTED_EXTERNAL,
        compromised_at: float | None = None,
        penalize: bool = True,
        penalty_factor: float = 0.1,
    ) -> InvalidationEvent:
        """Retroactively taint all data derived from a compromised source.

        Args:
            source_node_id: The CTG node that was compromised.
            reason: Why the source was invalidated.
            taint_label: Label to apply to affected data.
            compromised_at: When the compromise happened (default: node creation time).
            penalize: Whether to reduce trust scores of affected nodes.
            penalty_factor: Weight applied to trust penalty (0.0 to 1.0).

        Returns:
            InvalidationEvent with details of what was affected.
        """
        node = self._graph._nodes.get(source_node_id)
        if not node:
            logger.warning(
                "retroactive_invalidation_source_not_found",
                node_id=source_node_id,
            )
            return InvalidationEvent(
                source_node_id=source_node_id,
                compromised_at=compromised_at or time.time(),
                affected_node_ids=[],
                taint_labels_applied=[],
                reason=reason,
            )

        ts = compromised_at or node.trust.last_verified_at

        # Use CTG's invalidation to cascade trust damage
        self._graph.invalidate_node(source_node_id)

        # Traverse all downstream nodes
        downstream = self._graph.get_downstream(source_node_id)
        affected: list[str] = []

        for nid in downstream:
            downstream_node = self._graph._nodes.get(nid)
            if not downstream_node:
                continue

            # Only invalidate nodes that were active after compromise
            if downstream_node.trust.last_verified_at >= ts:
                affected.append(nid)

                # Apply taint label to the node
                downstream_node.taint_labels.add(taint_label.value)

                # Mark in TaintTracker if the node has an output hash we track
                if downstream_node.output_hash:
                    self._tracker.mark(
                        data=downstream_node.output_hash,
                        label=taint_label,
                        source_id=nid,
                        metadata={
                            "reason": reason,
                            "retroactive": True,
                            "original_source": source_node_id,
                            "compromised_at": ts,
                        },
                    )

                # Penalize trust score
                if penalize:
                    downstream_node.trust.verification_weights.append(
                        penalty_factor
                    )

                logger.info(
                    "retroactive_taint_applied",
                    node_id=nid,
                    tool=downstream_node.tool_name,
                    taint=taint_label.value,
                )

        # Also taint the source node itself
        node.taint_labels.add(taint_label.value)
        if node.output_hash:
            self._tracker.mark(
                data=node.output_hash,
                label=taint_label,
                source_id=source_node_id,
                metadata={"reason": reason, "retroactive": True, "is_source": True},
            )

        event = InvalidationEvent(
            source_node_id=source_node_id,
            compromised_at=ts,
            affected_node_ids=affected,
            taint_labels_applied=[taint_label.value] * (len(affected) + 1),
            reason=reason,
        )
        self._events.append(event)

        logger.warning(
            "retroactive_invalidation_complete",
            source=source_node_id,
            affected_count=len(affected),
            reason=reason,
        )
        return event

    def get_contamination_chain(
        self, node_id: str
    ) -> list[dict[str, Any]]:
        """Trace backward to find how taint reached a node.

        Returns a chain of nodes from the compromised source to this node.
        """
        chain = self._graph.get_causal_chain(node_id)
        result = []
        for nid in chain:
            node = self._graph._nodes.get(nid)
            if node:
                result.append({
                    "node_id": nid,
                    "tool_name": node.tool_name,
                    "server_name": node.server_name,
                    "trust": node.trust.current(),
                    "status": node.trust.status().value,
                    "taint_labels": sorted(node.taint_labels),
                })
        return result

    @property
    def events(self) -> list[InvalidationEvent]:
        return list(self._events)

    @property
    def taint_tracker(self) -> TaintTracker:
        return self._tracker

    def summary(self) -> dict[str, Any]:
        total_affected = sum(len(e.affected_node_ids) for e in self._events)
        return {
            "invalidation_events": len(self._events),
            "total_affected_nodes": total_affected,
            "taint_tracker": self._tracker.summary(),
        }

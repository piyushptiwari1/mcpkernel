"""Behavioral Fingerprinting — detect anomalous tool-call patterns.

Uses graph topology features to build a "normal" tool-use profile and
flags deviations.  Inspired by AttriGuard (arXiv:2603.10749) and
AgentSentry (arXiv:2602.22724) causal attribution guardrails.

Novel aspects:
  - Graph-topology features (fan-out, depth, delegation chains)
  - Per-server / per-agent behavioral baselines
  - Z-score anomaly detection with configurable sensitivity
"""

from __future__ import annotations

import math
import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from mcpkernel.utils import get_logger

if TYPE_CHECKING:
    from mcpkernel.trust.causal_graph import CausalTrustGraph

logger = get_logger(__name__)


@dataclass
class ToolCallFeatures:
    """Feature vector extracted from a tool call sequence."""

    total_calls: int = 0
    unique_tools: int = 0
    max_fan_out: int = 0  # max children of any single node
    max_depth: int = 0  # longest causal chain
    delegation_count: int = 0  # tool→tool delegations
    data_flow_count: int = 0  # data dependency edges
    avg_trust_score: float = 1.0
    call_rate: float = 0.0  # calls per second
    distinct_servers: int = 0
    permission_diversity: int = 0  # unique permissions used
    timestamp: float = field(default_factory=time.time)


@dataclass
class BehavioralFingerprint:
    """Baseline behavioral profile for an entity.

    Accumulates ToolCallFeatures over time to build a statistical
    model of "normal" behavior.
    """

    entity_id: str
    entity_type: str = "agent"  # "agent", "server", "user"
    history: list[ToolCallFeatures] = field(default_factory=list)
    max_history: int = 1000
    created_at: float = field(default_factory=time.time)

    def record(self, features: ToolCallFeatures) -> None:
        """Record observed features."""
        self.history.append(features)
        if len(self.history) > self.max_history:
            self.history = self.history[-self.max_history :]

    def _mean_std(self, attr: str) -> tuple[float, float]:
        """Compute mean and std-dev for a numeric feature."""
        if not self.history:
            return 0.0, 1.0
        values = [getattr(f, attr) for f in self.history]
        n = len(values)
        mean = sum(values) / n
        if n < 2:
            return mean, 1.0
        variance = sum((v - mean) ** 2 for v in values) / (n - 1)
        return mean, math.sqrt(variance) if variance > 0 else 1.0

    def z_scores(self, features: ToolCallFeatures) -> dict[str, float]:
        """Compute z-scores for each feature against baseline."""
        numeric_fields = [
            "total_calls",
            "unique_tools",
            "max_fan_out",
            "max_depth",
            "delegation_count",
            "data_flow_count",
            "avg_trust_score",
            "call_rate",
            "distinct_servers",
            "permission_diversity",
        ]
        scores: dict[str, float] = {}
        for f in numeric_fields:
            mean, std = self._mean_std(f)
            val = getattr(features, f)
            scores[f] = (val - mean) / std if std > 0 else 0.0
        return scores


def extract_features(graph: CausalTrustGraph) -> ToolCallFeatures:
    """Extract behavioral features from a CausalTrustGraph snapshot."""
    nodes = graph._nodes
    forward = graph._adjacency

    if not nodes:
        return ToolCallFeatures()

    tools = set()
    servers = set()
    all_permissions: set[str] = set()
    trust_scores: list[float] = []
    delegation_count = 0
    data_flow_count = 0
    max_fan_out = 0

    for node in nodes.values():
        tools.add(node.tool_name)
        if node.server_name:
            servers.add(node.server_name)
        all_permissions.update(node.permissions_used)
        trust_scores.append(node.trust.current())

    for _source_id, targets in forward.items():
        fan_out = len(targets)
        max_fan_out = max(max_fan_out, fan_out)

    # Count edge types from the actual edges list
    for edge in graph._edges:
        if edge.edge_type == "delegation":
            delegation_count += 1
        elif edge.edge_type == "data_flow":
            data_flow_count += 1

    # Compute max depth via BFS from roots
    roots = _find_roots(graph)
    max_depth = 0
    for root_id in roots:
        depth = _bfs_max_depth(graph, root_id)
        max_depth = max(max_depth, depth)

    # Call rate: spans between first and last node creation
    timestamps = [n.trust.last_verified_at for n in nodes.values()]
    if len(timestamps) >= 2:
        span = max(timestamps) - min(timestamps)
        call_rate = len(nodes) / span if span > 0 else 0.0
    else:
        call_rate = 0.0

    avg_trust = sum(trust_scores) / len(trust_scores) if trust_scores else 1.0

    return ToolCallFeatures(
        total_calls=len(nodes),
        unique_tools=len(tools),
        max_fan_out=max_fan_out,
        max_depth=max_depth,
        delegation_count=delegation_count,
        data_flow_count=data_flow_count,
        avg_trust_score=avg_trust,
        call_rate=call_rate,
        distinct_servers=len(servers),
        permission_diversity=len(all_permissions),
    )


def _find_roots(graph: CausalTrustGraph) -> list[str]:
    """Find nodes with no incoming edges (causal roots)."""
    all_targets: set[str] = set()
    for targets in graph._adjacency.values():
        for target_id in targets:
            all_targets.add(target_id)
    return [nid for nid in graph._nodes if nid not in all_targets]


def _bfs_max_depth(graph: CausalTrustGraph, start_id: str) -> int:
    """BFS to find the max depth from a starting node."""
    visited: set[str] = set()
    queue: list[tuple[str, int]] = [(start_id, 0)]
    max_d = 0
    while queue:
        nid, depth = queue.pop(0)
        if nid in visited:
            continue
        visited.add(nid)
        max_d = max(max_d, depth)
        for child_id in graph._adjacency.get(nid, []):
            if child_id not in visited:
                queue.append((child_id, depth + 1))
    return max_d


class AnomalyDetector:
    """Detects behavioral anomalies using fingerprint baselines.

    Configuration:
      - sigma_threshold: z-score threshold for flagging (default: 2.5)
      - min_observations: minimum baseline records before alerting (default: 5)
      - monitored_features: which features to check (None = all)
    """

    def __init__(
        self,
        *,
        sigma_threshold: float = 2.5,
        min_observations: int = 5,
        monitored_features: list[str] | None = None,
    ) -> None:
        self._fingerprints: dict[str, BehavioralFingerprint] = {}
        self._sigma = sigma_threshold
        self._min_obs = min_observations
        self._monitored = monitored_features
        self._anomaly_log: list[dict[str, Any]] = []

    def register_entity(
        self,
        entity_id: str,
        entity_type: str = "agent",
        max_history: int = 1000,
    ) -> BehavioralFingerprint:
        """Register an entity for behavioral monitoring."""
        fp = BehavioralFingerprint(
            entity_id=entity_id,
            entity_type=entity_type,
            max_history=max_history,
        )
        self._fingerprints[entity_id] = fp
        return fp

    def observe(
        self,
        entity_id: str,
        features: ToolCallFeatures,
    ) -> list[dict[str, Any]]:
        """Observe features, check for anomalies, record in baseline.

        Returns list of anomaly alerts (empty if normal).
        """
        fp = self._fingerprints.get(entity_id)
        if not fp:
            return []

        anomalies: list[dict[str, Any]] = []

        if len(fp.history) >= self._min_obs:
            z = fp.z_scores(features)
            for feature_name, z_val in z.items():
                if self._monitored and feature_name not in self._monitored:
                    continue
                if abs(z_val) > self._sigma:
                    alert = {
                        "entity_id": entity_id,
                        "feature": feature_name,
                        "z_score": round(z_val, 3),
                        "threshold": self._sigma,
                        "observed": getattr(features, feature_name),
                        "timestamp": time.time(),
                    }
                    anomalies.append(alert)
                    self._anomaly_log.append(alert)
                    logger.warning(
                        "behavioral_anomaly",
                        entity_id=entity_id,
                        feature=feature_name,
                        z_score=round(z_val, 3),
                    )

        # Always record the observation for future baselines
        fp.record(features)
        return anomalies

    def get_fingerprint(self, entity_id: str) -> BehavioralFingerprint | None:
        return self._fingerprints.get(entity_id)

    @property
    def anomaly_log(self) -> list[dict[str, Any]]:
        return list(self._anomaly_log)

    def summary(self) -> dict[str, Any]:
        return {
            "monitored_entities": len(self._fingerprints),
            "total_anomalies": len(self._anomaly_log),
            "sigma_threshold": self._sigma,
            "min_observations": self._min_obs,
        }

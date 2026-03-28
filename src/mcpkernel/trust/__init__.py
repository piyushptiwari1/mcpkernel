"""Causal Trust Graph — adaptive trust propagation for agentic AI.

This package implements the Causal Trust Graph (CTG), a novel framework
that unifies causal attribution, trust decay, taint propagation, and
cryptographic provenance into a single directed acyclic graph.

Key concepts:
- **Trust Decay**: tool/server trust erodes exponentially without
  re-verification events.  T(t) = T₀ · e^{-λ(t - t₀)} · Π w(vᵢ)
- **Causal Attribution**: track which tool output caused which downstream
  action, enabling retroactive invalidation.
- **Behavioral Fingerprinting**: detect anomalous tool-call patterns via
  graph topology divergence.
- **Retroactive Taint Invalidation**: when a source is later found
  compromised, propagate taint backward through the causal graph.
"""

from mcpkernel.trust.behavioral import AnomalyDetector, BehavioralFingerprint
from mcpkernel.trust.causal_graph import (
    CausalEdge,
    CausalTrustGraph,
    TrustNode,
    TrustScore,
)
from mcpkernel.trust.retroactive import RetroactiveTaintEngine
from mcpkernel.trust.trust_decay import TrustDecayEngine

__all__ = [
    "AnomalyDetector",
    "BehavioralFingerprint",
    "CausalEdge",
    "CausalTrustGraph",
    "RetroactiveTaintEngine",
    "TrustDecayEngine",
    "TrustNode",
    "TrustScore",
]

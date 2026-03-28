"""Tests for mcpkernel.trust — Causal Trust Graph, decay, behavioral, retroactive."""

from __future__ import annotations

import time

import pytest

from mcpkernel.taint.tracker import TaintTracker
from mcpkernel.trust.behavioral import (
    AnomalyDetector,
    BehavioralFingerprint,
    ToolCallFeatures,
    extract_features,
)
from mcpkernel.trust.causal_graph import (
    CausalTrustGraph,
    NodeStatus,
    TrustScore,
)
from mcpkernel.trust.retroactive import RetroactiveTaintEngine
from mcpkernel.trust.trust_decay import TrustDecayEngine


# -----------------------------------------------------------------------
# TrustScore
# -----------------------------------------------------------------------
class TestTrustScore:
    def test_initial_trust_is_one(self):
        ts = TrustScore()
        assert ts.current() <= 1.0
        assert ts.current() > 0.9  # should still be high at creation

    def test_decay_over_time(self):
        ts = TrustScore(decay_rate=1.0, last_verified_at=time.time() - 5)
        assert ts.current() < 0.01

    def test_verify_resets_timer(self):
        ts = TrustScore(decay_rate=0.5, last_verified_at=time.time() - 10)
        before = ts.current()
        ts.verify()
        after = ts.current()
        assert after > before

    def test_penalize_reduces_trust(self):
        ts = TrustScore()
        ts.penalize(0.5)
        assert ts.current() < 1.0
        assert 0.5 in ts.verification_weights

    def test_status_transitions(self):
        ts = TrustScore(initial=1.0)
        assert ts.status() == NodeStatus.TRUSTED

        ts2 = TrustScore(initial=0.2, last_verified_at=time.time())
        assert ts2.status() in (NodeStatus.SUSPICIOUS, NodeStatus.DEGRADED)

        ts3 = TrustScore(initial=0.05, last_verified_at=time.time())
        assert ts3.status() == NodeStatus.COMPROMISED

    def test_zero_decay_rate(self):
        ts = TrustScore(decay_rate=0.0, last_verified_at=time.time() - 1000)
        assert ts.current() == pytest.approx(1.0, abs=0.01)


# -----------------------------------------------------------------------
# CausalTrustGraph
# -----------------------------------------------------------------------
class TestCausalTrustGraph:
    def test_add_node(self):
        g = CausalTrustGraph()
        node = g.add_node(tool_name="read_file", server_name="fs")
        assert node.tool_name == "read_file"
        assert node.node_id in g._nodes

    def test_add_edge_propagates_taint(self):
        g = CausalTrustGraph()
        n1 = g.add_node(tool_name="fetch", server_name="web")
        n2 = g.add_node(tool_name="process", server_name="compute")
        n1.taint_labels.add("untrusted_external")
        g.add_edge(n1.node_id, n2.node_id, edge_type="data_flow")
        assert "untrusted_external" in n2.taint_labels

    def test_get_causal_chain(self):
        g = CausalTrustGraph()
        n1 = g.add_node(tool_name="a", server_name="s")
        n2 = g.add_node(tool_name="b", server_name="s")
        n3 = g.add_node(tool_name="c", server_name="s")
        g.add_edge(n1.node_id, n2.node_id)
        g.add_edge(n2.node_id, n3.node_id)
        chain = g.get_causal_chain(n3.node_id)
        assert n1.node_id in chain
        assert n2.node_id in chain

    def test_get_downstream(self):
        g = CausalTrustGraph()
        n1 = g.add_node(tool_name="root", server_name="s")
        n2 = g.add_node(tool_name="child1", server_name="s")
        n3 = g.add_node(tool_name="child2", server_name="s")
        g.add_edge(n1.node_id, n2.node_id)
        g.add_edge(n1.node_id, n3.node_id)
        downstream = g.get_downstream(n1.node_id)
        assert n2.node_id in downstream
        assert n3.node_id in downstream

    def test_invalidate_cascades(self):
        g = CausalTrustGraph()
        n1 = g.add_node(tool_name="source", server_name="s")
        n2 = g.add_node(tool_name="mid", server_name="s")
        n3 = g.add_node(tool_name="leaf", server_name="s")
        g.add_edge(n1.node_id, n2.node_id)
        g.add_edge(n2.node_id, n3.node_id)
        g.invalidate_node(n1.node_id)
        assert n1.status == NodeStatus.INVALIDATED
        assert n2.status == NodeStatus.INVALIDATED
        assert n3.status == NodeStatus.INVALIDATED

    def test_compute_minimum_privileges(self):
        g = CausalTrustGraph()
        n1 = g.add_node(
            tool_name="read", server_name="fs", permissions={"read", "list"}
        )
        n2 = g.add_node(
            tool_name="write", server_name="fs", permissions={"write"}
        )
        g.add_edge(n1.node_id, n2.node_id)
        privs = g.compute_minimum_privileges("fs")
        assert "read" in privs
        assert "list" in privs
        assert "write" in privs

    def test_verify_node(self):
        g = CausalTrustGraph()
        n = g.add_node(tool_name="t", server_name="s")
        g.verify_node(n.node_id)
        assert g._nodes[n.node_id].trust.current() > 0.9

    def test_trust_summary(self):
        g = CausalTrustGraph()
        g.add_node(tool_name="a", server_name="s1")
        g.add_node(tool_name="b", server_name="s2")
        summary = g.get_trust_summary()
        assert summary["total_nodes"] == 2

    def test_to_dict(self):
        g = CausalTrustGraph()
        n1 = g.add_node(tool_name="a", server_name="s")
        n2 = g.add_node(tool_name="b", server_name="s")
        g.add_edge(n1.node_id, n2.node_id)
        d = g.to_dict()
        assert len(d["nodes"]) == 2
        assert len(d["edges"]) == 1

    def test_empty_graph(self):
        g = CausalTrustGraph()
        assert g.get_trust_summary()["total_nodes"] == 0
        assert g.to_dict()["nodes"] == {}


# -----------------------------------------------------------------------
# TrustDecayEngine
# -----------------------------------------------------------------------
class TestTrustDecayEngine:
    def test_register_and_get_trust(self):
        engine = TrustDecayEngine()
        engine.register("server-1", "server")
        trust = engine.get_trust("server-1")
        assert trust > 0.9

    def test_trust_decays_over_time(self):
        engine = TrustDecayEngine(server_decay_rate=10.0)
        profile = engine.register("srv", "server", decay_rate=10.0)
        profile.last_verified_at = time.time() - 1.0
        trust = engine.get_trust("srv")
        assert trust < 0.001

    def test_verify_resets_decay(self):
        engine = TrustDecayEngine(server_decay_rate=1.0)
        profile = engine.register("srv", "server", decay_rate=1.0)
        profile.last_verified_at = time.time() - 5.0
        before = engine.get_trust("srv")
        engine.verify("srv", "manual")
        after = engine.get_trust("srv")
        assert after > before

    def test_penalize(self):
        engine = TrustDecayEngine()
        engine.register("tool-x", "tool")
        before = engine.get_trust("tool-x")
        engine.penalize("tool-x", factor=0.5, reason="policy_violation")
        after = engine.get_trust("tool-x")
        assert after < before

    def test_get_all_below_threshold(self):
        engine = TrustDecayEngine(tool_decay_rate=100.0, alert_threshold=0.5)
        profile = engine.register("bad-tool", "tool", decay_rate=100.0)
        profile.last_verified_at = time.time() - 1.0
        below = engine.get_all_below_threshold()
        assert len(below) >= 1
        assert below[0][0] == "bad-tool"

    def test_unknown_entity(self):
        engine = TrustDecayEngine()
        assert engine.get_trust("nonexistent") == 0.0
        assert engine.verify("nonexistent") is False
        assert engine.penalize("nonexistent") is False

    def test_summary(self):
        engine = TrustDecayEngine()
        engine.register("s1", "server")
        engine.register("t1", "tool")
        s = engine.summary()
        assert s["total_entities"] == 2
        assert "server" in s["average_trust_by_type"]

    def test_alerts_generated(self):
        engine = TrustDecayEngine(alert_threshold=0.99)
        profile = engine.register("x", "tool")
        profile.last_verified_at = time.time() - 1.0
        profile.decay_rate = 0.1
        engine.get_trust("x")  # Should trigger alert
        assert len(engine.alerts) >= 1


# -----------------------------------------------------------------------
# BehavioralFingerprint & AnomalyDetector
# -----------------------------------------------------------------------
class TestBehavioralFingerprint:
    def test_record_and_z_scores(self):
        fp = BehavioralFingerprint(entity_id="agent-1")
        for _ in range(10):
            fp.record(ToolCallFeatures(total_calls=5, unique_tools=2))
        # An observation that deviates significantly
        z = fp.z_scores(ToolCallFeatures(total_calls=100, unique_tools=2))
        assert z["total_calls"] > 2.0  # should be a clear outlier

    def test_empty_baseline(self):
        fp = BehavioralFingerprint(entity_id="new")
        z = fp.z_scores(ToolCallFeatures(total_calls=10))
        # With no history, z-scores should be 0 or low
        assert abs(z["total_calls"]) < 20

    def test_max_history(self):
        fp = BehavioralFingerprint(entity_id="a", max_history=5)
        for _ in range(10):
            fp.record(ToolCallFeatures(total_calls=1))
        assert len(fp.history) == 5


class TestAnomalyDetector:
    def test_no_anomaly_under_threshold(self):
        detector = AnomalyDetector(sigma_threshold=3.0, min_observations=3)
        detector.register_entity("agent-1")
        for _ in range(5):
            anomalies = detector.observe(
                "agent-1", ToolCallFeatures(total_calls=5, unique_tools=2)
            )
        assert len(anomalies) == 0

    def test_anomaly_detected(self):
        detector = AnomalyDetector(sigma_threshold=2.0, min_observations=3)
        detector.register_entity("agent-1")
        # Establish baseline
        for _ in range(10):
            detector.observe(
                "agent-1", ToolCallFeatures(total_calls=5, unique_tools=2)
            )
        # Inject anomaly
        anomalies = detector.observe(
            "agent-1", ToolCallFeatures(total_calls=500, unique_tools=50)
        )
        assert len(anomalies) > 0
        assert any(a["feature"] == "total_calls" for a in anomalies)

    def test_unregistered_entity(self):
        detector = AnomalyDetector()
        anomalies = detector.observe("unknown", ToolCallFeatures())
        assert anomalies == []

    def test_summary(self):
        detector = AnomalyDetector()
        detector.register_entity("a")
        s = detector.summary()
        assert s["monitored_entities"] == 1


class TestExtractFeatures:
    def test_extract_from_graph(self):
        g = CausalTrustGraph()
        n1 = g.add_node(
            tool_name="read", server_name="fs", permissions={"read"}
        )
        n2 = g.add_node(
            tool_name="write", server_name="fs", permissions={"write"}
        )
        g.add_edge(n1.node_id, n2.node_id, edge_type="data_flow")
        features = extract_features(g)
        assert features.total_calls == 2
        assert features.unique_tools == 2
        assert features.data_flow_count == 1
        assert features.permission_diversity == 2

    def test_empty_graph(self):
        g = CausalTrustGraph()
        features = extract_features(g)
        assert features.total_calls == 0


# -----------------------------------------------------------------------
# RetroactiveTaintEngine
# -----------------------------------------------------------------------
class TestRetroactiveTaintEngine:
    def test_invalidate_source_propagates(self):
        g = CausalTrustGraph()
        n1 = g.add_node(tool_name="fetch", server_name="web")
        n2 = g.add_node(tool_name="parse", server_name="compute")
        n3 = g.add_node(tool_name="store", server_name="db")
        g.add_edge(n1.node_id, n2.node_id)
        g.add_edge(n2.node_id, n3.node_id)

        tracker = TaintTracker()
        engine = RetroactiveTaintEngine(g, tracker)
        event = engine.invalidate_source(
            n1.node_id, reason="compromised_api"
        )
        assert n1.node_id not in event.affected_node_ids  # source itself not in affected list
        assert len(event.affected_node_ids) == 2
        assert "untrusted_external" in n2.taint_labels
        assert "untrusted_external" in n3.taint_labels

    def test_invalidate_nonexistent_node(self):
        g = CausalTrustGraph()
        engine = RetroactiveTaintEngine(g)
        event = engine.invalidate_source("nonexistent")
        assert len(event.affected_node_ids) == 0

    def test_contamination_chain(self):
        g = CausalTrustGraph()
        n1 = g.add_node(tool_name="a", server_name="s")
        n2 = g.add_node(tool_name="b", server_name="s")
        g.add_edge(n1.node_id, n2.node_id)

        engine = RetroactiveTaintEngine(g)
        engine.invalidate_source(n1.node_id)
        chain = engine.get_contamination_chain(n2.node_id)
        assert len(chain) >= 1

    def test_summary(self):
        g = CausalTrustGraph()
        n1 = g.add_node(tool_name="x", server_name="s")
        engine = RetroactiveTaintEngine(g)
        engine.invalidate_source(n1.node_id)
        s = engine.summary()
        assert s["invalidation_events"] == 1

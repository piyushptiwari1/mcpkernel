"""Trust Decay Engine — time-based trust erosion with verification events.

Implements the mathematical model:
    T(t) = T₀ · e^{-λ(t - t₀)} · Π w(vᵢ)

Use cases:
  - MCP server trust degrades if not re-verified
  - Tool trust erodes between successful audits
  - Agent trust drops after policy violations
"""

from __future__ import annotations

import math
import time
from dataclasses import dataclass, field
from typing import Any

from mcpkernel.utils import get_logger

logger = get_logger(__name__)


@dataclass
class VerificationEvent:
    """A recorded trust verification event."""

    event_id: str
    entity_id: str
    event_type: str  # "audit_pass", "signature_verified", "policy_compliant", etc.
    weight: float = 1.0  # 0.0 to 1.0
    timestamp: float = field(default_factory=time.time)
    details: dict[str, Any] = field(default_factory=dict)


@dataclass
class TrustProfile:
    """Trust profile for an entity (server, tool, agent)."""

    entity_id: str
    entity_type: str  # "server", "tool", "agent"
    initial_trust: float = 1.0
    decay_rate: float = 0.001  # λ — slow default (per-second)
    last_verified_at: float = field(default_factory=time.time)
    created_at: float = field(default_factory=time.time)
    verification_history: list[VerificationEvent] = field(default_factory=list)
    penalty_history: list[dict[str, Any]] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def current_trust(self, now: float | None = None) -> float:
        """Compute trust with exponential decay + verification weights."""
        t = now or time.time()
        elapsed = max(0.0, t - self.last_verified_at)
        base = self.initial_trust * math.exp(-self.decay_rate * elapsed)

        weight_product = 1.0
        for event in self.verification_history:
            weight_product *= max(0.0, min(1.0, event.weight))

        return max(0.0, min(1.0, base * weight_product))


class TrustDecayEngine:
    """Manages trust profiles for all entities in the system.

    Provides:
      - Automatic trust decay over time
      - Verification events that reset/boost trust
      - Penalty events that reduce trust
      - Configurable decay rates per entity type
      - Trust threshold alerts
    """

    def __init__(
        self,
        *,
        default_decay_rate: float = 0.001,
        server_decay_rate: float = 0.0005,
        tool_decay_rate: float = 0.001,
        agent_decay_rate: float = 0.002,
        alert_threshold: float = 0.3,
    ) -> None:
        self._profiles: dict[str, TrustProfile] = {}
        self._decay_rates = {
            "server": server_decay_rate,
            "tool": tool_decay_rate,
            "agent": agent_decay_rate,
        }
        self._default_decay = default_decay_rate
        self._alert_threshold = alert_threshold
        self._alerts: list[dict[str, Any]] = []

    def register(
        self,
        entity_id: str,
        entity_type: str = "tool",
        *,
        initial_trust: float = 1.0,
        decay_rate: float | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> TrustProfile:
        """Register an entity with a trust profile."""
        rate = decay_rate or self._decay_rates.get(entity_type, self._default_decay)
        profile = TrustProfile(
            entity_id=entity_id,
            entity_type=entity_type,
            initial_trust=initial_trust,
            decay_rate=rate,
            metadata=metadata or {},
        )
        self._profiles[entity_id] = profile
        logger.info(
            "trust_profile_registered",
            entity_id=entity_id,
            entity_type=entity_type,
            initial_trust=initial_trust,
            decay_rate=rate,
        )
        return profile

    def get_trust(self, entity_id: str, now: float | None = None) -> float:
        """Get current trust score for an entity."""
        profile = self._profiles.get(entity_id)
        if not profile:
            return 0.0
        score = profile.current_trust(now)
        if score < self._alert_threshold and entity_id not in {
            a["entity_id"] for a in self._alerts
        }:
            self._alerts.append({
                "entity_id": entity_id,
                "score": score,
                "timestamp": time.time(),
                "reason": "trust_below_threshold",
            })
            logger.warning(
                "trust_alert",
                entity_id=entity_id,
                score=round(score, 4),
                threshold=self._alert_threshold,
            )
        return score

    def verify(
        self,
        entity_id: str,
        event_type: str = "manual_verification",
        *,
        weight: float = 1.0,
        details: dict[str, Any] | None = None,
    ) -> bool:
        """Record a verification event, resetting the decay timer."""
        profile = self._profiles.get(entity_id)
        if not profile:
            return False

        from mcpkernel.utils import generate_request_id

        event = VerificationEvent(
            event_id=generate_request_id(),
            entity_id=entity_id,
            event_type=event_type,
            weight=weight,
            details=details or {},
        )
        profile.verification_history.append(event)
        profile.last_verified_at = time.time()
        # Remove entity from alerts if trust recovers
        self._alerts = [a for a in self._alerts if a["entity_id"] != entity_id]
        logger.info(
            "trust_verification",
            entity_id=entity_id,
            event_type=event_type,
            weight=weight,
        )
        return True

    def penalize(
        self,
        entity_id: str,
        factor: float = 0.5,
        *,
        reason: str = "policy_violation",
    ) -> bool:
        """Apply a trust penalty to an entity."""
        profile = self._profiles.get(entity_id)
        if not profile:
            return False

        profile.verification_history.append(
            VerificationEvent(
                event_id=f"penalty_{time.time()}",
                entity_id=entity_id,
                event_type="penalty",
                weight=factor,
                details={"reason": reason},
            )
        )
        profile.penalty_history.append({
            "factor": factor,
            "reason": reason,
            "timestamp": time.time(),
        })
        logger.warning(
            "trust_penalty",
            entity_id=entity_id,
            factor=factor,
            reason=reason,
        )
        return True

    def get_profile(self, entity_id: str) -> TrustProfile | None:
        return self._profiles.get(entity_id)

    def get_all_below_threshold(
        self, threshold: float | None = None, now: float | None = None
    ) -> list[tuple[str, float]]:
        """Get all entities with trust below a threshold."""
        t = threshold or self._alert_threshold
        results = []
        for eid, profile in self._profiles.items():
            score = profile.current_trust(now)
            if score < t:
                results.append((eid, score))
        return sorted(results, key=lambda x: x[1])

    @property
    def alerts(self) -> list[dict[str, Any]]:
        return list(self._alerts)

    def summary(self, now: float | None = None) -> dict[str, Any]:
        """Get a summary of all trust profiles."""
        by_type: dict[str, list[float]] = {}
        for profile in self._profiles.values():
            score = profile.current_trust(now)
            by_type.setdefault(profile.entity_type, []).append(score)

        avg_by_type = {}
        for etype, scores in by_type.items():
            avg_by_type[etype] = round(sum(scores) / len(scores), 4) if scores else 0

        return {
            "total_entities": len(self._profiles),
            "average_trust_by_type": avg_by_type,
            "below_threshold": len(self.get_all_below_threshold(now=now)),
            "active_alerts": len(self._alerts),
        }

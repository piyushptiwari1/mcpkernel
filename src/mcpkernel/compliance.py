"""Compliance Presets — one-line regulatory compliance activation.

Usage:
    from mcpkernel.compliance import apply_preset
    settings = apply_preset("hipaa", get_config())

Supported presets:
  - hipaa: HIPAA Safe Harbor — PII blocking, full taint, signed audit
  - soc2: SOC 2 Type II — audit logging, access controls, encryption
  - pci_dss: PCI DSS v4.0 — secret blocking, network isolation, encrypted logs
  - gdpr: GDPR Article 25 — data minimization, PII detection, right to erasure
  - fedramp: FedRAMP High — full sandbox, mTLS, eBPF monitoring, signed DEE
"""

from __future__ import annotations

from typing import Any

from mcpkernel.utils import get_logger

logger = get_logger(__name__)


# ---------------------------------------------------------------------------
# Preset definitions: each maps config section → overrides
# ---------------------------------------------------------------------------
PRESETS: dict[str, dict[str, dict[str, Any]]] = {
    "hipaa": {
        "taint": {
            "mode": "full",
            "block_on_violation": True,
            "pii_patterns_enabled": True,
            "static_analysis_enabled": True,
        },
        "audit": {
            "enabled": True,
            "sign_entries": True,
        },
        "dee": {
            "enabled": True,
            "sign_traces": True,
        },
        "trust": {
            "enabled": True,
            "retroactive_invalidation": True,
            "alert_threshold": 0.4,
        },
        "sandbox": {
            "network_enabled": False,
        },
        "policy": {
            "default_action": "deny",
        },
    },
    "soc2": {
        "taint": {
            "mode": "full",
            "block_on_violation": True,
        },
        "audit": {
            "enabled": True,
            "sign_entries": True,
        },
        "auth": {
            "enabled": True,
        },
        "dee": {
            "enabled": True,
            "sign_traces": True,
        },
        "observability": {
            "metrics_enabled": True,
            "tracing_enabled": True,
        },
        "trust": {
            "enabled": True,
        },
    },
    "pci_dss": {
        "taint": {
            "mode": "full",
            "block_on_violation": True,
            "pii_patterns_enabled": True,
        },
        "audit": {
            "enabled": True,
            "sign_entries": True,
        },
        "sandbox": {
            "network_enabled": False,
            "max_memory_mb": 128,
        },
        "auth": {
            "enabled": True,
        },
        "rate_limit": {
            "enabled": True,
        },
        "trust": {
            "enabled": True,
            "compromise_threshold": 0.15,
        },
        "policy": {
            "default_action": "deny",
        },
    },
    "gdpr": {
        "taint": {
            "mode": "full",
            "block_on_violation": True,
            "pii_patterns_enabled": True,
        },
        "context": {
            "enabled": True,
            "strategy": "aggressive",
            "max_context_tokens": 2048,
        },
        "audit": {
            "enabled": True,
        },
        "trust": {
            "enabled": True,
            "retroactive_invalidation": True,
        },
    },
    "fedramp": {
        "taint": {
            "mode": "full",
            "block_on_violation": True,
            "pii_patterns_enabled": True,
            "static_analysis_enabled": True,
        },
        "audit": {
            "enabled": True,
            "sign_entries": True,
        },
        "auth": {
            "enabled": True,
        },
        "sandbox": {
            "network_enabled": False,
        },
        "ebpf": {
            "enabled": True,
        },
        "dee": {
            "enabled": True,
            "sign_traces": True,
            "replay_on_drift": True,
        },
        "trust": {
            "enabled": True,
            "retroactive_invalidation": True,
            "alert_threshold": 0.5,
            "anomaly_sigma": 2.0,
        },
        "policy": {
            "default_action": "deny",
        },
    },
}

PRESET_NAMES = list(PRESETS.keys())


def apply_preset(preset_name: str, settings: Any) -> Any:
    """Apply a compliance preset to MCPKernelSettings.

    Args:
        preset_name: One of "hipaa", "soc2", "pci_dss", "gdpr", "fedramp".
        settings: MCPKernelSettings instance to modify in-place.

    Returns:
        The modified settings object.

    Raises:
        ValueError: If preset_name is not recognized.
    """
    name = preset_name.lower().strip()
    if name not in PRESETS:
        raise ValueError(f"Unknown compliance preset '{preset_name}'. Available: {', '.join(PRESET_NAMES)}")

    overrides = PRESETS[name]
    for section_key, section_overrides in overrides.items():
        section_obj = getattr(settings, section_key, None)
        if section_obj is None:
            continue
        for attr_key, attr_val in section_overrides.items():
            if hasattr(section_obj, attr_key):
                setattr(section_obj, attr_key, attr_val)

    logger.info(
        "compliance_preset_applied",
        preset=name,
        sections_modified=list(overrides.keys()),
    )
    return settings


def get_preset_description(preset_name: str) -> str:
    """Get a human-readable description of what a preset configures."""
    descriptions = {
        "hipaa": (
            "HIPAA Safe Harbor: Full taint tracking with PII blocking, "
            "signed audit logs, signed DEE traces, network isolation, "
            "retroactive taint invalidation, deny-by-default policy."
        ),
        "soc2": (
            "SOC 2 Type II: Full taint and audit logging, authentication "
            "required, signed traces, full observability (metrics + tracing), "
            "trust monitoring enabled."
        ),
        "pci_dss": (
            "PCI DSS v4.0: Full taint with PII detection, signed audit, "
            "network isolation, memory restrictions, authentication and "
            "rate limiting, strict trust thresholds, deny-by-default."
        ),
        "gdpr": (
            "GDPR Article 25 — Data Protection by Design: Full taint with "
            "PII detection, aggressive context minimization (2048 tokens), "
            "audit logging, retroactive taint invalidation for right to erasure."
        ),
        "fedramp": (
            "FedRAMP High: Maximum security — full taint, signed audit, "
            "authentication required, network isolation, eBPF syscall monitoring, "
            "signed DEE with drift replay, retroactive taint, aggressive anomaly "
            "detection (sigma=2.0), deny-by-default policy."
        ),
    }
    return descriptions.get(preset_name.lower().strip(), "Unknown preset.")

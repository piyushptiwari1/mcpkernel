"""Tests for mcpkernel.compliance — preset application and validation."""

from __future__ import annotations

import pytest

from mcpkernel.compliance import (
    PRESET_NAMES,
    apply_preset,
    get_preset_description,
)
from mcpkernel.config import MCPKernelSettings


class TestCompliancePresets:
    def test_all_presets_apply(self):
        for name in PRESET_NAMES:
            settings = MCPKernelSettings()
            result = apply_preset(name, settings)
            assert result is settings  # modified in-place

    def test_hipaa_enables_full_taint(self):
        settings = MCPKernelSettings()
        apply_preset("hipaa", settings)
        assert settings.taint.mode == "full"
        assert settings.taint.block_on_violation is True
        assert settings.taint.pii_patterns_enabled is True
        assert settings.audit.enabled is True
        assert settings.audit.sign_entries is True

    def test_pci_dss_disables_network(self):
        settings = MCPKernelSettings()
        apply_preset("pci_dss", settings)
        assert settings.sandbox.network_enabled is False
        assert settings.auth.enabled is True
        assert settings.rate_limit.enabled is True

    def test_gdpr_aggressive_context(self):
        settings = MCPKernelSettings()
        apply_preset("gdpr", settings)
        assert settings.context.strategy == "aggressive"
        assert settings.context.max_context_tokens == 2048

    def test_fedramp_maximum_security(self):
        settings = MCPKernelSettings()
        apply_preset("fedramp", settings)
        assert settings.ebpf.enabled is True
        assert settings.dee.replay_on_drift is True
        assert settings.trust.anomaly_sigma == 2.0
        assert settings.policy.default_action == "deny"

    def test_soc2_observability(self):
        settings = MCPKernelSettings()
        apply_preset("soc2", settings)
        assert settings.observability.metrics_enabled is True
        assert settings.observability.tracing_enabled is True
        assert settings.auth.enabled is True

    def test_unknown_preset_raises(self):
        settings = MCPKernelSettings()
        with pytest.raises(ValueError, match="Unknown compliance preset"):
            apply_preset("nonexistent", settings)

    def test_case_insensitive(self):
        settings = MCPKernelSettings()
        apply_preset("HIPAA", settings)
        assert settings.taint.mode == "full"

    def test_get_preset_description(self):
        for name in PRESET_NAMES:
            desc = get_preset_description(name)
            assert len(desc) > 10
        assert "Unknown" in get_preset_description("bogus")

"""Tests for MCPKernelProxy Python API, protect() decorator, presets, and new CLI commands."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from mcpkernel.api import POLICY_PRESETS, MCPKernelProxy, protect
from mcpkernel.presets import get_preset_rules, list_presets

if TYPE_CHECKING:
    from pathlib import Path

# ── Preset tests ──────────────────────────────────────────────────────


class TestPresets:
    """Tests for built-in policy presets."""

    def test_list_presets_returns_all(self):
        result = list_presets()
        assert "permissive" in result
        assert "standard" in result
        assert "strict" in result

    def test_list_presets_descriptions(self):
        result = list_presets()
        for _name, desc in result.items():
            assert isinstance(desc, str)
            assert len(desc) > 5

    def test_get_preset_rules_permissive(self):
        rules = get_preset_rules("permissive")
        assert len(rules) >= 1
        assert all(r.id.startswith("perm-") for r in rules)

    def test_get_preset_rules_standard(self):
        rules = get_preset_rules("standard")
        assert len(rules) >= 3
        assert any(r.action.value == "deny" for r in rules)
        assert any(r.action.value == "audit" for r in rules)

    def test_get_preset_rules_strict(self):
        rules = get_preset_rules("strict")
        assert len(rules) >= 4
        deny_count = sum(1 for r in rules if r.action.value == "deny")
        assert deny_count >= 3

    def test_get_preset_rules_unknown_raises(self):
        with pytest.raises(ValueError, match="Unknown preset"):
            get_preset_rules("nonexistent")

    def test_get_preset_rules_returns_copies(self):
        rules1 = get_preset_rules("standard")
        rules2 = get_preset_rules("standard")
        assert rules1 is not rules2

    def test_policy_presets_dict_valid(self):
        for _name, info in POLICY_PRESETS.items():
            assert "default_action" in info
            assert "description" in info
            assert info["default_action"] in ("allow", "audit", "deny")


# ── MCPKernelProxy tests ─────────────────────────────────────────────


class TestMCPKernelProxyInit:
    """Tests for MCPKernelProxy construction."""

    def test_default_construction(self):
        proxy = MCPKernelProxy()
        assert proxy.started is False
        assert proxy.policy_preset == "standard"
        assert proxy.hooks == []
        assert proxy.tool_names == set()

    def test_custom_policy_preset(self):
        proxy = MCPKernelProxy(policy="strict")
        assert proxy.policy_preset == "strict"

    def test_custom_policy_path(self, tmp_path: Path):
        p = tmp_path / "custom.yaml"
        proxy = MCPKernelProxy(policy=p)
        assert proxy.policy_preset is None

    def test_custom_policy_string_path(self, tmp_path: Path):
        p = tmp_path / "custom.yaml"
        proxy = MCPKernelProxy(policy=str(p))
        assert proxy.policy_preset is None

    def test_feature_toggles(self):
        proxy = MCPKernelProxy(taint=False, audit=False, sandbox=True, context_pruning=True)
        assert proxy._taint_enabled is False
        assert proxy._audit_enabled is False
        assert proxy._sandbox_enabled is True
        assert proxy._context_pruning is True


class TestMCPKernelProxyLifecycle:
    """Tests for MCPKernelProxy start/stop lifecycle."""

    @pytest.mark.asyncio
    async def test_start_creates_pipeline(self):
        proxy = MCPKernelProxy(policy="permissive", taint=False, audit=False)
        await proxy.start()
        assert proxy.started is True
        assert len(proxy.hooks) >= 2  # at least policy + dee + observability
        await proxy.stop()
        assert proxy.started is False

    @pytest.mark.asyncio
    async def test_double_start_noop(self):
        proxy = MCPKernelProxy(policy="permissive", taint=False, audit=False)
        await proxy.start()
        pipeline_id = id(proxy._pipeline)
        await proxy.start()  # should be no-op
        assert id(proxy._pipeline) == pipeline_id
        await proxy.stop()

    @pytest.mark.asyncio
    async def test_double_stop_noop(self):
        proxy = MCPKernelProxy(policy="permissive", taint=False, audit=False)
        await proxy.start()
        await proxy.stop()
        await proxy.stop()  # should not raise

    @pytest.mark.asyncio
    async def test_async_context_manager(self):
        async with MCPKernelProxy(policy="permissive", taint=False, audit=False) as proxy:
            assert proxy.started is True
        assert proxy.started is False

    @pytest.mark.asyncio
    async def test_start_with_taint(self):
        proxy = MCPKernelProxy(policy="permissive", taint=True, audit=False)
        await proxy.start()
        assert "taint" in proxy.hooks
        await proxy.stop()

    @pytest.mark.asyncio
    async def test_start_with_audit(self):
        proxy = MCPKernelProxy(policy="permissive", taint=False, audit=True)
        await proxy.start()
        assert "audit" in proxy.hooks
        await proxy.stop()

    @pytest.mark.asyncio
    async def test_hooks_include_policy_dee_observability(self):
        proxy = MCPKernelProxy(policy="standard", taint=False, audit=False)
        await proxy.start()
        assert "policy" in proxy.hooks
        assert "dee" in proxy.hooks
        assert "observability" in proxy.hooks
        await proxy.stop()


class TestMCPKernelProxyCallTool:
    """Tests for MCPKernelProxy.call_tool."""

    @pytest.mark.asyncio
    async def test_call_tool_not_started_raises(self):
        proxy = MCPKernelProxy()
        with pytest.raises(RuntimeError, match="not started"):
            await proxy.call_tool("some_tool", {"arg": "val"})

    @pytest.mark.asyncio
    async def test_list_tools_not_started_raises(self):
        proxy = MCPKernelProxy()
        with pytest.raises(RuntimeError, match="not started"):
            await proxy.list_tools()


class TestMCPKernelProxyBuildSettings:
    """Tests for _build_settings config assembly."""

    def test_build_settings_standard_preset(self):
        proxy = MCPKernelProxy(policy="standard", host="127.0.0.1", port=9090)
        settings = proxy._build_settings()
        assert settings.proxy.host == "127.0.0.1"
        assert settings.proxy.port == 9090
        assert settings.policy.default_action == "audit"

    def test_build_settings_strict_preset(self):
        proxy = MCPKernelProxy(policy="strict")
        settings = proxy._build_settings()
        assert settings.policy.default_action == "deny"

    def test_build_settings_permissive_preset(self):
        proxy = MCPKernelProxy(policy="permissive")
        settings = proxy._build_settings()
        assert settings.policy.default_action == "allow"

    def test_build_settings_upstream_strings(self):
        proxy = MCPKernelProxy(upstream=["http://localhost:3000/mcp"])
        settings = proxy._build_settings()
        assert len(settings.upstream) == 1
        assert settings.upstream[0].url == "http://localhost:3000/mcp"

    def test_build_settings_taint_disabled(self):
        proxy = MCPKernelProxy(taint=False)
        settings = proxy._build_settings()
        assert settings.taint.mode == "off"


# ── protect() decorator tests ────────────────────────────────────────


class TestProtectDecorator:
    """Tests for the @protect decorator."""

    def test_protect_returns_callable(self):
        decorator = protect(policy="standard")
        assert callable(decorator)

    def test_protect_preserves_name(self):
        @protect(policy="standard")
        async def my_tool(x: int) -> int:
            return x * 2

        assert my_tool.__name__ == "my_tool"

    def test_protect_preserves_docstring(self):
        @protect(policy="standard")
        async def my_tool(x: int) -> int:
            """Double the input."""
            return x * 2

        assert my_tool.__doc__ == "Double the input."


# ── CLI tests ─────────────────────────────────────────────────────────


class TestCLIInit:
    """Tests for mcpkernel init command."""

    def test_init_creates_config_dir(self, tmp_path: Path):
        from typer.testing import CliRunner

        from mcpkernel.cli import app

        runner = CliRunner()
        result = runner.invoke(app, ["init", str(tmp_path)])
        assert result.exit_code == 0
        assert (tmp_path / ".mcpkernel" / "config.yaml").exists()
        assert (tmp_path / ".mcpkernel" / "policies").is_dir()

    def test_init_with_preset(self, tmp_path: Path):
        from typer.testing import CliRunner

        from mcpkernel.cli import app

        runner = CliRunner()
        result = runner.invoke(app, ["init", str(tmp_path), "--preset", "strict"])
        assert result.exit_code == 0
        config = (tmp_path / ".mcpkernel" / "config.yaml").read_text()
        assert "strict" in config
        assert "default_action: deny" in config

    def test_init_with_invalid_preset(self, tmp_path: Path):
        from typer.testing import CliRunner

        from mcpkernel.cli import app

        runner = CliRunner()
        result = runner.invoke(app, ["init", str(tmp_path), "--preset", "bogus"])
        assert result.exit_code == 1
        assert "Unknown preset" in result.output

    def test_init_with_permissive_preset(self, tmp_path: Path):
        from typer.testing import CliRunner

        from mcpkernel.cli import app

        runner = CliRunner()
        result = runner.invoke(app, ["init", str(tmp_path), "--preset", "permissive"])
        assert result.exit_code == 0
        config = (tmp_path / ".mcpkernel" / "config.yaml").read_text()
        assert "default_action: allow" in config


class TestCLIPresets:
    """Tests for mcpkernel presets command."""

    def test_presets_lists_all(self):
        from typer.testing import CliRunner

        from mcpkernel.cli import app

        runner = CliRunner()
        result = runner.invoke(app, ["presets"])
        assert result.exit_code == 0
        assert "permissive" in result.output
        assert "standard" in result.output
        assert "strict" in result.output


class TestCLIQuickstart:
    """Tests for mcpkernel quickstart command."""

    def test_quickstart_default(self):
        from typer.testing import CliRunner

        from mcpkernel.cli import app

        runner = CliRunner()
        result = runner.invoke(app, ["quickstart"])
        assert result.exit_code == 0
        assert "Quickstart" in result.output
        assert "hooks loaded" in result.output
        assert "Pipeline start/stop OK" in result.output

    def test_quickstart_strict(self):
        from typer.testing import CliRunner

        from mcpkernel.cli import app

        runner = CliRunner()
        result = runner.invoke(app, ["quickstart", "--preset", "strict"])
        assert result.exit_code == 0
        assert "strict" in result.output

    def test_quickstart_invalid_preset(self):
        from typer.testing import CliRunner

        from mcpkernel.cli import app

        runner = CliRunner()
        result = runner.invoke(app, ["quickstart", "--preset", "bogus"])
        assert result.exit_code == 1


class TestCLIStatus:
    """Tests for mcpkernel status command."""

    def test_status_with_config(self, tmp_path: Path):
        from typer.testing import CliRunner

        from mcpkernel.cli import app

        # Create a config file first
        config_file = tmp_path / "config.yaml"
        config_file.write_text("proxy:\n  host: 127.0.0.1\n  port: 9090\npolicy:\n  default_action: deny\n")

        runner = CliRunner()
        result = runner.invoke(app, ["status", "--config", str(config_file)])
        assert result.exit_code == 0
        assert "127.0.0.1:9090" in result.output
        assert "deny" in result.output


class TestCLIVersion:
    """Tests for mcpkernel version command."""

    def test_version_output(self):
        from typer.testing import CliRunner

        from mcpkernel.cli import app

        runner = CliRunner()
        result = runner.invoke(app, ["version"])
        assert result.exit_code == 0
        assert "0.1.2" in result.output


# ── Import tests ──────────────────────────────────────────────────────


class TestImports:
    """Tests that the public API is importable from the top-level package."""

    def test_import_mcpkernel_proxy(self):
        from mcpkernel import MCPKernelProxy

        assert MCPKernelProxy is not None

    def test_import_protect(self):
        from mcpkernel import protect

        assert protect is not None

    def test_import_policy_presets(self):
        from mcpkernel import POLICY_PRESETS

        assert isinstance(POLICY_PRESETS, dict)
        assert "standard" in POLICY_PRESETS

    def test_import_version(self):
        from mcpkernel import __version__

        assert __version__ == "0.1.2"

    def test_import_errors(self):
        from mcpkernel import (
            AuthError,
            MCPKernelError,
            PolicyViolation,
        )

        assert issubclass(PolicyViolation, MCPKernelError)
        assert issubclass(AuthError, MCPKernelError)


# ── SPEC-001: Regex patterns in presets (PolicyEngine + preset rules) ─


class TestPresetPolicyEngineIntegration:
    """Tests that preset rules behave correctly inside PolicyEngine."""

    def test_standard_denies_execute_code(self):
        """SPEC-001: standard preset DENY for execute_code."""
        from mcpkernel.policy.engine import PolicyAction, PolicyEngine

        engine = PolicyEngine(default_action=PolicyAction.ALLOW)
        engine.add_rules(get_preset_rules("standard"))
        decision = engine.evaluate("execute_code", {})
        assert decision.action == PolicyAction.DENY
        assert decision.allowed is False

    def test_standard_denies_shell_exec(self):
        """SPEC-001: standard preset DENY for shell_exec."""
        from mcpkernel.policy.engine import PolicyAction, PolicyEngine

        engine = PolicyEngine(default_action=PolicyAction.ALLOW)
        engine.add_rules(get_preset_rules("standard"))
        decision = engine.evaluate("shell_exec", {})
        assert decision.action == PolicyAction.DENY
        assert decision.allowed is False

    def test_standard_audits_safe_read(self):
        """SPEC-001: standard preset AUDIT for safe_read."""
        from mcpkernel.policy.engine import PolicyAction, PolicyEngine

        engine = PolicyEngine(default_action=PolicyAction.ALLOW)
        engine.add_rules(get_preset_rules("standard"))
        decision = engine.evaluate("safe_read", {})
        assert decision.action == PolicyAction.AUDIT

    def test_permissive_audits_any_tool(self):
        """SPEC-001: permissive preset AUDIT for any tool."""
        from mcpkernel.policy.engine import PolicyAction, PolicyEngine

        engine = PolicyEngine(default_action=PolicyAction.ALLOW)
        engine.add_rules(get_preset_rules("permissive"))
        decision = engine.evaluate("literally_anything", {})
        assert decision.action == PolicyAction.AUDIT

    def test_strict_denies_fetch_data(self):
        """SPEC-001: strict preset DENY for fetch_data (network)."""
        from mcpkernel.policy.engine import PolicyAction, PolicyEngine

        engine = PolicyEngine(default_action=PolicyAction.ALLOW)
        engine.add_rules(get_preset_rules("strict"))
        decision = engine.evaluate("fetch_data", {})
        assert decision.action == PolicyAction.DENY
        assert decision.allowed is False


# ── SPEC-002: PolicyViolation constructor ────────────────────────────


class TestPolicyViolation:
    """Tests for PolicyViolation error class."""

    def test_constructor_positional_args(self):
        """SPEC-002: PolicyViolation('rule-id', 'message') works."""
        from mcpkernel.utils import PolicyViolation

        err = PolicyViolation("rule-id", "blocked by policy")
        assert err.rule_id == "rule-id"
        assert "blocked by policy" in str(err)

    def test_has_rule_id_and_message_attrs(self):
        """SPEC-002: PolicyViolation has rule_id attribute and string repr."""
        from mcpkernel.utils import PolicyViolation

        err = PolicyViolation("test-rule-42", "not allowed")
        assert err.rule_id == "test-rule-42"
        assert "[test-rule-42]" in str(err)
        assert "not allowed" in str(err)


# ── SPEC-003: Preset rules loaded into engine on start() ────────────


class TestPresetRulesOnStart:
    """Tests that start() loads preset rules into _policy_engine."""

    @pytest.mark.asyncio
    async def test_standard_preset_loads_std_rules(self):
        """SPEC-003: start() with standard → rules with 'std-' prefix."""
        proxy = MCPKernelProxy(policy="standard", taint=False, audit=False)
        await proxy.start()
        try:
            assert proxy._policy_engine is not None
            rule_ids = [r.id for r in proxy._policy_engine._rules]
            assert any(rid.startswith("std-") for rid in rule_ids)
        finally:
            await proxy.stop()

    @pytest.mark.asyncio
    async def test_strict_preset_loads_strict_rules(self):
        """SPEC-003: start() with strict → rules with 'strict-' prefix."""
        proxy = MCPKernelProxy(policy="strict", taint=False, audit=False)
        await proxy.start()
        try:
            assert proxy._policy_engine is not None
            rule_ids = [r.id for r in proxy._policy_engine._rules]
            assert any(rid.startswith("strict-") for rid in rule_ids)
        finally:
            await proxy.stop()

    @pytest.mark.asyncio
    async def test_permissive_preset_loads_perm_rules(self):
        """SPEC-003: start() with permissive → rule 'perm-audit-all'."""
        proxy = MCPKernelProxy(policy="permissive", taint=False, audit=False)
        await proxy.start()
        try:
            assert proxy._policy_engine is not None
            rule_ids = [r.id for r in proxy._policy_engine._rules]
            assert "perm-audit-all" in rule_ids
        finally:
            await proxy.stop()


# ── SPEC-004: Clear default policy_paths ─────────────────────────────


class TestBuildSettingsPolicyPaths:
    """Tests that _build_settings returns empty policy_paths for presets."""

    def test_permissive_has_empty_policy_paths(self):
        """SPEC-004: permissive preset → empty policy_paths."""
        proxy = MCPKernelProxy(policy="permissive")
        settings = proxy._build_settings()
        assert settings.policy.policy_paths == []

    def test_standard_has_empty_policy_paths(self):
        """SPEC-004: standard preset → empty policy_paths."""
        proxy = MCPKernelProxy(policy="standard")
        settings = proxy._build_settings()
        assert settings.policy.policy_paths == []


# ── SPEC-005: owasp-asi-2026 error message ───────────────────────────


class TestOwaspPresetError:
    """Tests for owasp-asi-2026 preset error handling."""

    def test_owasp_preset_raises_with_file_based_message(self):
        """SPEC-005: get_preset_rules('owasp-asi-2026') → ValueError with 'file-based'."""
        with pytest.raises(ValueError, match="file-based"):
            get_preset_rules("owasp-asi-2026")


# ── SPEC-006: Sync function support in protect() ────────────────────


class TestProtectSyncFunction:
    """Tests for @protect() on synchronous functions."""

    @pytest.mark.asyncio
    async def test_protect_wraps_sync_function(self):
        """SPEC-006: @protect() works on a sync function called from async."""

        @protect(policy="permissive", taint=False, audit=False)
        def add_numbers(a: int, b: int) -> int:
            return a + b

        result = await add_numbers(3, 4)
        assert result == 7


# ── SPEC-009: No exec() in docstring ─────────────────────────────────


class TestNoExecInSource:
    """Tests that api.py does not contain exec(code) patterns."""

    def test_no_exec_code_in_api_source(self):
        """SPEC-009: 'exec(code)' must NOT appear in api.py source."""
        import inspect

        import mcpkernel.api as api_mod

        source = inspect.getsource(api_mod)
        assert "exec(code)" not in source


# ── SPEC-010: argument_patterns in export ────────────────────────────


class TestExportRules:
    """Tests for _export_rules_yaml including argument_patterns."""

    def test_export_includes_argument_patterns(self, tmp_path: Path):
        """SPEC-010: _export_rules_yaml output includes argument_patterns."""
        import yaml

        from mcpkernel.cli import _export_rules_yaml
        from mcpkernel.policy.engine import PolicyAction, PolicyRule

        rules = [
            PolicyRule(
                id="test-rule",
                name="Test",
                description="A test rule",
                action=PolicyAction.DENY,
                tool_patterns=["foo.*"],
                argument_patterns={"path": r"^/etc/.*"},
            ),
        ]
        out = tmp_path / "export.yaml"
        _export_rules_yaml(rules, out)

        data = yaml.safe_load(out.read_text())
        exported_rule = data["rules"][0]
        assert "argument_patterns" in exported_rule
        assert exported_rule["argument_patterns"] == {"path": r"^/etc/.*"}

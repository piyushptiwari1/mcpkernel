"""Tests for MCPKernel doctor diagnostics."""

from __future__ import annotations

import os
from unittest.mock import patch

import pytest

from mcpkernel.integrations.doctor import (
    _check_dependencies,
    _check_env_secrets,
    _check_permissions,
    _check_python,
    _check_tools_available,
    _format_report,
    run_diagnostics,
)


class TestCheckPython:
    """Tests for Python version checking."""

    def test_returns_checks(self) -> None:
        checks = _check_python()
        assert len(checks) >= 1
        assert checks[0]["name"] == "Python version"
        # We're running on 3.12+, so should pass
        assert checks[0]["status"] == "pass"

    def test_version_in_detail(self) -> None:
        checks = _check_python()
        assert "Python" in checks[0]["detail"]


class TestCheckDependencies:
    """Tests for dependency checking."""

    def test_mcpkernel_importable(self) -> None:
        checks = _check_dependencies()
        mcpkernel_check = [c for c in checks if "mcpkernel" in c["name"].lower()]
        assert len(mcpkernel_check) >= 1
        assert mcpkernel_check[0]["status"] == "pass"

    def test_returns_multiple_checks(self) -> None:
        checks = _check_dependencies()
        # Should check both required and optional deps
        assert len(checks) >= 5


class TestCheckEnvSecrets:
    """Tests for exposed secret detection."""

    def test_no_secrets_by_default(self) -> None:
        # Clear any suspicious env vars for the test
        clean_env = {
            k: v
            for k, v in os.environ.items()
            if k not in ("OPENAI_API_KEY", "ANTHROPIC_API_KEY", "AWS_SECRET_ACCESS_KEY")
        }
        with patch.dict(os.environ, clean_env, clear=True):
            checks = _check_env_secrets()
            # Should have a pass or no warn entries
            assert not any(c["status"] == "fail" for c in checks)

    def test_detects_exposed_key(self) -> None:
        with patch.dict(os.environ, {"OPENAI_API_KEY": "sk-realkey12345678901234567890"}):
            checks = _check_env_secrets()
            warns = [c for c in checks if c["status"] == "warn"]
            assert len(warns) >= 1
            assert any("OPENAI_API_KEY" in c["name"] for c in warns)

    def test_ignores_placeholder_values(self) -> None:
        with patch.dict(os.environ, {"OPENAI_API_KEY": "test"}):
            checks = _check_env_secrets()
            warns = [c for c in checks if c["status"] == "warn" and "OPENAI_API_KEY" in c["name"]]
            assert len(warns) == 0


class TestCheckToolsAvailable:
    """Tests for external tool availability check."""

    def test_returns_checks(self) -> None:
        checks = _check_tools_available()
        assert len(checks) >= 1
        # All should be either pass or info
        assert all(c["status"] in ("pass", "info") for c in checks)


class TestCheckPermissions:
    """Tests for file permission checking."""

    def test_returns_list(self) -> None:
        checks = _check_permissions()
        # Should be a list (possibly empty if no config exists)
        assert isinstance(checks, list)


class TestFormatReport:
    """Tests for report formatting."""

    def test_formats_passes(self) -> None:
        checks = [{"name": "Test", "status": "pass", "detail": "OK"}]
        report = _format_report(checks)
        assert "[PASS]" in report
        assert "Test" in report

    def test_formats_failures(self) -> None:
        checks = [{"name": "Bad", "status": "fail", "detail": "Missing"}]
        report = _format_report(checks)
        assert "[FAIL]" in report

    def test_formats_warnings(self) -> None:
        checks = [{"name": "Meh", "status": "warn", "detail": "Careful"}]
        report = _format_report(checks)
        assert "[WARN]" in report

    def test_includes_header(self) -> None:
        report = _format_report([])
        assert "MCPKernel Doctor" in report


class TestRunDiagnostics:
    """Tests for the full diagnostics runner."""

    @pytest.mark.asyncio
    async def test_returns_string(self) -> None:
        report = await run_diagnostics()
        assert isinstance(report, str)
        assert "MCPKernel Doctor" in report

    @pytest.mark.asyncio
    async def test_includes_python_check(self) -> None:
        report = await run_diagnostics()
        assert "Python" in report

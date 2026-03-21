"""Tests for mcpguard.config — settings loading and validation."""

import os
from pathlib import Path

import pytest

from mcpguard.config import (
    MCPGuardSettings,
    SandboxBackend,
    TaintMode,
    LogLevel,
    load_config,
)


class TestDefaultConfig:
    def test_default_values(self):
        settings = MCPGuardSettings()
        assert settings.proxy.host == "127.0.0.1"
        assert settings.proxy.port == 8080
        assert settings.sandbox.backend == SandboxBackend.DOCKER
        assert settings.taint.mode == TaintMode.LIGHT

    def test_sandbox_backends(self):
        for backend in SandboxBackend:
            assert backend.value in ("docker", "firecracker", "wasm", "microsandbox")

    def test_taint_modes(self):
        for mode in TaintMode:
            assert mode.value in ("full", "light", "off")


class TestConfigLoading:
    def test_load_default(self):
        settings = load_config()
        assert isinstance(settings, MCPGuardSettings)

    def test_load_from_yaml(self, tmp_path: Path):
        config_file = tmp_path / "test_config.yaml"
        config_file.write_text(
            "proxy:\n"
            "  host: 0.0.0.0\n"
            "  port: 9000\n"
            "sandbox:\n"
            "  backend: wasm\n"
        )
        settings = load_config(config_path=str(config_file))
        assert settings.proxy.host == "0.0.0.0"
        assert settings.proxy.port == 9000
        assert settings.sandbox.backend == SandboxBackend.WASM

    def test_env_override(self, monkeypatch):
        monkeypatch.setenv("MCPGUARD_PROXY__PORT", "7777")
        settings = load_config()
        assert settings.proxy.port == 7777


class TestConfigValidation:
    def test_valid_log_levels(self):
        settings = MCPGuardSettings()
        assert settings.observability.log_level in (LogLevel.DEBUG, LogLevel.INFO, LogLevel.WARNING, LogLevel.ERROR)

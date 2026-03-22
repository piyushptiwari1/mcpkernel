"""Tests for mcpkernel.config — settings loading and validation."""

from pathlib import Path

from mcpkernel.config import (
    LogLevel,
    MCPKernelSettings,
    SandboxBackend,
    TaintMode,
    load_config,
)


class TestDefaultConfig:
    def test_default_values(self):
        settings = MCPKernelSettings()
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
        assert isinstance(settings, MCPKernelSettings)

    def test_load_from_yaml(self, tmp_path: Path):
        config_file = tmp_path / "test_config.yaml"
        config_file.write_text("proxy:\n  host: 0.0.0.0\n  port: 9000\nsandbox:\n  backend: wasm\n")
        settings = load_config(config_path=str(config_file))
        assert settings.proxy.host == "0.0.0.0"  # noqa: S104
        assert settings.proxy.port == 9000
        assert settings.sandbox.backend == SandboxBackend.WASM

    def test_env_override(self, monkeypatch):
        monkeypatch.setenv("MCPKERNEL_PROXY__PORT", "7777")
        settings = load_config()
        assert settings.proxy.port == 7777


class TestConfigValidation:
    def test_valid_log_levels(self):
        settings = MCPKernelSettings()
        assert settings.observability.log_level in (LogLevel.DEBUG, LogLevel.INFO, LogLevel.WARNING, LogLevel.ERROR)

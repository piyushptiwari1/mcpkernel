"""Hierarchical configuration with Pydantic v2 settings.

Load order (last wins): defaults → YAML file → environment variables → CLI overrides.
"""

from __future__ import annotations

from enum import StrEnum
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------
class SandboxBackend(StrEnum):
    DOCKER = "docker"
    FIRECRACKER = "firecracker"
    WASM = "wasm"
    MICROSANDBOX = "microsandbox"


class TaintMode(StrEnum):
    FULL = "full"
    LIGHT = "light"
    OFF = "off"


class LogLevel(StrEnum):
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"


class PruningStrategy(StrEnum):
    AGGRESSIVE = "aggressive"
    MODERATE = "moderate"
    CONSERVATIVE = "conservative"


# ---------------------------------------------------------------------------
# Sub-models
# ---------------------------------------------------------------------------
class ProxyConfig(BaseModel):
    """Proxy gateway settings."""

    host: str = "127.0.0.1"
    port: int = Field(default=8080, ge=1, le=65535)
    workers: int = Field(default=1, ge=1)
    tls_cert: Path | None = None
    tls_key: Path | None = None
    cors_origins: list[str] = Field(default_factory=lambda: ["*"])
    max_request_size_bytes: int = Field(default=10 * 1024 * 1024, ge=1024)


class AuthConfig(BaseModel):
    """Authentication settings."""

    enabled: bool = False
    api_keys: list[str] = Field(default_factory=list)
    oauth2_jwks_url: str | None = None
    oauth2_issuer: str | None = None
    oauth2_audience: str | None = None
    mtls_ca_cert: Path | None = None


class RateLimitConfig(BaseModel):
    """Rate limiting settings."""

    enabled: bool = False
    requests_per_minute: int = Field(default=60, ge=1)
    burst_size: int = Field(default=10, ge=1)
    redis_url: str | None = None


class SandboxConfig(BaseModel):
    """Sandbox execution backend settings."""

    backend: SandboxBackend = SandboxBackend.DOCKER
    default_timeout_seconds: int = Field(default=30, ge=1)
    max_cpu_cores: float = Field(default=1.0, gt=0)
    max_memory_mb: int = Field(default=256, ge=64)
    max_disk_mb: int = Field(default=512, ge=64)
    network_enabled: bool = False
    allowed_egress_domains: list[str] = Field(default_factory=list)
    docker_image: str = "python:3.12-slim"
    firecracker_kernel_path: Path | None = None
    firecracker_rootfs_path: Path | None = None


class DEEConfig(BaseModel):
    """Deterministic Execution Envelope settings."""

    enabled: bool = True
    store_path: Path = Path("dee_store/traces.db")
    sign_traces: bool = True
    replay_on_drift: bool = False


class TaintConfig(BaseModel):
    """Taint tracking settings."""

    mode: TaintMode = TaintMode.LIGHT
    block_on_violation: bool = True
    pii_patterns_enabled: bool = True
    static_analysis_enabled: bool = True
    custom_sources: list[str] = Field(default_factory=list)
    custom_sinks: list[str] = Field(default_factory=list)


class ContextConfig(BaseModel):
    """Context minimization settings."""

    enabled: bool = True
    strategy: PruningStrategy = PruningStrategy.MODERATE
    max_context_tokens: int = Field(default=4096, ge=128)


class EBPFConfig(BaseModel):
    """eBPF kernel interceptor settings."""

    enabled: bool = False
    redirect_ports: list[int] = Field(default_factory=lambda: [8080])
    monitored_syscalls: list[str] = Field(default_factory=lambda: ["connect", "sendto", "open", "write", "execve"])


class PolicyConfig(BaseModel):
    """Policy engine settings."""

    policy_paths: list[Path] = Field(default_factory=lambda: [Path("policies/owasp_asi_2026_strict.yaml")])
    hot_reload: bool = True
    default_action: str = "deny"


class ObservabilityConfig(BaseModel):
    """Observability and metrics settings."""

    metrics_enabled: bool = True
    metrics_port: int = Field(default=9090, ge=1, le=65535)
    tracing_enabled: bool = True
    otlp_endpoint: str = "http://localhost:4317"
    log_level: LogLevel = LogLevel.INFO
    json_logs: bool = True


class AuditConfig(BaseModel):
    """Audit and compliance settings."""

    enabled: bool = True
    log_path: Path = Path("dee_store/audit.jsonl")
    sign_entries: bool = True
    export_format: str = "json"


# ---------------------------------------------------------------------------
# Root settings
# ---------------------------------------------------------------------------
class MCPGuardSettings(BaseSettings):
    """Root configuration for mcpguard.

    Values are loaded from (last wins):
    1. Field defaults
    2. YAML config file (``config_path``)
    3. Environment variables prefixed ``MCPGUARD_``
    4. CLI overrides (applied programmatically)
    """

    model_config = SettingsConfigDict(
        env_prefix="MCPGUARD_",
        env_nested_delimiter="__",
        case_sensitive=False,
    )

    config_path: Path | None = Field(default=None, description="Path to YAML config file")

    proxy: ProxyConfig = Field(default_factory=ProxyConfig)
    auth: AuthConfig = Field(default_factory=AuthConfig)
    rate_limit: RateLimitConfig = Field(default_factory=RateLimitConfig)
    sandbox: SandboxConfig = Field(default_factory=SandboxConfig)
    dee: DEEConfig = Field(default_factory=DEEConfig)
    taint: TaintConfig = Field(default_factory=TaintConfig)
    context: ContextConfig = Field(default_factory=ContextConfig)
    ebpf: EBPFConfig = Field(default_factory=EBPFConfig)
    policy: PolicyConfig = Field(default_factory=PolicyConfig)
    observability: ObservabilityConfig = Field(default_factory=ObservabilityConfig)
    audit: AuditConfig = Field(default_factory=AuditConfig)

    @field_validator("config_path", mode="before")
    @classmethod
    def _resolve_config_path(cls, v: Any) -> Path | None:
        if v is None:
            return None
        p = Path(v)
        if not p.exists():
            from mcpguard.utils import ConfigError

            raise ConfigError(f"Config file not found: {p}")
        return p

    def model_post_init(self, __context: Any) -> None:
        """Merge YAML config file values after env-var resolution."""
        if self.config_path is not None:
            yaml_data = _load_yaml(self.config_path)
            if yaml_data:
                _deep_merge(self, yaml_data)


# ---------------------------------------------------------------------------
# YAML loading helpers
# ---------------------------------------------------------------------------
def _load_yaml(path: Path) -> dict[str, Any]:
    """Read and parse a YAML config file."""
    with open(path, encoding="utf-8") as fh:
        data = yaml.safe_load(fh)
    if not isinstance(data, dict):
        return {}
    return data


def _deep_merge(settings: MCPGuardSettings, overrides: dict[str, Any]) -> None:
    """Apply *overrides* from YAML onto existing *settings* in-place."""
    for section_key, section_val in overrides.items():
        if not isinstance(section_val, dict):
            continue
        current = getattr(settings, section_key, None)
        if current is None:
            continue
        for k, v in section_val.items():
            if hasattr(current, k):
                setattr(current, k, v)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------
_settings: MCPGuardSettings | None = None


def load_config(
    config_path: Path | None = None,
    overrides: dict[str, Any] | None = None,
) -> MCPGuardSettings:
    """Load and return the global settings singleton.

    Parameters
    ----------
    config_path:
        Optional YAML file to merge.
    overrides:
        Dict of programmatic overrides (e.g. from CLI).
    """
    global _settings
    kwargs: dict[str, Any] = {}
    if config_path is not None:
        kwargs["config_path"] = config_path
    _settings = MCPGuardSettings(**kwargs)
    if overrides:
        _deep_merge(_settings, overrides)
    return _settings


def get_config() -> MCPGuardSettings:
    """Return the current settings singleton, loading defaults if needed."""
    global _settings
    if _settings is None:
        _settings = MCPGuardSettings()
    return _settings

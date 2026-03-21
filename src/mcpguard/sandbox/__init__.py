"""Pluggable sandbox execution backends."""

from mcpguard.sandbox.base import ResourceLimits, SandboxBackend, SandboxMetrics, SnapshotInfo, Workspace

__all__ = [
    "ResourceLimits",
    "SandboxBackend",
    "SandboxMetrics",
    "SnapshotInfo",
    "Workspace",
    "create_backend",
]


def create_backend(config: object) -> SandboxBackend:
    """Factory: instantiate the correct sandbox backend from config."""
    from mcpguard.config import SandboxBackend as SBEnum
    from mcpguard.config import SandboxConfig

    if not isinstance(config, SandboxConfig):
        raise TypeError(f"Expected SandboxConfig, got {type(config)}")

    match config.backend:
        case SBEnum.DOCKER:
            from mcpguard.sandbox.docker_backend import DockerSandbox

            return DockerSandbox(config)
        case SBEnum.FIRECRACKER:
            from mcpguard.sandbox.firecracker_backend import FirecrackerSandbox

            return FirecrackerSandbox(config)
        case SBEnum.WASM:
            from mcpguard.sandbox.wasm_backend import WASMSandbox

            return WASMSandbox(config)
        case SBEnum.MICROSANDBOX:
            from mcpguard.sandbox.microsandbox_backend import MicrosandboxSandbox

            return MicrosandboxSandbox(config)
        case _:
            raise ValueError(f"Unknown sandbox backend: {config.backend}")

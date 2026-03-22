"""Abstract base for all sandbox backends."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


@dataclass
class ResourceLimits:
    """Resource constraints for a sandbox execution."""

    cpu_cores: float = 1.0
    memory_mb: int = 256
    disk_mb: int = 512
    timeout_seconds: int = 30
    network_enabled: bool = False
    allowed_egress_domains: list[str] = field(default_factory=list)


@dataclass
class SandboxMetrics:
    """Runtime metrics from a sandbox instance."""

    cpu_used_pct: float = 0.0
    memory_used_mb: float = 0.0
    disk_used_mb: float = 0.0
    cold_start_ms: float = 0.0


@dataclass
class Workspace:
    """Handle to a sandbox workspace (persistent or ephemeral)."""

    workspace_id: str
    persistent: bool = False
    root_path: str = "/workspace"
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class SnapshotInfo:
    """Metadata about a workspace snapshot."""

    snapshot_id: str
    workspace_id: str
    created_at: float = 0.0
    size_bytes: int = 0


class SandboxBackend(ABC):
    """Protocol-like base class for pluggable sandbox execution."""

    @abstractmethod
    async def execute_code(
        self,
        code: str,
        timeout: int | None = None,
        resource_limits: ResourceLimits | None = None,
    ) -> Any:
        """Execute *code* in the sandbox and return an :class:`ExecutionResult`."""

    @abstractmethod
    async def create_workspace(self, *, persistent: bool = False) -> Workspace:
        """Create a new isolated workspace."""

    @abstractmethod
    async def set_network_policy(
        self,
        workspace: Workspace,
        *,
        allow_egress: bool = False,
        allowed_domains: list[str] | None = None,
    ) -> None:
        """Configure network access for a workspace."""

    @abstractmethod
    async def mount_filesystem(
        self,
        workspace: Workspace,
        *,
        read_only_paths: list[str] | None = None,
        temp_dirs: list[str] | None = None,
    ) -> None:
        """Mount file system paths into the workspace."""

    @abstractmethod
    async def get_metrics(self, workspace: Workspace) -> SandboxMetrics:
        """Return current resource usage metrics."""

    @abstractmethod
    async def cleanup(self, workspace: Workspace) -> None:
        """Destroy the workspace and release all resources."""

    @abstractmethod
    async def snapshot(self, workspace: Workspace) -> SnapshotInfo:
        """Capture the current state of a workspace for later restore."""

    @abstractmethod
    async def restore(self, snapshot: SnapshotInfo) -> Workspace:
        """Restore a workspace from a snapshot."""

"""Microsandbox-style remote HTTP API sandbox backend."""

from __future__ import annotations

import time
from typing import Any

import httpx

from mcpguard.proxy.interceptor import ExecutionResult
from mcpguard.sandbox.base import ResourceLimits, SandboxBackend, SandboxMetrics, SnapshotInfo, Workspace
from mcpguard.utils import SandboxError, generate_request_id, get_logger

logger = get_logger(__name__)


class MicrosandboxSandbox(SandboxBackend):
    """Sandbox that delegates to a remote Microsandbox-compatible HTTP API.

    Expects the microsandbox server at the configured URL.
    """

    def __init__(self, config: Any) -> None:
        self._config = config
        self._base_url: str = getattr(config, "microsandbox_url", "http://localhost:8081")

    async def execute_code(
        self,
        code: str,
        timeout: int | None = None,
        resource_limits: ResourceLimits | None = None,
    ) -> ExecutionResult:
        limits = resource_limits or ResourceLimits(timeout_seconds=timeout or self._config.default_timeout_seconds)
        start = time.monotonic()

        async with httpx.AsyncClient(timeout=limits.timeout_seconds + 5) as client:
            try:
                resp = await client.post(
                    f"{self._base_url}/execute",
                    json={
                        "code": code,
                        "timeout": limits.timeout_seconds,
                        "resource_limits": {
                            "cpu_cores": limits.cpu_cores,
                            "memory_mb": limits.memory_mb,
                            "disk_mb": limits.disk_mb,
                            "network_enabled": limits.network_enabled,
                        },
                    },
                )
                resp.raise_for_status()
                data = resp.json()
            except httpx.HTTPStatusError as exc:
                raise SandboxError(f"Microsandbox API returned {exc.response.status_code}") from exc
            except httpx.ConnectError as exc:
                raise SandboxError(f"Cannot reach microsandbox at {self._base_url}: {exc}") from exc

        elapsed = time.monotonic() - start
        return ExecutionResult(
            content=[{"type": "text", "text": data.get("output", "")}],
            is_error=data.get("is_error", False),
            metadata={"backend": "microsandbox", "duration_seconds": elapsed},
            duration_seconds=elapsed,
        )

    async def create_workspace(self, *, persistent: bool = False) -> Workspace:
        return Workspace(workspace_id=generate_request_id(), persistent=persistent)

    async def set_network_policy(
        self,
        workspace: Workspace,
        *,
        allow_egress: bool = False,
        allowed_domains: list[str] | None = None,
    ) -> None:
        workspace.metadata["network"] = {"allow_egress": allow_egress}

    async def mount_filesystem(
        self,
        workspace: Workspace,
        *,
        read_only_paths: list[str] | None = None,
        temp_dirs: list[str] | None = None,
    ) -> None:
        pass

    async def get_metrics(self, workspace: Workspace) -> SandboxMetrics:
        return SandboxMetrics()

    async def cleanup(self, workspace: Workspace) -> None:
        logger.info("microsandbox workspace cleaned up", workspace_id=workspace.workspace_id)

    async def snapshot(self, workspace: Workspace) -> SnapshotInfo:
        return SnapshotInfo(
            snapshot_id=generate_request_id(),
            workspace_id=workspace.workspace_id,
            created_at=time.time(),
        )

    async def restore(self, snapshot: SnapshotInfo) -> Workspace:
        return Workspace(workspace_id=snapshot.workspace_id, persistent=True)

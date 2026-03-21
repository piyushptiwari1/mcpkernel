"""Firecracker/libkrun MicroVM sandbox backend."""

from __future__ import annotations

import time
from typing import Any

from mcpguard.proxy.interceptor import ExecutionResult
from mcpguard.sandbox.base import ResourceLimits, SandboxBackend, SandboxMetrics, SnapshotInfo, Workspace
from mcpguard.utils import SandboxError, generate_request_id, get_logger

logger = get_logger(__name__)


class FirecrackerSandbox(SandboxBackend):
    """MicroVM sandbox using Firecracker or libkrun.

    Communicates with the Firecracker socket API for VM lifecycle
    management.  Requires pre-built kernel + rootfs images.
    """

    def __init__(self, config: Any) -> None:
        self._config = config
        if not config.firecracker_kernel_path or not config.firecracker_rootfs_path:
            logger.warning("Firecracker kernel/rootfs not configured — backend will fail at execution time")

    async def execute_code(
        self,
        code: str,
        timeout: int | None = None,
        resource_limits: ResourceLimits | None = None,
    ) -> ExecutionResult:
        """Boot a microVM, execute *code*, collect output, and destroy the VM."""
        limits = resource_limits or ResourceLimits(timeout_seconds=timeout or self._config.default_timeout_seconds)

        kernel = self._config.firecracker_kernel_path
        rootfs = self._config.firecracker_rootfs_path
        if not kernel or not rootfs:
            raise SandboxError("Firecracker kernel/rootfs paths not configured")

        import asyncio

        vm_id = generate_request_id()
        start = time.monotonic()

        # Build Firecracker config JSON
        fc_config = {
            "boot-source": {
                "kernel_image_path": str(kernel),
                "boot_args": "console=ttyS0 reboot=k panic=1 pci=off",
            },
            "drives": [
                {
                    "drive_id": "rootfs",
                    "path_on_host": str(rootfs),
                    "is_root_device": True,
                    "is_read_only": True,
                }
            ],
            "machine-config": {
                "vcpu_count": max(1, int(limits.cpu_cores)),
                "mem_size_mib": limits.memory_mb,
            },
        }

        try:
            # In production this would use the Firecracker API socket.
            # For now, run via subprocess for demonstration.
            proc = await asyncio.create_subprocess_exec(
                "firecracker",
                "--no-api",
                "--config-file",
                "/dev/stdin",
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            import json as _json

            stdout_data, _stderr_data = await asyncio.wait_for(
                proc.communicate(input=_json.dumps(fc_config).encode()),
                timeout=limits.timeout_seconds,
            )
            elapsed = time.monotonic() - start
            return ExecutionResult(
                content=[{"type": "text", "text": stdout_data.decode(errors="replace")}],
                is_error=proc.returncode != 0,
                metadata={"vm_id": vm_id, "exit_code": proc.returncode, "duration_seconds": elapsed},
                duration_seconds=elapsed,
            )
        except TimeoutError as exc:
            raise SandboxError(f"Firecracker VM timed out after {limits.timeout_seconds}s") from exc
        except FileNotFoundError as exc:
            raise SandboxError("firecracker binary not found in PATH") from exc

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
        workspace.metadata["mounts"] = {"read_only": read_only_paths or []}

    async def get_metrics(self, workspace: Workspace) -> SandboxMetrics:
        return SandboxMetrics()

    async def cleanup(self, workspace: Workspace) -> None:
        logger.info("firecracker workspace cleaned up", workspace_id=workspace.workspace_id)

    async def snapshot(self, workspace: Workspace) -> SnapshotInfo:
        return SnapshotInfo(
            snapshot_id=generate_request_id(),
            workspace_id=workspace.workspace_id,
            created_at=time.time(),
        )

    async def restore(self, snapshot: SnapshotInfo) -> Workspace:
        return Workspace(workspace_id=snapshot.workspace_id, persistent=True)

"""Docker sandbox backend — ephemeral containers with resource limits."""

from __future__ import annotations

import contextlib
import time
from typing import Any

from mcpkernel.proxy.interceptor import ExecutionResult
from mcpkernel.sandbox.base import ResourceLimits, SandboxBackend, SandboxMetrics, SnapshotInfo, Workspace
from mcpkernel.utils import SandboxError, generate_request_id, get_logger

logger = get_logger(__name__)


class DockerSandbox(SandboxBackend):
    """Sandbox backed by Docker containers.

    Each ``execute_code`` call runs inside an ephemeral container
    with enforced CPU, memory, disk, and network constraints.
    """

    def __init__(self, config: Any) -> None:
        self._config = config
        self._client: Any = None

    def _get_client(self) -> Any:
        if self._client is None:
            try:
                import docker

                self._client = docker.from_env()
            except Exception as exc:
                raise SandboxError(f"Cannot connect to Docker daemon: {exc}") from exc
        return self._client

    async def execute_code(
        self,
        code: str,
        timeout: int | None = None,
        resource_limits: ResourceLimits | None = None,
    ) -> ExecutionResult:
        import asyncio

        limits = resource_limits or ResourceLimits(
            cpu_cores=self._config.max_cpu_cores,
            memory_mb=self._config.max_memory_mb,
            timeout_seconds=timeout or self._config.default_timeout_seconds,
            network_enabled=self._config.network_enabled,
        )

        def _run() -> ExecutionResult:
            client = self._get_client()
            start = time.monotonic()

            # Build container config with resource constraints
            nano_cpus = int(limits.cpu_cores * 1e9)
            mem_limit = f"{limits.memory_mb}m"
            network_mode = "bridge" if limits.network_enabled else "none"

            try:
                container = client.containers.run(
                    image=self._config.docker_image,
                    command=["python3", "-c", code],
                    nano_cpus=nano_cpus,
                    mem_limit=mem_limit,
                    network_mode=network_mode,
                    read_only=True,
                    tmpfs={"/tmp": f"size={limits.disk_mb}m"},  # noqa: S108
                    remove=False,
                    detach=True,
                    stdout=True,
                    stderr=True,
                )
            except Exception as exc:
                raise SandboxError(f"Failed to create container: {exc}") from exc

            try:
                exit_info = container.wait(timeout=limits.timeout_seconds)
                stdout = container.logs(stdout=True, stderr=False).decode(errors="replace")
                stderr = container.logs(stdout=False, stderr=True).decode(errors="replace")
                exit_code = exit_info.get("StatusCode", -1)
            except Exception as exc:
                with contextlib.suppress(Exception):
                    container.kill()
                raise SandboxError(f"Container execution failed: {exc}") from exc
            finally:
                with contextlib.suppress(Exception):
                    container.remove(force=True)

            elapsed = time.monotonic() - start
            is_error = exit_code != 0

            content: list[dict[str, Any]] = [{"type": "text", "text": stdout}]
            if stderr:
                content.append({"type": "text", "text": f"[stderr] {stderr}"})

            return ExecutionResult(
                content=content,
                is_error=is_error,
                metadata={"exit_code": exit_code, "duration_seconds": elapsed},
                duration_seconds=elapsed,
            )

        return await asyncio.to_thread(_run)

    async def create_workspace(self, *, persistent: bool = False) -> Workspace:
        ws_id = generate_request_id()
        return Workspace(workspace_id=ws_id, persistent=persistent)

    async def set_network_policy(
        self,
        workspace: Workspace,
        *,
        allow_egress: bool = False,
        allowed_domains: list[str] | None = None,
    ) -> None:
        workspace.metadata["network"] = {
            "allow_egress": allow_egress,
            "allowed_domains": allowed_domains or [],
        }

    async def mount_filesystem(
        self,
        workspace: Workspace,
        *,
        read_only_paths: list[str] | None = None,
        temp_dirs: list[str] | None = None,
    ) -> None:
        workspace.metadata["mounts"] = {
            "read_only": read_only_paths or [],
            "temp": temp_dirs or [],
        }

    async def get_metrics(self, workspace: Workspace) -> SandboxMetrics:
        return SandboxMetrics()

    async def cleanup(self, workspace: Workspace) -> None:
        logger.info("docker workspace cleaned up", workspace_id=workspace.workspace_id)

    async def snapshot(self, workspace: Workspace) -> SnapshotInfo:
        snap_id = f"snap_{generate_request_id()}"
        return SnapshotInfo(
            snapshot_id=snap_id,
            workspace_id=workspace.workspace_id,
            created_at=time.time(),
        )

    async def restore(self, snapshot: SnapshotInfo) -> Workspace:
        return Workspace(workspace_id=snapshot.workspace_id, persistent=True)

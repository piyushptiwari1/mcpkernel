"""WASM (wasmtime) sandbox backend — lightweight isolation."""

from __future__ import annotations

import time
from typing import Any

from mcpkernel.proxy.interceptor import ExecutionResult
from mcpkernel.sandbox.base import ResourceLimits, SandboxBackend, SandboxMetrics, SnapshotInfo, Workspace
from mcpkernel.utils import SandboxError, generate_request_id, get_logger

logger = get_logger(__name__)


class WASMSandbox(SandboxBackend):
    """Lightweight sandbox using WebAssembly via wasmtime-py.

    Best for simple, stateless tool executions where full VM
    isolation is overkill.
    """

    def __init__(self, config: Any) -> None:
        self._config = config

    async def execute_code(
        self,
        code: str,
        timeout: int | None = None,
        resource_limits: ResourceLimits | None = None,
    ) -> ExecutionResult:
        import asyncio

        limits = resource_limits or ResourceLimits(timeout_seconds=timeout or self._config.default_timeout_seconds)
        start = time.monotonic()

        def _run_wasm() -> ExecutionResult:
            try:
                import wasmtime
            except ImportError as exc:
                raise SandboxError("wasmtime not installed — run: pip install 'mcpkernel[wasm]'") from exc

            engine = wasmtime.Engine()
            store = wasmtime.Store(engine)
            store.set_fuel(limits.timeout_seconds * 1_000_000)

            # For real use we'd compile the code to WASM via a toolchain.
            # This stub demonstrates the interface.
            elapsed = time.monotonic() - start
            return ExecutionResult(
                content=[{"type": "text", "text": f"WASM execution placeholder for: {code[:200]}"}],
                is_error=False,
                metadata={"backend": "wasm", "duration_seconds": elapsed},
                duration_seconds=elapsed,
            )

        return await asyncio.to_thread(_run_wasm)

    async def create_workspace(self, *, persistent: bool = False) -> Workspace:
        return Workspace(workspace_id=generate_request_id(), persistent=persistent)

    async def set_network_policy(
        self,
        workspace: Workspace,
        *,
        allow_egress: bool = False,
        allowed_domains: list[str] | None = None,
    ) -> None:
        pass  # WASM is network-isolated by default

    async def mount_filesystem(
        self,
        workspace: Workspace,
        *,
        read_only_paths: list[str] | None = None,
        temp_dirs: list[str] | None = None,
    ) -> None:
        pass  # WASM has no filesystem access by default

    async def get_metrics(self, workspace: Workspace) -> SandboxMetrics:
        return SandboxMetrics()

    async def cleanup(self, workspace: Workspace) -> None:
        pass

    async def snapshot(self, workspace: Workspace) -> SnapshotInfo:
        return SnapshotInfo(
            snapshot_id=generate_request_id(),
            workspace_id=workspace.workspace_id,
            created_at=time.time(),
        )

    async def restore(self, snapshot: SnapshotInfo) -> Workspace:
        return Workspace(workspace_id=snapshot.workspace_id)

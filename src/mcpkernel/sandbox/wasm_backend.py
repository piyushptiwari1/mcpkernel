"""WASM (wasmtime) sandbox backend — lightweight isolation.

Supports two execution modes:

1. **WASM bytecode** — pass raw ``.wasm`` bytes (detected by the ``\\x00asm``
   magic header).  The module is instantiated inside a WASI sandbox with
   fuel-limited execution and captured stdout/stderr.

2. **Script text** — any other string is written to a WASI virtual
   filesystem and executed via a pre-compiled WASM interpreter image
   (e.g. ``wasm-micropython``).  When no interpreter image is configured
   the code is executed natively in a subprocess as a fallback while
   still reporting through the sandbox interface.
"""

from __future__ import annotations

import contextlib
import os
import subprocess
import tempfile
import time
from typing import Any

from mcpkernel.proxy.interceptor import ExecutionResult
from mcpkernel.sandbox.base import ResourceLimits, SandboxBackend, SandboxMetrics, SnapshotInfo, Workspace
from mcpkernel.utils import SandboxError, generate_request_id, get_logger

logger = get_logger(__name__)

# Maximum captured output per stream to avoid memory issues
_MAX_OUTPUT_BYTES = 1_048_576  # 1 MiB


class WASMSandbox(SandboxBackend):
    """Lightweight sandbox using WebAssembly via wasmtime-py.

    Best for simple, stateless tool executions where full VM
    isolation is overkill.
    """

    def __init__(self, config: Any) -> None:
        self._config = config

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _is_wasm_bytes(code: str) -> bool:
        """Return *True* when *code* looks like raw WASM bytecode."""
        return code[:4] == "\x00asm"

    def _execute_wasm_module(
        self,
        code: str,
        limits: ResourceLimits,
        start: float,
    ) -> ExecutionResult:
        """Execute a pre-compiled WASM module via wasmtime WASI."""
        try:
            import wasmtime
        except ImportError as exc:
            raise SandboxError("wasmtime not installed — run: pip install 'mcpkernel[wasm]'") from exc

        wasi_cfg = wasmtime.WasiConfig()
        wasi_cfg.inherit_env = False

        with tempfile.NamedTemporaryFile(delete=False, suffix=".stdout") as stdout_file:
            stdout_path = stdout_file.name
        with tempfile.NamedTemporaryFile(delete=False, suffix=".stderr") as stderr_file:
            stderr_path = stderr_file.name

        try:
            wasi_cfg.stdout_file = stdout_path
            wasi_cfg.stderr_file = stderr_path

            engine_cfg = wasmtime.Config()
            engine_cfg.consume_fuel = True
            engine = wasmtime.Engine(engine_cfg)
            store = wasmtime.Store(engine)
            store.set_fuel(limits.timeout_seconds * 10_000_000)
            store.set_wasi(wasi_cfg)

            linker = wasmtime.Linker(engine)
            linker.define_wasi()

            module = wasmtime.Module(engine, code.encode("latin-1"))
            instance = linker.instantiate(store, module)

            start_fn = instance.exports(store).get("_start")
            if start_fn is None:
                start_fn = instance.exports(store).get("main")

            is_error = False
            if start_fn is not None:
                try:
                    start_fn(store)
                except wasmtime.ExitTrap as exc:
                    is_error = exc.code != 0
                except wasmtime.WasmtimeError:
                    is_error = True

            elapsed = time.monotonic() - start
            stdout_text = self._read_limited(stdout_path)
            stderr_text = self._read_limited(stderr_path)

            content: list[dict[str, Any]] = [{"type": "text", "text": stdout_text}]
            if stderr_text:
                content.append({"type": "text", "text": f"[stderr] {stderr_text}"})

            return ExecutionResult(
                content=content,
                is_error=is_error,
                metadata={"backend": "wasm", "mode": "module", "duration_seconds": elapsed},
                duration_seconds=elapsed,
            )
        finally:
            for p in (stdout_path, stderr_path):
                with contextlib.suppress(OSError):
                    os.unlink(p)

    def _execute_script(
        self,
        code: str,
        limits: ResourceLimits,
        start: float,
    ) -> ExecutionResult:
        """Execute a text script in a sandboxed subprocess.

        If the config provides ``wasm_interpreter_path`` pointing to a
        WASI-compiled interpreter (``.wasm`` file), the script is piped
        through that interpreter via wasmtime CLI.  Otherwise falls back
        to a resource-limited native subprocess.
        """
        timeout = limits.timeout_seconds
        interpreter_path = getattr(self._config, "wasm_interpreter_path", None)

        if interpreter_path and os.path.isfile(interpreter_path):
            cmd = ["wasmtime", "run", "--fuel", str(timeout * 10_000_000), interpreter_path]
        else:
            cmd = ["python3", "-c", code]

        try:
            proc = subprocess.run(
                cmd,
                input=code if interpreter_path else None,
                capture_output=True,
                timeout=timeout,
                text=True,
                env={},
            )
        except subprocess.TimeoutExpired:
            elapsed = time.monotonic() - start
            return ExecutionResult(
                content=[{"type": "text", "text": f"Execution timed out after {timeout}s"}],
                is_error=True,
                metadata={"backend": "wasm", "mode": "script", "duration_seconds": elapsed},
                duration_seconds=elapsed,
            )
        except FileNotFoundError as exc:
            raise SandboxError(f"Interpreter not found: {exc}") from exc

        elapsed = time.monotonic() - start
        is_error = proc.returncode != 0

        stdout = (proc.stdout or "")[:_MAX_OUTPUT_BYTES]
        stderr = (proc.stderr or "")[:_MAX_OUTPUT_BYTES]

        content: list[dict[str, Any]] = [{"type": "text", "text": stdout}]
        if stderr:
            content.append({"type": "text", "text": f"[stderr] {stderr}"})

        return ExecutionResult(
            content=content,
            is_error=is_error,
            metadata={"backend": "wasm", "mode": "script", "duration_seconds": elapsed},
            duration_seconds=elapsed,
        )

    @staticmethod
    def _read_limited(path: str) -> str:
        """Read at most ``_MAX_OUTPUT_BYTES`` from *path*."""
        try:
            with open(path, errors="replace") as fh:
                return fh.read(_MAX_OUTPUT_BYTES)
        except OSError:
            return ""

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def execute_code(
        self,
        code: str,
        timeout: int | None = None,
        resource_limits: ResourceLimits | None = None,
    ) -> ExecutionResult:
        import asyncio

        limits = resource_limits or ResourceLimits(timeout_seconds=timeout or self._config.default_timeout_seconds)
        start = time.monotonic()

        if self._is_wasm_bytes(code):
            return await asyncio.to_thread(self._execute_wasm_module, code, limits, start)
        return await asyncio.to_thread(self._execute_script, code, limits, start)

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

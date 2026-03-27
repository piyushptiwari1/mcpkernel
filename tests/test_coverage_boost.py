"""Tests targeting low-coverage modules to push total above 80%.

Covers: dee/drift, dee/envelope, sandbox backends, ebpf/probe,
integrations/guardrails, integrations/langfuse, integrations/agent_scan.
"""

from __future__ import annotations

import asyncio
import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from mcpkernel.proxy.interceptor import ExecutionResult, MCPToolCall


# ===================================================================
# DEE Drift
# ===================================================================
class TestDetectDrift:
    """Cover detect_drift() and _classify_nondeterminism()."""

    @pytest.fixture
    def mock_store(self):
        store = AsyncMock()
        store.get = AsyncMock(
            return_value={
                "output_hash": "original_hash",
                "result_json": "{}",
            }
        )
        return store

    @pytest.fixture
    def mock_execute_fn(self):
        return AsyncMock()

    @pytest.mark.asyncio
    async def test_drift_none_all_match(self, mock_store, mock_execute_fn):
        """All replays match original → DriftCategory.NONE."""
        from mcpkernel.dee.drift import DriftCategory, detect_drift
        from mcpkernel.dee.envelope import ExecutionTrace

        fake_trace = ExecutionTrace(
            trace_id="replay-1",
            tool_name="test",
            agent_id="a",
            input_hash="ih",
            output_hash="original_hash",
            env_snapshot_hash="eh",
            timestamp=time.time(),
            duration_seconds=0.1,
            result=ExecutionResult(content=[]),
        )

        with patch("mcpkernel.dee.drift.replay", new_callable=AsyncMock, return_value=fake_trace):
            report = await detect_drift("t1", mock_store, mock_execute_fn, num_replays=2)
        assert report.category == DriftCategory.NONE
        assert report.original_output_hash == "original_hash"
        assert report.details["all_match_original"] is True

    @pytest.mark.asyncio
    async def test_drift_environment_change(self, mock_store, mock_execute_fn):
        """Replays agree with each other but not original → ENVIRONMENT_CHANGE."""
        from mcpkernel.dee.drift import DriftCategory, detect_drift
        from mcpkernel.dee.envelope import ExecutionTrace

        fake_trace = ExecutionTrace(
            trace_id="replay",
            tool_name="test",
            agent_id="a",
            input_hash="ih",
            output_hash="different_hash",
            env_snapshot_hash="eh",
            timestamp=time.time(),
            duration_seconds=0.1,
            result=ExecutionResult(content=[]),
        )

        with patch("mcpkernel.dee.drift.replay", new_callable=AsyncMock, return_value=fake_trace):
            report = await detect_drift("t1", mock_store, mock_execute_fn, num_replays=3)
        assert report.category == DriftCategory.ENVIRONMENT_CHANGE
        assert report.details["replays_consistent"] is True

    @pytest.mark.asyncio
    async def test_drift_nondeterministic_random(self, mock_store, mock_execute_fn):
        """Replays disagree with each other, result has 'random' → RANDOM_SEED."""
        from mcpkernel.dee.drift import DriftCategory, detect_drift
        from mcpkernel.dee.envelope import ExecutionTrace

        mock_store.get.return_value = {
            "output_hash": "orig",
            "result_json": '{"data": "random uuid output"}',
        }

        call_count = 0

        async def _make_trace(*a, **kw):
            nonlocal call_count
            call_count += 1
            return ExecutionTrace(
                trace_id=f"r-{call_count}",
                tool_name="test",
                agent_id="a",
                input_hash="ih",
                output_hash=f"hash-{call_count}",
                env_snapshot_hash="eh",
                timestamp=time.time(),
                duration_seconds=0.1,
                result=ExecutionResult(content=[]),
            )

        with patch("mcpkernel.dee.drift.replay", side_effect=_make_trace):
            report = await detect_drift("t1", mock_store, mock_execute_fn, num_replays=3)
        assert report.category == DriftCategory.RANDOM_SEED

    @pytest.mark.asyncio
    async def test_drift_nondeterministic_clock(self, mock_store, mock_execute_fn):
        """Result has 'timestamp' keyword → CLOCK_DEPENDENCY."""
        from mcpkernel.dee.drift import DriftCategory, detect_drift
        from mcpkernel.dee.envelope import ExecutionTrace

        mock_store.get.return_value = {
            "output_hash": "orig",
            "result_json": '{"created_at": "timestamp now"}',
        }

        call_count = 0

        async def _make_trace(*a, **kw):
            nonlocal call_count
            call_count += 1
            return ExecutionTrace(
                trace_id=f"r-{call_count}",
                tool_name="test",
                agent_id="a",
                input_hash="ih",
                output_hash=f"hash-{call_count}",
                env_snapshot_hash="eh",
                timestamp=time.time(),
                duration_seconds=0.1,
                result=ExecutionResult(content=[]),
            )

        with patch("mcpkernel.dee.drift.replay", side_effect=_make_trace):
            report = await detect_drift("t1", mock_store, mock_execute_fn, num_replays=3)
        assert report.category == DriftCategory.CLOCK_DEPENDENCY

    @pytest.mark.asyncio
    async def test_drift_nondeterministic_network(self, mock_store, mock_execute_fn):
        """Result has 'http' keyword → NETWORK_CALL."""
        from mcpkernel.dee.drift import DriftCategory, detect_drift
        from mcpkernel.dee.envelope import ExecutionTrace

        mock_store.get.return_value = {
            "output_hash": "orig",
            "result_json": '{"url": "http://api.example.com"}',
        }

        call_count = 0

        async def _make_trace(*a, **kw):
            nonlocal call_count
            call_count += 1
            return ExecutionTrace(
                trace_id=f"r-{call_count}",
                tool_name="test",
                agent_id="a",
                input_hash="ih",
                output_hash=f"hash-{call_count}",
                env_snapshot_hash="eh",
                timestamp=time.time(),
                duration_seconds=0.1,
                result=ExecutionResult(content=[]),
            )

        with patch("mcpkernel.dee.drift.replay", side_effect=_make_trace):
            report = await detect_drift("t1", mock_store, mock_execute_fn, num_replays=3)
        assert report.category == DriftCategory.NETWORK_CALL

    @pytest.mark.asyncio
    async def test_drift_nondeterministic_filesystem(self, mock_store, mock_execute_fn):
        """Result has 'file' keyword → FILESYSTEM_CHANGE."""
        from mcpkernel.dee.drift import DriftCategory, detect_drift
        from mcpkernel.dee.envelope import ExecutionTrace

        mock_store.get.return_value = {
            "output_hash": "orig",
            "result_json": '{"source": "file path /tmp/data"}',
        }

        call_count = 0

        async def _make_trace(*a, **kw):
            nonlocal call_count
            call_count += 1
            return ExecutionTrace(
                trace_id=f"r-{call_count}",
                tool_name="test",
                agent_id="a",
                input_hash="ih",
                output_hash=f"hash-{call_count}",
                env_snapshot_hash="eh",
                timestamp=time.time(),
                duration_seconds=0.1,
                result=ExecutionResult(content=[]),
            )

        with patch("mcpkernel.dee.drift.replay", side_effect=_make_trace):
            report = await detect_drift("t1", mock_store, mock_execute_fn, num_replays=3)
        assert report.category == DriftCategory.FILESYSTEM_CHANGE

    @pytest.mark.asyncio
    async def test_drift_nondeterministic_unknown(self, mock_store, mock_execute_fn):
        """Result has no matching keywords → UNKNOWN."""
        from mcpkernel.dee.drift import DriftCategory, detect_drift
        from mcpkernel.dee.envelope import ExecutionTrace

        mock_store.get.return_value = {
            "output_hash": "orig",
            "result_json": '{"data": "some opaque value"}',
        }

        call_count = 0

        async def _make_trace(*a, **kw):
            nonlocal call_count
            call_count += 1
            return ExecutionTrace(
                trace_id=f"r-{call_count}",
                tool_name="test",
                agent_id="a",
                input_hash="ih",
                output_hash=f"hash-{call_count}",
                env_snapshot_hash="eh",
                timestamp=time.time(),
                duration_seconds=0.1,
                result=ExecutionResult(content=[]),
            )

        with patch("mcpkernel.dee.drift.replay", side_effect=_make_trace):
            report = await detect_drift("t1", mock_store, mock_execute_fn, num_replays=3)
        assert report.category == DriftCategory.UNKNOWN

    @pytest.mark.asyncio
    async def test_drift_trace_not_found(self, mock_execute_fn):
        """Missing trace raises DriftDetected."""
        from mcpkernel.dee.drift import detect_drift
        from mcpkernel.utils import DriftDetected

        store = AsyncMock()
        store.get.return_value = None
        with pytest.raises(DriftDetected, match="Trace not found"):
            await detect_drift("nonexistent", store, mock_execute_fn)


# ===================================================================
# DEE Envelope
# ===================================================================
class TestWrapExecution:
    """Cover wrap_execution() and _sign_trace()."""

    @pytest.mark.asyncio
    async def test_wrap_execution_no_sign(self):
        from mcpkernel.dee.envelope import wrap_execution

        call = MCPToolCall(
            request_id=1,
            tool_name="test_tool",
            arguments={"x": 1},
            raw_jsonrpc={},
        )
        result = ExecutionResult(content=[{"type": "text", "text": "ok"}])
        execute_fn = AsyncMock(return_value=result)

        trace = await wrap_execution(call, execute_fn, sign=False)
        assert trace.tool_name == "test_tool"
        assert trace.sigstore_bundle is None
        assert trace.input_hash
        assert trace.output_hash
        assert trace.duration_seconds >= 0

    @pytest.mark.asyncio
    async def test_wrap_execution_with_sign_no_sigstore(self):
        """Sign=True but sigstore not installed → bundle is None."""
        from mcpkernel.dee.envelope import wrap_execution

        call = MCPToolCall(
            request_id=1,
            tool_name="test_tool",
            arguments={},
            raw_jsonrpc={},
        )
        result = ExecutionResult(content=[])
        execute_fn = AsyncMock(return_value=result)

        with patch.dict("sys.modules", {"sigstore": None, "sigstore.sign": None}):
            trace = await wrap_execution(call, execute_fn, sign=True)
        assert trace.sigstore_bundle is None

    @pytest.mark.asyncio
    async def test_wrap_execution_sign_exception(self):
        """Sigstore import succeeds but signing raises → bundle is None."""
        from mcpkernel.dee.envelope import wrap_execution

        call = MCPToolCall(
            request_id=1,
            tool_name="test_tool",
            arguments={},
            raw_jsonrpc={},
        )
        result = ExecutionResult(content=[])
        execute_fn = AsyncMock(return_value=result)

        mock_signer = MagicMock()
        mock_signer.sign_artifact.side_effect = RuntimeError("signing failed")

        mock_signing_ctx = MagicMock()
        mock_signing_ctx.production.return_value.signer.return_value.__enter__ = MagicMock(return_value=mock_signer)
        mock_signing_ctx.production.return_value.signer.return_value.__exit__ = MagicMock(return_value=False)

        mock_sign_mod = MagicMock()
        mock_sign_mod.SigningContext = mock_signing_ctx

        with patch.dict("sys.modules", {"sigstore": MagicMock(), "sigstore.sign": mock_sign_mod}):
            trace = await wrap_execution(call, execute_fn, sign=True)
        assert trace.sigstore_bundle is None

    @pytest.mark.asyncio
    async def test_wrap_execution_with_agent_id(self):
        from mcpkernel.dee.envelope import wrap_execution

        call = MCPToolCall(request_id=1, tool_name="t", arguments={}, raw_jsonrpc={})
        execute_fn = AsyncMock(return_value=ExecutionResult(content=[]))
        trace = await wrap_execution(call, execute_fn, agent_id="agent-007", sign=False)
        assert trace.agent_id == "agent-007"


# ===================================================================
# Sandbox Backends
# ===================================================================
class TestDockerSandboxExecution:
    """Cover DockerSandbox.execute_code() with mocked Docker client."""

    @pytest.mark.asyncio
    async def test_execute_code_success(self):
        from mcpkernel.sandbox.docker_backend import DockerSandbox

        cfg = MagicMock()
        cfg.max_cpu_cores = 1
        cfg.max_memory_mb = 256
        cfg.default_timeout_seconds = 30
        cfg.network_enabled = False
        cfg.docker_image = "python:3.12-slim"

        mock_container = MagicMock()
        mock_container.wait.return_value = {"StatusCode": 0}
        mock_container.logs.side_effect = [b"hello world\n", b""]
        mock_container.remove = MagicMock()

        mock_client = MagicMock()
        mock_client.containers.run.return_value = mock_container

        sb = DockerSandbox(cfg)
        sb._client = mock_client

        result = await sb.execute_code("print('hello')")
        assert not result.is_error
        assert "hello world" in result.content[0]["text"]

    @pytest.mark.asyncio
    async def test_execute_code_with_stderr(self):
        from mcpkernel.sandbox.docker_backend import DockerSandbox

        cfg = MagicMock()
        cfg.max_cpu_cores = 1
        cfg.max_memory_mb = 256
        cfg.default_timeout_seconds = 30
        cfg.network_enabled = True
        cfg.docker_image = "python:3.12-slim"

        mock_container = MagicMock()
        mock_container.wait.return_value = {"StatusCode": 1}
        mock_container.logs.side_effect = [b"", b"error occurred"]
        mock_container.remove = MagicMock()

        mock_client = MagicMock()
        mock_client.containers.run.return_value = mock_container

        sb = DockerSandbox(cfg)
        sb._client = mock_client

        result = await sb.execute_code("bad code")
        assert result.is_error
        assert len(result.content) == 2
        assert "stderr" in result.content[1]["text"]

    @pytest.mark.asyncio
    async def test_execute_code_container_create_fails(self):
        from mcpkernel.sandbox.docker_backend import DockerSandbox
        from mcpkernel.utils import SandboxError

        cfg = MagicMock()
        cfg.max_cpu_cores = 1
        cfg.max_memory_mb = 256
        cfg.default_timeout_seconds = 30
        cfg.network_enabled = False
        cfg.docker_image = "python:3.12-slim"

        mock_client = MagicMock()
        mock_client.containers.run.side_effect = RuntimeError("no image")

        sb = DockerSandbox(cfg)
        sb._client = mock_client

        with pytest.raises(SandboxError, match="Failed to create container"):
            await sb.execute_code("print()")

    @pytest.mark.asyncio
    async def test_execute_code_container_wait_fails(self):
        from mcpkernel.sandbox.docker_backend import DockerSandbox
        from mcpkernel.utils import SandboxError

        cfg = MagicMock()
        cfg.max_cpu_cores = 1
        cfg.max_memory_mb = 256
        cfg.default_timeout_seconds = 30
        cfg.network_enabled = False
        cfg.docker_image = "python:3.12-slim"

        mock_container = MagicMock()
        mock_container.wait.side_effect = TimeoutError("timed out")
        mock_container.kill = MagicMock()
        mock_container.remove = MagicMock()

        mock_client = MagicMock()
        mock_client.containers.run.return_value = mock_container

        sb = DockerSandbox(cfg)
        sb._client = mock_client

        with pytest.raises(SandboxError, match="Container execution failed"):
            await sb.execute_code("while True: pass")


class TestFirecrackerSandboxExecution:
    """Cover FirecrackerSandbox.execute_code()."""

    @pytest.mark.asyncio
    async def test_execute_no_kernel_config(self):
        from mcpkernel.sandbox.firecracker_backend import FirecrackerSandbox
        from mcpkernel.utils import SandboxError

        cfg = MagicMock()
        cfg.firecracker_kernel_path = ""
        cfg.firecracker_rootfs_path = ""
        cfg.default_timeout_seconds = 10

        sb = FirecrackerSandbox(cfg)
        with pytest.raises(SandboxError, match="not configured"):
            await sb.execute_code("print()")

    @pytest.mark.asyncio
    async def test_execute_binary_not_found(self):
        from mcpkernel.sandbox.firecracker_backend import FirecrackerSandbox
        from mcpkernel.utils import SandboxError

        cfg = MagicMock()
        cfg.firecracker_kernel_path = "/boot/vmlinux"
        cfg.firecracker_rootfs_path = "/rootfs.ext4"
        cfg.default_timeout_seconds = 5

        sb = FirecrackerSandbox(cfg)
        with pytest.raises(SandboxError, match="not found"):
            await sb.execute_code("print()")

    @pytest.mark.asyncio
    async def test_execute_success_mocked(self):
        from mcpkernel.sandbox.firecracker_backend import FirecrackerSandbox

        cfg = MagicMock()
        cfg.firecracker_kernel_path = "/boot/vmlinux"
        cfg.firecracker_rootfs_path = "/rootfs.ext4"
        cfg.default_timeout_seconds = 10

        sb = FirecrackerSandbox(cfg)

        mock_proc = AsyncMock()
        mock_proc.communicate = AsyncMock(return_value=(b"hello from VM", b""))
        mock_proc.returncode = 0

        with (
            patch("asyncio.create_subprocess_exec", new_callable=AsyncMock, return_value=mock_proc),
            patch("asyncio.wait_for", new_callable=AsyncMock, return_value=(b"hello from VM", b"")),
        ):
            mock_proc2 = AsyncMock()
            mock_proc2.returncode = 0
            mock_proc2.communicate = AsyncMock(return_value=(b"hello from VM", b""))

            with patch("asyncio.create_subprocess_exec", new_callable=AsyncMock, return_value=mock_proc2):
                result = await sb.execute_code("print('hi')")
        assert not result.is_error


class TestWASMSandboxExecution:
    """Cover WASMSandbox.execute_code() with the script fallback path."""

    @pytest.mark.asyncio
    async def test_execute_no_wasmtime_with_wasm_bytes(self):
        """WASM bytecode path raises SandboxError when wasmtime is missing."""
        from mcpkernel.sandbox.wasm_backend import WASMSandbox
        from mcpkernel.utils import SandboxError

        cfg = MagicMock()
        cfg.default_timeout_seconds = 10

        sb = WASMSandbox(cfg)
        # \x00asm prefix triggers the WASM module path
        with patch.dict("sys.modules", {"wasmtime": None}), pytest.raises((SandboxError, ModuleNotFoundError)):
            await sb.execute_code("\x00asm" + "rest")

    @pytest.mark.asyncio
    async def test_execute_script_fallback(self):
        """Script text path runs code via subprocess and captures stdout."""
        from mcpkernel.sandbox.wasm_backend import WASMSandbox

        cfg = MagicMock()
        cfg.default_timeout_seconds = 10
        cfg.wasm_interpreter_path = None

        sb = WASMSandbox(cfg)
        result = await sb.execute_code("print('hello from wasm sandbox')")
        assert not result.is_error
        assert "hello from wasm sandbox" in result.content[0]["text"]

    @pytest.mark.asyncio
    async def test_execute_script_error(self):
        """Script that raises should return is_error=True."""
        from mcpkernel.sandbox.wasm_backend import WASMSandbox

        cfg = MagicMock()
        cfg.default_timeout_seconds = 10
        cfg.wasm_interpreter_path = None

        sb = WASMSandbox(cfg)
        result = await sb.execute_code("raise ValueError('boom')")
        assert result.is_error

    @pytest.mark.asyncio
    async def test_execute_script_timeout(self):
        """Script that exceeds timeout should return is_error=True."""
        from mcpkernel.sandbox.wasm_backend import WASMSandbox

        cfg = MagicMock()
        cfg.default_timeout_seconds = 1
        cfg.wasm_interpreter_path = None

        sb = WASMSandbox(cfg)
        result = await sb.execute_code("import time; time.sleep(10)")
        assert result.is_error
        assert "timed out" in result.content[0]["text"].lower()


class TestMicrosandboxExecution:
    """Cover MicrosandboxSandbox.execute_code()."""

    @pytest.mark.asyncio
    async def test_execute_success(self):
        from mcpkernel.sandbox.microsandbox_backend import MicrosandboxSandbox

        cfg = MagicMock()
        cfg.default_timeout_seconds = 10
        cfg.microsandbox_url = "http://localhost:8081"

        sb = MicrosandboxSandbox(cfg)

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json.return_value = {"output": "result", "is_error": False}

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=mock_resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock()

        with patch("httpx.AsyncClient", return_value=mock_client):
            result = await sb.execute_code("print()")
        assert not result.is_error
        assert result.content[0]["text"] == "result"

    @pytest.mark.asyncio
    async def test_execute_http_error(self):
        import httpx

        from mcpkernel.sandbox.microsandbox_backend import MicrosandboxSandbox
        from mcpkernel.utils import SandboxError

        cfg = MagicMock()
        cfg.default_timeout_seconds = 10
        cfg.microsandbox_url = "http://localhost:8081"

        sb = MicrosandboxSandbox(cfg)

        mock_resp = MagicMock()
        mock_resp.status_code = 500
        mock_resp.raise_for_status.side_effect = httpx.HTTPStatusError(
            "Server Error",
            request=MagicMock(),
            response=mock_resp,
        )

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=mock_resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("httpx.AsyncClient", return_value=mock_client), pytest.raises(SandboxError, match="500"):
            await sb.execute_code("print()")

    @pytest.mark.asyncio
    async def test_execute_connection_error(self):
        import httpx

        from mcpkernel.sandbox.microsandbox_backend import MicrosandboxSandbox
        from mcpkernel.utils import SandboxError

        cfg = MagicMock()
        cfg.default_timeout_seconds = 10
        cfg.microsandbox_url = "http://localhost:9999"

        sb = MicrosandboxSandbox(cfg)

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(side_effect=httpx.ConnectError("refused"))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with (
            patch("httpx.AsyncClient", return_value=mock_client),
            pytest.raises(SandboxError, match="Cannot reach"),
        ):
            await sb.execute_code("print()")


# ===================================================================
# eBPF Probe
# ===================================================================
class TestEBPFProbeExecution:
    """Cover EBPFProbe start/stop/poll paths."""

    @pytest.mark.asyncio
    async def test_start_unavailable_noop(self):
        from mcpkernel.ebpf.probe import EBPFProbe

        probe = EBPFProbe()
        # Not root, so unavailable
        await probe.start()
        assert not probe.available

    @pytest.mark.asyncio
    async def test_stop_noop(self):
        from mcpkernel.ebpf.probe import EBPFProbe

        probe = EBPFProbe()
        await probe.stop()
        assert probe._bpf is None

    @pytest.mark.asyncio
    async def test_start_with_mocked_bcc(self):
        from mcpkernel.ebpf.probe import EBPFProbe

        probe = EBPFProbe()
        probe._available = True

        mock_bpf_cls = MagicMock()
        mock_bpf_instance = MagicMock()
        mock_bpf_cls.return_value = mock_bpf_instance

        with (
            patch.dict("sys.modules", {"bcc": MagicMock(BPF=mock_bpf_cls)}),
            patch("mcpkernel.ebpf.probe.EBPFProbe._check_availability", return_value=True),
        ):
            probe._available = True
            # Mock the executor to avoid actual thread
            with patch.object(asyncio.get_running_loop(), "run_in_executor"):
                await probe.start()
        assert probe._running
        await probe.stop()
        assert not probe._running

    def test_on_event_registers_callback(self):
        from mcpkernel.ebpf.probe import EBPFProbe

        probe = EBPFProbe()
        cb = MagicMock()
        probe.on_event(cb)
        assert cb in probe._callbacks

    def test_events_property(self):
        from mcpkernel.ebpf.probe import EBPFProbe, ProbeEvent, SyscallType

        probe = EBPFProbe()
        evt = ProbeEvent(syscall=SyscallType.CONNECT, pid=123, comm="test", timestamp=time.time())
        probe._events.append(evt)
        assert len(probe.events) == 1

    def test_poll_loop_no_bpf(self):
        """_poll_loop returns immediately when _bpf is None."""
        from mcpkernel.ebpf.probe import EBPFProbe

        probe = EBPFProbe()
        probe._poll_loop()  # should not raise


# ===================================================================
# Guardrails Integration
# ===================================================================
class TestGuardrailsValidation:
    """Cover GuardrailsValidator methods with mocked guardrails lib."""

    @pytest.mark.asyncio
    async def test_validate_text_not_available(self):
        from mcpkernel.integrations.guardrails import GuardrailsConfig, GuardrailsValidator

        v = GuardrailsValidator(GuardrailsConfig(enabled=False))
        result = await v.validate_text("some text with PII")
        assert result == []

    @pytest.mark.asyncio
    async def test_validate_text_with_mock_guardrails(self):
        from mcpkernel.integrations.guardrails import GuardrailsConfig, GuardrailsValidator

        cfg = GuardrailsConfig(enabled=True, pii_validator=True, secrets_validator=True, toxic_content=True)
        v = GuardrailsValidator(cfg)

        # Mock guardrails being available
        mock_gd = MagicMock()
        with patch.dict("sys.modules", {"guardrails": mock_gd}):
            v._init_attempted = True
            v._available = True

            # Mock the validators to return no detections (ImportError path)
            result = await v.validate_text("hello world")
        assert isinstance(result, list)

    @pytest.mark.asyncio
    async def test_detect_pii_import_error(self):
        from mcpkernel.integrations.guardrails import GuardrailsConfig, GuardrailsValidator

        cfg = GuardrailsConfig(enabled=True, pii_validator=True)
        v = GuardrailsValidator(cfg)
        v._init_attempted = True
        v._available = True

        # guardrails.hub not importable → empty result
        result = await v._detect_pii("John Doe email: john@example.com", "field.name")
        assert result == []

    @pytest.mark.asyncio
    async def test_detect_secrets_import_error(self):
        from mcpkernel.integrations.guardrails import GuardrailsConfig, GuardrailsValidator

        cfg = GuardrailsConfig(enabled=True, secrets_validator=True)
        v = GuardrailsValidator(cfg)
        v._init_attempted = True
        v._available = True

        result = await v._detect_secrets("AKIAIOSFODNN7EXAMPLE", "field")
        assert result == []

    @pytest.mark.asyncio
    async def test_detect_toxic_import_error(self):
        from mcpkernel.integrations.guardrails import GuardrailsConfig, GuardrailsValidator

        cfg = GuardrailsConfig(enabled=True, toxic_content=True)
        v = GuardrailsValidator(cfg)
        v._init_attempted = True
        v._available = True

        result = await v._detect_toxic("some text", "field")
        assert result == []

    @pytest.mark.asyncio
    async def test_detect_pii_with_mock_validator(self):
        from mcpkernel.integrations.guardrails import GuardrailsConfig, GuardrailsValidator

        cfg = GuardrailsConfig(enabled=True, pii_validator=True)
        v = GuardrailsValidator(cfg)
        v._init_attempted = True
        v._available = True

        mock_result = MagicMock()
        mock_result.validation_passed = False
        mock_result.detected_entities = [{"entity_type": "EMAIL_ADDRESS", "text": "john@example.com", "score": 0.95}]

        mock_validator = MagicMock()
        mock_validator.validate.return_value = mock_result

        mock_detect_pii = MagicMock(return_value=mock_validator)
        mock_hub = MagicMock(DetectPII=mock_detect_pii)

        with patch.dict("sys.modules", {"guardrails": MagicMock(), "guardrails.hub": mock_hub}):
            result = await v._detect_pii("john@example.com", "email_field")
        assert len(result) == 1
        assert result[0].entity_type == "EMAIL_ADDRESS"

    @pytest.mark.asyncio
    async def test_detect_secrets_with_mock_validator(self):
        from mcpkernel.integrations.guardrails import GuardrailsConfig, GuardrailsValidator

        cfg = GuardrailsConfig(enabled=True, secrets_validator=True)
        v = GuardrailsValidator(cfg)
        v._init_attempted = True
        v._available = True

        mock_result = MagicMock()
        mock_result.validation_passed = False

        mock_validator = MagicMock()
        mock_validator.validate.return_value = mock_result

        mock_secrets = MagicMock(return_value=mock_validator)
        mock_hub = MagicMock(SecretsPresent=mock_secrets)

        with patch.dict("sys.modules", {"guardrails": MagicMock(), "guardrails.hub": mock_hub}):
            result = await v._detect_secrets("AKIAIOSFODNN7EXAMPLE", "key")
        assert len(result) == 1
        assert result[0].label.value == "secret"

    @pytest.mark.asyncio
    async def test_detect_toxic_with_mock_validator(self):
        from mcpkernel.integrations.guardrails import GuardrailsConfig, GuardrailsValidator

        cfg = GuardrailsConfig(enabled=True, toxic_content=True)
        v = GuardrailsValidator(cfg)
        v._init_attempted = True
        v._available = True

        mock_result = MagicMock()
        mock_result.validation_passed = False

        mock_validator = MagicMock()
        mock_validator.validate.return_value = mock_result

        mock_toxic = MagicMock(return_value=mock_validator)
        mock_hub = MagicMock(ToxicLanguage=mock_toxic)

        with patch.dict("sys.modules", {"guardrails": MagicMock(), "guardrails.hub": mock_hub}):
            result = await v._detect_toxic("offensive content", "message")
        assert len(result) == 1

    @pytest.mark.asyncio
    async def test_validate_dict_recursive(self):
        from mcpkernel.integrations.guardrails import GuardrailsConfig, GuardrailsValidator

        cfg = GuardrailsConfig(enabled=False)
        v = GuardrailsValidator(cfg)
        # Not available, so returns empty
        result = await v.validate_dict({"a": "hello", "b": {"c": "world"}, "d": [1, "text"]})
        assert result == []

    @pytest.mark.asyncio
    async def test_try_init_import_success(self):
        from mcpkernel.integrations.guardrails import GuardrailsConfig, GuardrailsValidator

        cfg = GuardrailsConfig(enabled=True)
        v = GuardrailsValidator(cfg)
        mock_gd = MagicMock()
        with patch.dict("sys.modules", {"guardrails": mock_gd}):
            v._try_init()
        assert v._available

    @pytest.mark.asyncio
    async def test_try_init_import_failure(self):
        from mcpkernel.integrations.guardrails import GuardrailsConfig, GuardrailsValidator

        cfg = GuardrailsConfig(enabled=True)
        v = GuardrailsValidator(cfg)
        # Module 'guardrails' not in sys.modules → import will fail
        with patch.dict("sys.modules", {"guardrails": None}):
            v._init_attempted = False
            v._try_init()
        assert not v._available

    @pytest.mark.asyncio
    async def test_detect_pii_validator_exception(self):
        """validator.validate raises → graceful empty result."""
        from mcpkernel.integrations.guardrails import GuardrailsConfig, GuardrailsValidator

        cfg = GuardrailsConfig(enabled=True, pii_validator=True)
        v = GuardrailsValidator(cfg)
        v._init_attempted = True
        v._available = True

        mock_validator = MagicMock()
        mock_validator.validate.side_effect = RuntimeError("boom")

        mock_detect_pii = MagicMock(return_value=mock_validator)
        mock_hub = MagicMock(DetectPII=mock_detect_pii)

        with patch.dict("sys.modules", {"guardrails": MagicMock(), "guardrails.hub": mock_hub}):
            result = await v._detect_pii("test", "f")
        assert result == []


# ===================================================================
# Langfuse Integration
# ===================================================================
class TestLangfuseExporter:
    """Cover LangfuseExporter lifecycle and export methods."""

    @pytest.mark.asyncio
    async def test_start_disabled(self):
        from mcpkernel.integrations.langfuse import LangfuseConfig, LangfuseExporter

        exp = LangfuseExporter(config=LangfuseConfig(enabled=False))
        await exp.start()
        assert not exp._started

    @pytest.mark.asyncio
    async def test_start_and_shutdown(self):
        from mcpkernel.integrations.langfuse import LangfuseConfig, LangfuseExporter

        cfg = LangfuseConfig(
            enabled=True,
            public_key="pk-test",
            secret_key="sk-test",  # noqa: S106
            host="https://test.langfuse.com",
        )
        exp = LangfuseExporter(config=cfg)

        mock_client = AsyncMock()
        mock_client.aclose = AsyncMock()

        with patch("httpx.AsyncClient", return_value=mock_client):
            await exp.start()
            assert exp._started
            await exp.shutdown()
            assert not exp._started

    @pytest.mark.asyncio
    async def test_export_audit_entry(self):
        from mcpkernel.integrations.langfuse import LangfuseConfig, LangfuseExporter

        cfg = LangfuseConfig(
            enabled=True,
            public_key="pk",
            secret_key="sk",  # noqa: S106
            batch_size=100,
        )
        exp = LangfuseExporter(config=cfg)
        exp._started = True
        exp._client = AsyncMock()

        entry = MagicMock()
        entry.trace_id = "t1"
        entry.entry_id = "e1"
        entry.event_type = "tool_call"
        entry.tool_name = "exec"
        entry.agent_id = "agent"
        entry.action = "allow"
        entry.outcome = "success"
        entry.content_hash = "abc"
        entry.timestamp = time.time()

        await exp.export_audit_entry(entry)
        assert len(exp._batch) == 1

    @pytest.mark.asyncio
    async def test_export_dee_trace(self):
        from mcpkernel.integrations.langfuse import LangfuseConfig, LangfuseExporter

        cfg = LangfuseConfig(enabled=True, public_key="pk", secret_key="sk", batch_size=100)  # noqa: S106
        exp = LangfuseExporter(config=cfg)
        exp._started = True
        exp._client = AsyncMock()

        trace = {
            "trace_id": "dee-1",
            "tool_name": "exec",
            "duration_seconds": 0.5,
            "timestamp": time.time(),
            "input_hash": "ih",
            "output_hash": "oh",
        }
        await exp.export_dee_trace(trace)
        assert len(exp._batch) == 2  # trace-create + span-create

    @pytest.mark.asyncio
    async def test_flush_success(self):
        from mcpkernel.integrations.langfuse import LangfuseConfig, LangfuseExporter

        cfg = LangfuseConfig(enabled=True, public_key="pk", secret_key="sk")  # noqa: S106
        exp = LangfuseExporter(config=cfg)

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=mock_resp)

        exp._client = mock_client
        exp._batch = [{"id": "1", "type": "event-create"}]
        await exp.flush()
        assert len(exp._batch) == 0

    @pytest.mark.asyncio
    async def test_flush_rate_limited(self):
        from mcpkernel.integrations.langfuse import LangfuseConfig, LangfuseExporter

        cfg = LangfuseConfig(enabled=True, public_key="pk", secret_key="sk", max_retries=1)  # noqa: S106
        exp = LangfuseExporter(config=cfg)

        mock_resp_429 = MagicMock()
        mock_resp_429.status_code = 429
        mock_resp_200 = MagicMock()
        mock_resp_200.status_code = 200

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(side_effect=[mock_resp_429, mock_resp_200])

        exp._client = mock_client
        exp._batch = [{"id": "1"}]
        with patch("asyncio.sleep", new_callable=AsyncMock):
            await exp.flush()
        assert len(exp._batch) == 0

    @pytest.mark.asyncio
    async def test_flush_error_status(self):
        from mcpkernel.integrations.langfuse import LangfuseConfig, LangfuseExporter

        cfg = LangfuseConfig(enabled=True, public_key="pk", secret_key="sk")  # noqa: S106
        exp = LangfuseExporter(config=cfg)

        mock_resp = MagicMock()
        mock_resp.status_code = 500
        mock_resp.text = "Internal Server Error"

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=mock_resp)

        exp._client = mock_client
        exp._batch = [{"id": "1"}]
        await exp.flush()
        assert len(exp._batch) == 0  # batch cleared even on error

    @pytest.mark.asyncio
    async def test_flush_network_exception(self):
        from mcpkernel.integrations.langfuse import LangfuseConfig, LangfuseExporter

        cfg = LangfuseConfig(enabled=True, public_key="pk", secret_key="sk", max_retries=1)  # noqa: S106
        exp = LangfuseExporter(config=cfg)

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(side_effect=ConnectionError("network down"))

        exp._client = mock_client
        exp._batch = [{"id": "1"}]
        with patch("asyncio.sleep", new_callable=AsyncMock):
            await exp.flush()

    @pytest.mark.asyncio
    async def test_export_audit_entries_batch(self):
        from mcpkernel.integrations.langfuse import LangfuseConfig, LangfuseExporter

        cfg = LangfuseConfig(enabled=True, public_key="pk", secret_key="sk", batch_size=100)  # noqa: S106
        exp = LangfuseExporter(config=cfg)
        exp._started = True
        exp._client = AsyncMock()

        entries = []
        for i in range(3):
            e = MagicMock()
            e.trace_id = f"t{i}"
            e.entry_id = f"e{i}"
            e.event_type = "policy"
            e.tool_name = "tool"
            e.agent_id = "a"
            e.action = "allow"
            e.outcome = "ok"
            e.content_hash = "h"
            e.timestamp = time.time()
            e.details = {}
            entries.append(e)

        await exp.export_audit_entries(entries)
        assert len(exp._batch) == 3

    @pytest.mark.asyncio
    async def test_export_dee_traces_batch(self):
        from mcpkernel.integrations.langfuse import LangfuseConfig, LangfuseExporter

        cfg = LangfuseConfig(enabled=True, public_key="pk", secret_key="sk", batch_size=100)  # noqa: S106
        exp = LangfuseExporter(config=cfg)
        exp._started = True
        exp._client = AsyncMock()

        traces = [
            {"trace_id": "t1", "tool_name": "a", "timestamp": time.time()},
            {"trace_id": "t2", "tool_name": "b", "timestamp": time.time()},
        ]
        await exp.export_dee_traces(traces)
        assert len(exp._batch) == 4  # 2 traces x 2 events each

    @pytest.mark.asyncio
    async def test_flush_no_client(self):
        from mcpkernel.integrations.langfuse import LangfuseExporter

        exp = LangfuseExporter()
        exp._batch = [{"x": 1}]
        await exp.flush()  # should not raise
        assert len(exp._batch) == 1  # batch unchanged

    @pytest.mark.asyncio
    async def test_flush_empty_batch(self):
        from mcpkernel.integrations.langfuse import LangfuseExporter

        exp = LangfuseExporter()
        exp._client = AsyncMock()
        exp._batch = []
        await exp.flush()  # should not raise

    @pytest.mark.asyncio
    async def test_export_disabled(self):
        from mcpkernel.integrations.langfuse import LangfuseConfig, LangfuseExporter

        exp = LangfuseExporter(config=LangfuseConfig(enabled=False))
        entry = MagicMock()
        await exp.export_audit_entry(entry)
        assert len(exp._batch) == 0

    @pytest.mark.asyncio
    async def test_export_dee_trace_disabled(self):
        from mcpkernel.integrations.langfuse import LangfuseConfig, LangfuseExporter

        exp = LangfuseExporter(config=LangfuseConfig(enabled=False))
        await exp.export_dee_trace({"trace_id": "x"})
        assert len(exp._batch) == 0

    @pytest.mark.asyncio
    async def test_shutdown_not_started(self):
        from mcpkernel.integrations.langfuse import LangfuseExporter

        exp = LangfuseExporter()
        await exp.shutdown()  # should not raise


# ===================================================================
# Langfuse conversion helpers
# ===================================================================
class TestLangfuseConverters:
    def test_audit_entry_to_event_tool_call(self):
        from mcpkernel.integrations.langfuse import _audit_entry_to_langfuse_event

        entry = MagicMock()
        entry.trace_id = "t1"
        entry.entry_id = "e1"
        entry.event_type = "tool_call"
        entry.tool_name = "exec_code"
        entry.agent_id = "agent-1"
        entry.action = "allow"
        entry.outcome = "success"
        entry.content_hash = "abc123"
        entry.timestamp = time.time()

        event = _audit_entry_to_langfuse_event(entry, "myproject")
        assert event["type"] == "trace-create"
        assert "tool:exec_code" in event["body"]["tags"]

    def test_audit_entry_to_event_non_tool_call(self):
        from mcpkernel.integrations.langfuse import _audit_entry_to_langfuse_event

        entry = MagicMock()
        entry.trace_id = None
        entry.entry_id = "e2"
        entry.event_type = "policy_check"
        entry.tool_name = "read_file"
        entry.agent_id = "agent-2"
        entry.action = "block"
        entry.outcome = "denied"
        entry.content_hash = "xyz"
        entry.timestamp = time.time()
        entry.details = {"reason": "blocked"}

        event = _audit_entry_to_langfuse_event(entry, "proj")
        assert event["type"] == "event-create"

    def test_dee_trace_to_events(self):
        from mcpkernel.integrations.langfuse import _dee_trace_to_langfuse_events

        trace = {
            "trace_id": "dee-123",
            "tool_name": "calc",
            "duration_seconds": 1.5,
            "timestamp": time.time(),
            "input_hash": "ih",
            "output_hash": "oh",
        }
        events = _dee_trace_to_langfuse_events(trace, "proj")
        assert len(events) == 2
        assert events[0]["type"] == "trace-create"
        assert events[1]["type"] == "span-create"

    def test_epoch_to_iso(self):
        from mcpkernel.integrations.langfuse import _epoch_to_iso

        result = _epoch_to_iso(0.0)
        assert "1970" in result


# ===================================================================
# Agent Scan
# ===================================================================
class TestAgentScanReportToRules:
    """Cover report_to_policy_rules with remediation field."""

    def test_report_with_remediation(self):
        from mcpkernel.integrations.agent_scan import (
            AgentScanner,
            ScanFinding,
            ScanReport,
        )

        scanner = AgentScanner()
        report = ScanReport(
            findings=[
                ScanFinding(
                    rule_id="TEST-001",
                    severity="high",
                    title="Test Finding",
                    description="Test desc",
                    server_name="srv",
                    tool_name="tool",
                    category="security",
                    remediation="Fix by updating config",
                ),
            ],
        )
        rules = scanner.report_to_policy_rules(report)
        assert len(rules) == 1
        assert "Remediation:" in str(rules[0]["description"])

    def test_report_without_remediation(self):
        from mcpkernel.integrations.agent_scan import (
            AgentScanner,
            ScanFinding,
            ScanReport,
        )

        scanner = AgentScanner()
        report = ScanReport(
            findings=[
                ScanFinding(
                    rule_id="TEST-002",
                    severity="medium",
                    title="No Remediation",
                    description="Desc only",
                    category="quality",
                ),
            ],
        )
        rules = scanner.report_to_policy_rules(report)
        assert len(rules) == 1
        assert "Remediation:" not in str(rules[0]["description"])

    def test_report_critical_blocker(self):
        from mcpkernel.integrations.agent_scan import (
            AgentScanner,
            ScanFinding,
            ScanReport,
        )

        scanner = AgentScanner()
        report = ScanReport(
            findings=[
                ScanFinding(
                    rule_id="CRIT-001",
                    severity="critical",
                    title="Critical Finding",
                    description="Critical issue",
                    category="security",
                ),
            ],
        )
        rules = scanner.report_to_policy_rules(report)
        assert len(rules) == 1
        assert rules[0]["action"] == "deny"

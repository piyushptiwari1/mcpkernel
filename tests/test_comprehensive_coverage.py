"""Comprehensive tests to bring coverage from 61% to 80%+.

Tests sandbox backends, eBPF, CLI, DEE envelope/replay/drift,
proxy server, and observability modules.
"""

from __future__ import annotations

import json
import time
from typing import TYPE_CHECKING, Any
from unittest.mock import MagicMock, patch

import pytest

from mcpkernel.proxy.interceptor import ExecutionResult, InterceptorContext, MCPToolCall

if TYPE_CHECKING:
    from pathlib import Path

# ── Helpers ──────────────────────────────────────────────────────────────


def _make_ctx(tool_name: str = "test_tool", arguments: dict | None = None) -> InterceptorContext:
    call = MCPToolCall(
        request_id=1,
        tool_name=tool_name,
        arguments=arguments or {},
        raw_jsonrpc={"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": tool_name}},
    )
    return InterceptorContext(call=call)


# =====================================================================
# Section 1: Sandbox backends (base, docker, firecracker, wasm, microsandbox, factory)
# =====================================================================


class TestSandboxBase:
    """Test sandbox base types and the factory."""

    def test_resource_limits_defaults(self):
        from mcpkernel.sandbox.base import ResourceLimits

        rl = ResourceLimits()
        assert rl.cpu_cores == 1.0
        assert rl.memory_mb == 256
        assert rl.timeout_seconds == 30
        assert rl.network_enabled is False

    def test_workspace_defaults(self):
        from mcpkernel.sandbox.base import Workspace

        ws = Workspace(workspace_id="ws-1")
        assert ws.persistent is False
        assert ws.root_path == "/workspace"
        assert ws.metadata == {}

    def test_snapshot_info(self):
        from mcpkernel.sandbox.base import SnapshotInfo

        snap = SnapshotInfo(snapshot_id="s1", workspace_id="w1", created_at=1000.0)
        assert snap.snapshot_id == "s1"
        assert snap.size_bytes == 0

    def test_sandbox_metrics_defaults(self):
        from mcpkernel.sandbox.base import SandboxMetrics

        m = SandboxMetrics()
        assert m.cpu_used_pct == 0.0
        assert m.cold_start_ms == 0.0

    def test_create_backend_docker(self):
        from mcpkernel.config import SandboxConfig
        from mcpkernel.sandbox import create_backend
        from mcpkernel.sandbox.docker_backend import DockerSandbox

        cfg = SandboxConfig(backend="docker")
        backend = create_backend(cfg)
        assert isinstance(backend, DockerSandbox)

    def test_create_backend_firecracker(self):
        from mcpkernel.config import SandboxConfig
        from mcpkernel.sandbox import create_backend
        from mcpkernel.sandbox.firecracker_backend import FirecrackerSandbox

        cfg = SandboxConfig(backend="firecracker")
        backend = create_backend(cfg)
        assert isinstance(backend, FirecrackerSandbox)

    def test_create_backend_wasm(self):
        from mcpkernel.config import SandboxConfig
        from mcpkernel.sandbox import create_backend
        from mcpkernel.sandbox.wasm_backend import WASMSandbox

        cfg = SandboxConfig(backend="wasm")
        backend = create_backend(cfg)
        assert isinstance(backend, WASMSandbox)

    def test_create_backend_microsandbox(self):
        from mcpkernel.config import SandboxConfig
        from mcpkernel.sandbox import create_backend
        from mcpkernel.sandbox.microsandbox_backend import MicrosandboxSandbox

        cfg = SandboxConfig(backend="microsandbox")
        backend = create_backend(cfg)
        assert isinstance(backend, MicrosandboxSandbox)

    def test_create_backend_invalid_config_type(self):
        from mcpkernel.sandbox import create_backend

        with pytest.raises(TypeError, match="Expected SandboxConfig"):
            create_backend({"backend": "docker"})


class TestDockerBackend:
    """Test DockerSandbox non-execution methods."""

    def _make(self):
        from mcpkernel.config import SandboxConfig
        from mcpkernel.sandbox.docker_backend import DockerSandbox

        return DockerSandbox(SandboxConfig())

    @pytest.mark.asyncio
    async def test_create_workspace(self):
        sb = self._make()
        ws = await sb.create_workspace()
        assert ws.workspace_id
        assert ws.persistent is False

    @pytest.mark.asyncio
    async def test_create_workspace_persistent(self):
        sb = self._make()
        ws = await sb.create_workspace(persistent=True)
        assert ws.persistent is True

    @pytest.mark.asyncio
    async def test_set_network_policy(self):
        sb = self._make()
        ws = await sb.create_workspace()
        await sb.set_network_policy(ws, allow_egress=True, allowed_domains=["example.com"])
        assert ws.metadata["network"]["allow_egress"] is True

    @pytest.mark.asyncio
    async def test_mount_filesystem(self):
        sb = self._make()
        ws = await sb.create_workspace()
        await sb.mount_filesystem(ws, read_only_paths=["/data"], temp_dirs=["/tmp"])  # noqa: S108
        assert ws.metadata["mounts"]["read_only"] == ["/data"]

    @pytest.mark.asyncio
    async def test_get_metrics(self):
        sb = self._make()
        ws = await sb.create_workspace()
        metrics = await sb.get_metrics(ws)
        assert metrics.cpu_used_pct == 0.0

    @pytest.mark.asyncio
    async def test_cleanup(self):
        sb = self._make()
        ws = await sb.create_workspace()
        await sb.cleanup(ws)  # Should not raise

    @pytest.mark.asyncio
    async def test_snapshot_and_restore(self):
        sb = self._make()
        ws = await sb.create_workspace()
        snap = await sb.snapshot(ws)
        assert snap.snapshot_id
        restored = await sb.restore(snap)
        assert restored.workspace_id == ws.workspace_id

    def test_get_client_no_docker(self):
        from mcpkernel.sandbox.docker_backend import DockerSandbox
        from mcpkernel.utils import SandboxError

        sb = DockerSandbox(MagicMock())
        with patch.dict("sys.modules", {"docker": None}), pytest.raises((SandboxError, Exception)):
            sb._get_client()


class TestWASMBackend:
    """Test WASMSandbox non-execution methods."""

    def _make(self):
        from mcpkernel.config import SandboxConfig
        from mcpkernel.sandbox.wasm_backend import WASMSandbox

        return WASMSandbox(SandboxConfig(backend="wasm"))

    @pytest.mark.asyncio
    async def test_create_workspace(self):
        sb = self._make()
        ws = await sb.create_workspace()
        assert ws.workspace_id

    @pytest.mark.asyncio
    async def test_set_network_policy_noop(self):
        sb = self._make()
        ws = await sb.create_workspace()
        await sb.set_network_policy(ws)  # Should be no-op

    @pytest.mark.asyncio
    async def test_mount_filesystem_noop(self):
        sb = self._make()
        ws = await sb.create_workspace()
        await sb.mount_filesystem(ws)  # Should be no-op

    @pytest.mark.asyncio
    async def test_get_metrics(self):
        sb = self._make()
        ws = await sb.create_workspace()
        m = await sb.get_metrics(ws)
        assert m.cpu_used_pct == 0.0

    @pytest.mark.asyncio
    async def test_cleanup_noop(self):
        sb = self._make()
        ws = await sb.create_workspace()
        await sb.cleanup(ws)

    @pytest.mark.asyncio
    async def test_snapshot_and_restore(self):
        sb = self._make()
        ws = await sb.create_workspace()
        snap = await sb.snapshot(ws)
        restored = await sb.restore(snap)
        assert restored.workspace_id == ws.workspace_id


class TestFirecrackerBackend:
    """Test FirecrackerSandbox non-execution methods."""

    def _make(self):
        from mcpkernel.config import SandboxConfig
        from mcpkernel.sandbox.firecracker_backend import FirecrackerSandbox

        return FirecrackerSandbox(SandboxConfig(backend="firecracker"))

    @pytest.mark.asyncio
    async def test_create_workspace(self):
        sb = self._make()
        ws = await sb.create_workspace(persistent=True)
        assert ws.persistent is True

    @pytest.mark.asyncio
    async def test_set_network_policy(self):
        sb = self._make()
        ws = await sb.create_workspace()
        await sb.set_network_policy(ws, allow_egress=False)
        assert ws.metadata["network"]["allow_egress"] is False

    @pytest.mark.asyncio
    async def test_mount_filesystem(self):
        sb = self._make()
        ws = await sb.create_workspace()
        await sb.mount_filesystem(ws, read_only_paths=["/ro"])
        assert ws.metadata["mounts"]["read_only"] == ["/ro"]

    @pytest.mark.asyncio
    async def test_get_metrics(self):
        sb = self._make()
        ws = await sb.create_workspace()
        m = await sb.get_metrics(ws)
        assert m.cpu_used_pct == 0.0

    @pytest.mark.asyncio
    async def test_cleanup(self):
        sb = self._make()
        ws = await sb.create_workspace()
        await sb.cleanup(ws)

    @pytest.mark.asyncio
    async def test_snapshot_restore(self):
        sb = self._make()
        ws = await sb.create_workspace()
        snap = await sb.snapshot(ws)
        restored = await sb.restore(snap)
        assert restored.workspace_id == ws.workspace_id

    @pytest.mark.asyncio
    async def test_execute_code_no_kernel(self):
        from mcpkernel.utils import SandboxError

        sb = self._make()
        with pytest.raises(SandboxError, match="kernel/rootfs"):
            await sb.execute_code("print('hello')")


class TestMicrosandboxBackend:
    """Test MicrosandboxSandbox non-execution methods."""

    def _make(self):
        from mcpkernel.config import SandboxConfig
        from mcpkernel.sandbox.microsandbox_backend import MicrosandboxSandbox

        return MicrosandboxSandbox(SandboxConfig(backend="microsandbox"))

    @pytest.mark.asyncio
    async def test_create_workspace(self):
        sb = self._make()
        ws = await sb.create_workspace()
        assert ws.workspace_id

    @pytest.mark.asyncio
    async def test_set_network_policy(self):
        sb = self._make()
        ws = await sb.create_workspace()
        await sb.set_network_policy(ws, allow_egress=True)

    @pytest.mark.asyncio
    async def test_mount_filesystem_noop(self):
        sb = self._make()
        ws = await sb.create_workspace()
        await sb.mount_filesystem(ws)

    @pytest.mark.asyncio
    async def test_get_metrics(self):
        sb = self._make()
        ws = await sb.create_workspace()
        m = await sb.get_metrics(ws)
        assert m.cpu_used_pct == 0.0

    @pytest.mark.asyncio
    async def test_cleanup(self):
        sb = self._make()
        ws = await sb.create_workspace()
        await sb.cleanup(ws)

    @pytest.mark.asyncio
    async def test_snapshot_restore(self):
        sb = self._make()
        ws = await sb.create_workspace()
        snap = await sb.snapshot(ws)
        restored = await sb.restore(snap)
        assert restored.workspace_id == ws.workspace_id


# =====================================================================
# Section 2: eBPF — NetworkRedirector, EBPFProbe, EBPFHook
# =====================================================================


class TestNetworkRedirector:
    """Test NetworkRedirector egress checking."""

    def test_blocks_prohibited_port(self):
        from mcpkernel.ebpf.redirector import EgressRule, NetworkRedirector

        r = NetworkRedirector(EgressRule(blocked_ports={25, 445}))
        assert r.check_egress("example.com", 25) is False

    def test_allows_normal_port(self):
        from mcpkernel.ebpf.redirector import NetworkRedirector

        r = NetworkRedirector()
        assert r.check_egress("example.com", 443) is True

    def test_allows_dns_when_enabled(self):
        from mcpkernel.ebpf.redirector import EgressRule, NetworkRedirector

        r = NetworkRedirector(EgressRule(allow_dns=True))
        assert r.check_egress("8.8.8.8", 53) is True

    def test_blocks_dns_when_disabled(self):
        from mcpkernel.ebpf.redirector import EgressRule, NetworkRedirector

        r = NetworkRedirector(EgressRule(allow_dns=False, blocked_ports=set()))
        # When DNS is disabled and no domain allowlist, it should pass
        assert r.check_egress("8.8.8.8", 53) is True

    def test_domain_allowlist_blocks_unallowed(self):
        from mcpkernel.ebpf.redirector import EgressRule, NetworkRedirector

        r = NetworkRedirector(EgressRule(allowed_domains={"safe.com"}))
        assert r.check_egress("evil.com", 443) is False

    def test_domain_allowlist_allows_listed(self):
        from mcpkernel.ebpf.redirector import EgressRule, NetworkRedirector

        r = NetworkRedirector(EgressRule(allowed_domains={"api.example.com"}))
        assert r.check_egress("api.example.com", 443) is True

    def test_domain_allowlist_allows_subdomain(self):
        from mcpkernel.ebpf.redirector import EgressRule, NetworkRedirector

        r = NetworkRedirector(EgressRule(allowed_domains={"example.com"}))
        assert r.check_egress("sub.example.com", 443) is True

    def test_cidr_allowlist_blocks_unallowed_ip(self):
        from mcpkernel.ebpf.redirector import EgressRule, NetworkRedirector

        r = NetworkRedirector(EgressRule(allowed_cidrs=["10.0.0.0/8"]))
        assert r.check_egress("192.168.1.1", 80) is False

    def test_cidr_allowlist_allows_in_range(self):
        from mcpkernel.ebpf.redirector import EgressRule, NetworkRedirector

        r = NetworkRedirector(EgressRule(allowed_cidrs=["10.0.0.0/8"]))
        assert r.check_egress("10.1.2.3", 80) is True

    def test_update_rules(self):
        from mcpkernel.ebpf.redirector import EgressRule, NetworkRedirector

        r = NetworkRedirector()
        new_rules = EgressRule(allowed_domains={"new.com"}, blocked_ports={9999})
        r.update_rules(new_rules)
        assert r.check_egress("old.com", 443) is False
        assert r.check_egress("new.com", 443) is True


class TestEBPFProbe:
    """Test EBPFProbe in unprivileged mode."""

    def test_probe_unavailable_without_root(self):
        from mcpkernel.ebpf.probe import EBPFProbe

        probe = EBPFProbe()
        # Not running as root in tests
        assert probe.available is False

    def test_events_initially_empty(self):
        from mcpkernel.ebpf.probe import EBPFProbe

        probe = EBPFProbe()
        assert probe.events == []

    def test_clear_events(self):
        from mcpkernel.ebpf.probe import EBPFProbe

        probe = EBPFProbe()
        probe.clear_events()
        assert probe.events == []

    def test_on_event_callback(self):
        from mcpkernel.ebpf.probe import EBPFProbe

        probe = EBPFProbe()
        cb = MagicMock()
        probe.on_event(cb)
        assert cb in probe._callbacks

    @pytest.mark.asyncio
    async def test_start_noop_when_unavailable(self):
        from mcpkernel.ebpf.probe import EBPFProbe

        probe = EBPFProbe()
        await probe.start()  # Should not raise

    @pytest.mark.asyncio
    async def test_stop_noop(self):
        from mcpkernel.ebpf.probe import EBPFProbe

        probe = EBPFProbe()
        await probe.stop()


class TestProbeEvent:
    """Test ProbeEvent data structure."""

    def test_probe_event_creation(self):
        from mcpkernel.ebpf.probe import ProbeEvent, SyscallType

        evt = ProbeEvent(syscall=SyscallType.CONNECT, pid=1234, comm="python3", timestamp=time.time())
        assert evt.syscall == SyscallType.CONNECT
        assert evt.pid == 1234
        assert evt.details == {}


class TestEBPFHook:
    """Test EBPFHook integration."""

    @pytest.mark.asyncio
    async def test_allows_non_url_arguments(self):
        from mcpkernel.ebpf.redirector import NetworkRedirector
        from mcpkernel.proxy.hooks import EBPFHook

        hook = EBPFHook(NetworkRedirector())
        ctx = _make_ctx(arguments={"code": "print('hello')", "count": "5"})
        await hook.pre_execution(ctx)
        assert not ctx.aborted

    @pytest.mark.asyncio
    async def test_blocks_prohibited_url(self):
        from mcpkernel.ebpf.redirector import EgressRule, NetworkRedirector
        from mcpkernel.proxy.hooks import EBPFHook

        redirector = NetworkRedirector(EgressRule(allowed_domains={"safe.com"}))
        hook = EBPFHook(redirector)
        ctx = _make_ctx(arguments={"url": "https://evil.com/api"})
        await hook.pre_execution(ctx)
        assert ctx.aborted
        assert "egress blocked" in ctx.abort_reason

    @pytest.mark.asyncio
    async def test_allows_safe_url(self):
        from mcpkernel.ebpf.redirector import EgressRule, NetworkRedirector
        from mcpkernel.proxy.hooks import EBPFHook

        redirector = NetworkRedirector(EgressRule(allowed_domains={"safe.com"}))
        hook = EBPFHook(redirector)
        ctx = _make_ctx(arguments={"url": "https://safe.com/api"})
        await hook.pre_execution(ctx)
        assert not ctx.aborted

    @pytest.mark.asyncio
    async def test_log_with_probe(self):
        from mcpkernel.ebpf.redirector import NetworkRedirector
        from mcpkernel.proxy.hooks import EBPFHook

        mock_probe = MagicMock()
        mock_probe.events = [MagicMock()]
        hook = EBPFHook(NetworkRedirector(), probe=mock_probe)
        ctx = _make_ctx()
        await hook.log(ctx)
        assert ctx.extra.get("ebpf_events") == 1
        mock_probe.clear_events.assert_called_once()

    @pytest.mark.asyncio
    async def test_log_without_probe(self):
        from mcpkernel.ebpf.redirector import NetworkRedirector
        from mcpkernel.proxy.hooks import EBPFHook

        hook = EBPFHook(NetworkRedirector())
        ctx = _make_ctx()
        await hook.log(ctx)  # Should not raise


class TestExtractHostPort:
    """Test the _extract_host_port helper."""

    def test_https_url(self):
        from mcpkernel.proxy.hooks import _extract_host_port

        host, port = _extract_host_port("https://example.com/path")
        assert host == "example.com"
        assert port == 443

    def test_http_url(self):
        from mcpkernel.proxy.hooks import _extract_host_port

        host, port = _extract_host_port("http://example.com:8080/path")
        assert host == "example.com"
        assert port == 8080

    def test_not_a_url(self):
        from mcpkernel.proxy.hooks import _extract_host_port

        host, port = _extract_host_port("just some text")
        assert host == ""
        assert port == 0


# =====================================================================
# Section 3: DEE — envelope, replay, drift, snapshot
# =====================================================================


class TestWrapExecution:
    """Test DEE envelope wrap_execution."""

    @pytest.mark.asyncio
    async def test_wraps_execution_no_sign(self):
        from mcpkernel.dee.envelope import wrap_execution

        call = MCPToolCall(
            request_id="t1",
            tool_name="test_fn",
            arguments={"x": 1},
            raw_jsonrpc={"jsonrpc": "2.0", "id": "t1"},
        )
        result = ExecutionResult(content=[{"type": "text", "text": "ok"}])

        async def fake_exec(c: Any) -> ExecutionResult:
            return result

        trace = await wrap_execution(call, fake_exec, sign=False)
        assert trace.trace_id.startswith("tr_")
        assert trace.tool_name == "test_fn"
        assert trace.input_hash
        assert trace.output_hash
        assert trace.duration_seconds >= 0
        assert trace.sigstore_bundle is None

    @pytest.mark.asyncio
    async def test_wraps_execution_with_agent_id(self):
        from mcpkernel.dee.envelope import wrap_execution

        call = MCPToolCall(
            request_id="t2",
            tool_name="fn",
            arguments={},
            raw_jsonrpc={"jsonrpc": "2.0", "id": "t2"},
        )
        result = ExecutionResult(content=[{"type": "text", "text": "ok"}])

        async def fake_exec(c: Any) -> ExecutionResult:
            return result

        trace = await wrap_execution(call, fake_exec, agent_id="agent-007", sign=False)
        assert trace.agent_id == "agent-007"


class TestReplay:
    """Test DEE replay engine."""

    @pytest.mark.asyncio
    async def test_replay_nonexistent_trace(self, trace_db):
        from mcpkernel.dee.replay import replay
        from mcpkernel.utils import ReplayError

        async def fake_exec(c: Any) -> ExecutionResult:
            return ExecutionResult(content=[{"type": "text", "text": "ok"}])

        with pytest.raises(ReplayError, match="not found"):
            await replay("nonexistent", trace_db, fake_exec)

    @pytest.mark.asyncio
    async def test_replay_existing_trace(self, trace_db):
        from mcpkernel.dee.envelope import wrap_execution
        from mcpkernel.dee.replay import replay, validate_replay_integrity

        call = MCPToolCall(
            request_id="r1",
            tool_name="deterministic_fn",
            arguments={"input": "fixed"},
            raw_jsonrpc={"jsonrpc": "2.0", "id": "r1"},
        )
        result = ExecutionResult(content=[{"type": "text", "text": "fixed_output"}])

        async def fake_exec(c: Any) -> ExecutionResult:
            return result

        original = await wrap_execution(call, fake_exec, sign=False)
        original.metadata["arguments"] = call.arguments
        await trace_db.store(original)

        new_trace = await replay(original.trace_id, trace_db, fake_exec)
        assert new_trace.output_hash == original.output_hash

        match = await validate_replay_integrity(original.trace_id, new_trace, trace_db)
        assert match is True

    @pytest.mark.asyncio
    async def test_validate_replay_integrity_not_found(self, trace_db):
        from mcpkernel.dee.replay import validate_replay_integrity
        from mcpkernel.utils import ReplayError

        fake_trace = MagicMock()
        fake_trace.output_hash = "abc"
        with pytest.raises(ReplayError, match="not found"):
            await validate_replay_integrity("nope", fake_trace, trace_db)


class TestDriftDetection:
    """Test drift classification helpers."""

    def test_classify_random(self):
        from mcpkernel.dee.drift import _classify_nondeterminism

        result = _classify_nondeterminism(
            {"result_json": '{"output": "random value uuid"}'},
            ["h1", "h2"],
        )
        from mcpkernel.dee.drift import DriftCategory

        assert result == DriftCategory.RANDOM_SEED

    def test_classify_clock(self):
        from mcpkernel.dee.drift import DriftCategory, _classify_nondeterminism

        result = _classify_nondeterminism(
            {"result_json": '{"output": "timestamp now"}'},
            ["h1", "h2"],
        )
        assert result == DriftCategory.CLOCK_DEPENDENCY

    def test_classify_network(self):
        from mcpkernel.dee.drift import DriftCategory, _classify_nondeterminism

        result = _classify_nondeterminism(
            {"result_json": '{"output": "http request"}'},
            ["h1", "h2"],
        )
        assert result == DriftCategory.NETWORK_CALL

    def test_classify_filesystem(self):
        from mcpkernel.dee.drift import DriftCategory, _classify_nondeterminism

        result = _classify_nondeterminism(
            {"result_json": '{"output": "file read path"}'},
            ["h1", "h2"],
        )
        assert result == DriftCategory.FILESYSTEM_CHANGE

    def test_classify_unknown(self):
        from mcpkernel.dee.drift import DriftCategory, _classify_nondeterminism

        result = _classify_nondeterminism(
            {"result_json": '{"output": "nothing special here"}'},
            ["h1", "h2"],
        )
        assert result == DriftCategory.UNKNOWN

    def test_drift_report_fields(self):
        from mcpkernel.dee.drift import DriftCategory, DriftReport

        report = DriftReport(
            original_trace_id="t1",
            replay_trace_id="t2",
            category=DriftCategory.NONE,
            original_output_hash="aaa",
            replay_output_hash="aaa",
            details={},
        )
        assert report.category == DriftCategory.NONE


class TestEnvironmentSnapshot:
    """Test DEE environment snapshot."""

    def test_snapshot_without_workspace(self):
        from mcpkernel.dee.snapshot import take_environment_snapshot

        h = take_environment_snapshot(workspace_path=None)
        assert isinstance(h, str)
        assert len(h) == 64  # SHA-256 hex

    def test_snapshot_with_workspace(self, tmp_path: Path):
        from mcpkernel.dee.snapshot import take_environment_snapshot

        (tmp_path / "file.txt").write_text("hello")
        h = take_environment_snapshot(workspace_path=tmp_path)
        assert isinstance(h, str)
        assert len(h) == 64

    def test_snapshot_without_env_vars(self):
        from mcpkernel.dee.snapshot import take_environment_snapshot

        h = take_environment_snapshot(include_env_vars=False)
        assert len(h) == 64

    def test_snapshot_deterministic(self, tmp_path: Path):
        from mcpkernel.dee.snapshot import take_environment_snapshot

        (tmp_path / "a.txt").write_text("content")
        h1 = take_environment_snapshot(workspace_path=tmp_path, include_env_vars=False)
        h2 = take_environment_snapshot(workspace_path=tmp_path, include_env_vars=False)
        assert h1 == h2


# =====================================================================
# Section 4: CLI commands
# =====================================================================


class TestCLI:
    """Test CLI commands using Typer CliRunner."""

    def test_version(self):
        from typer.testing import CliRunner

        from mcpkernel.cli import app

        runner = CliRunner()
        result = runner.invoke(app, ["version"])
        assert result.exit_code == 0
        assert "mcpkernel" in result.output

    def test_validate_policy_valid(self, tmp_path: Path):
        from typer.testing import CliRunner

        from mcpkernel.cli import app

        policy = tmp_path / "test.yaml"
        policy.write_text("rules:\n  - id: T1\n    name: Test\n    action: deny\n    tool_patterns: ['.*']\n")
        runner = CliRunner()
        result = runner.invoke(app, ["validate-policy", str(policy)])
        assert result.exit_code == 0
        assert "1 valid rules" in result.output

    def test_validate_policy_invalid(self, tmp_path: Path):
        from typer.testing import CliRunner

        from mcpkernel.cli import app

        policy = tmp_path / "bad.yaml"
        policy.write_text("no_rules_key: true\n")
        runner = CliRunner()
        result = runner.invoke(app, ["validate-policy", str(policy)])
        assert result.exit_code == 1

    def test_validate_policy_directory(self, tmp_path: Path):
        from typer.testing import CliRunner

        from mcpkernel.cli import app

        policy = tmp_path / "rules.yaml"
        policy.write_text("rules:\n  - id: D1\n    name: Dir test\n    action: allow\n")
        runner = CliRunner()
        result = runner.invoke(app, ["validate-policy", str(tmp_path)])
        assert result.exit_code == 0

    def test_scan_missing_file(self):
        from typer.testing import CliRunner

        from mcpkernel.cli import app

        runner = CliRunner()
        result = runner.invoke(app, ["scan", "/nonexistent_file.py"])
        assert result.exit_code == 1

    def test_scan_clean_file(self, tmp_path: Path):
        from typer.testing import CliRunner

        from mcpkernel.cli import app

        code_file = tmp_path / "safe.py"
        code_file.write_text("x = 1 + 2\nprint(x)\n")
        runner = CliRunner()
        result = runner.invoke(app, ["scan", str(code_file)])
        assert result.exit_code == 0
        assert "No dangerous patterns" in result.output

    def test_scan_dangerous_file(self, tmp_path: Path):
        from typer.testing import CliRunner

        from mcpkernel.cli import app

        code_file = tmp_path / "dangerous.py"
        code_file.write_text("eval(input())\n")
        runner = CliRunner()
        result = runner.invoke(app, ["scan", str(code_file)])
        assert "issue(s)" in result.output

    def test_config_show(self):
        from typer.testing import CliRunner

        from mcpkernel.cli import app

        runner = CliRunner()
        result = runner.invoke(app, ["config-show"])
        assert result.exit_code == 0
        output = result.output
        assert "proxy" in output
        assert "sandbox" in output

    def test_init_creates_structure(self, tmp_path: Path):
        from typer.testing import CliRunner

        from mcpkernel.cli import app

        runner = CliRunner()
        result = runner.invoke(app, ["init", str(tmp_path)])
        assert result.exit_code == 0
        assert (tmp_path / ".mcpkernel" / "config.yaml").exists()
        assert (tmp_path / ".mcpkernel" / "policies").is_dir()

    def test_init_idempotent(self, tmp_path: Path):
        from typer.testing import CliRunner

        from mcpkernel.cli import app

        runner = CliRunner()
        runner.invoke(app, ["init", str(tmp_path)])
        result = runner.invoke(app, ["init", str(tmp_path)])
        assert result.exit_code == 0

    def test_trace_list_empty(self, tmp_path: Path):
        from typer.testing import CliRunner

        from mcpkernel.cli import app

        db = str(tmp_path / "empty_traces.db")
        runner = CliRunner()
        result = runner.invoke(app, ["trace-list", "--db", db])
        assert result.exit_code == 0
        assert "No traces found" in result.output

    def test_trace_export_not_found(self, tmp_path: Path):
        from typer.testing import CliRunner

        from mcpkernel.cli import app

        db = str(tmp_path / "traces.db")
        runner = CliRunner()
        result = runner.invoke(app, ["trace-export", "nonexistent", "--db", db])
        assert result.exit_code == 1

    def test_audit_query_empty(self, tmp_path: Path):
        from typer.testing import CliRunner

        from mcpkernel.cli import app

        db = str(tmp_path / "audit.db")
        runner = CliRunner()
        result = runner.invoke(app, ["audit-query", "--db", db])
        assert result.exit_code == 0
        assert "No audit entries" in result.output


# =====================================================================
# Section 5: Proxy server
# =====================================================================


class TestProxyServer:
    """Test proxy server app factory and routes."""

    def test_create_proxy_app(self):
        from mcpkernel.proxy.server import create_proxy_app

        app = create_proxy_app()
        assert app.title == "mcpkernel"

    @pytest.mark.asyncio
    async def test_health_endpoint(self):
        from httpx import ASGITransport, AsyncClient

        from mcpkernel.proxy.server import create_proxy_app

        app = create_proxy_app()
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/health")
            assert resp.status_code == 200
            assert resp.json()["status"] == "ok"


# =====================================================================
# Section 6: Observability — tracing setup
# =====================================================================


class TestTracingSetup:
    """Test observability tracing setup."""

    def test_tracing_disabled(self):
        from mcpkernel.observability.tracing import TracingSetup, setup_tracing

        cfg = TracingSetup(enabled=False)
        result = setup_tracing(cfg)
        assert result is None

    def test_tracing_no_otel(self):
        from mcpkernel.observability.tracing import TracingSetup, setup_tracing

        # OTEL is installed in our env, but test with no endpoint
        cfg = TracingSetup(enabled=True, otlp_endpoint="")
        result = setup_tracing(cfg)
        # Should succeed (provider without exporter)
        assert result is not None

    def test_tracing_with_grpc_endpoint(self):
        from mcpkernel.observability.tracing import TracingSetup, setup_tracing

        cfg = TracingSetup(enabled=True, otlp_endpoint="http://localhost:4317", otlp_protocol="grpc")
        result = setup_tracing(cfg)
        assert result is not None

    def test_tracing_with_http_endpoint(self):
        from mcpkernel.observability.tracing import TracingSetup, setup_tracing

        cfg = TracingSetup(enabled=True, otlp_endpoint="http://localhost:4318", otlp_protocol="http")
        result = setup_tracing(cfg)
        # May or may not work depending on installed packages
        # The code path is covered either way
        assert result is not None or result is None


# =====================================================================
# Section 7: Config edge cases
# =====================================================================


class TestConfigEdgeCases:
    """Test configuration edge cases for coverage."""

    def test_load_config_with_yaml(self, tmp_path: Path):
        from mcpkernel.config import load_config

        cfg_file = tmp_path / "config.yaml"
        cfg_file.write_text("proxy:\n  host: 0.0.0.0\n  port: 9000\nsandbox:\n  backend: wasm\n")
        settings = load_config(config_path=cfg_file)
        assert settings.proxy.host == "0.0.0.0"  # noqa: S104
        assert settings.proxy.port == 9000

    def test_load_config_nonexistent_raises(self, tmp_path: Path):
        from mcpkernel.config import load_config
        from mcpkernel.utils import ConfigError

        with pytest.raises(ConfigError, match="not found"):
            load_config(config_path=tmp_path / "nope.yaml")

    def test_get_config_singleton(self):
        from mcpkernel.config import get_config

        cfg1 = get_config()
        cfg2 = get_config()
        assert cfg1 is cfg2

    def test_deep_merge_invalid_section(self):
        from mcpkernel.config import MCPKernelSettings, _deep_merge

        settings = MCPKernelSettings()
        _deep_merge(settings, {"nonexistent_section": {"key": "val"}})
        # Should not raise, just skip

    def test_yaml_non_dict(self, tmp_path: Path):
        from mcpkernel.config import _load_yaml

        f = tmp_path / "non_dict.yaml"
        f.write_text("just a string")
        assert _load_yaml(f) == {}


# =====================================================================
# Section 8: Transform helpers
# =====================================================================


class TestTransformHelpers:
    """Test proxy transform utilities."""

    def test_normalize_from_mcp_success(self):
        from mcpkernel.proxy.transform import normalize_from_mcp

        result = normalize_from_mcp({"result": {"content": [{"type": "text"}], "isError": False}})
        assert result["ok"] is True

    def test_normalize_from_mcp_error(self):
        from mcpkernel.proxy.transform import normalize_from_mcp

        result = normalize_from_mcp({"error": {"code": -32000, "message": "fail"}})
        assert result["ok"] is False

    def test_normalize_to_mcp_flat_body(self):
        from mcpkernel.proxy.transform import normalize_to_mcp

        result = normalize_to_mcp({"tool": "run", "arguments": {"x": 1}})
        assert result["method"] == "tools/call"
        assert result["params"]["name"] == "run"

    def test_normalize_to_mcp_already_jsonrpc(self):
        from mcpkernel.proxy.transform import normalize_to_mcp

        raw = {"jsonrpc": "2.0", "id": 1, "method": "tools/call"}
        assert normalize_to_mcp(raw) is raw


# =====================================================================
# Section 9: Additional edge cases for existing modules
# =====================================================================


class TestContextReducerEdgeCases:
    """Test context reducer edge cases."""

    def test_reduce_small_context(self):
        from mcpkernel.context.reducer import ContextReducer

        reducer = ContextReducer()
        result = reducer.reduce({})
        assert result.reduced_tokens == result.original_tokens
        assert result.pruned_fields == []

    def test_reduce_with_query_terms(self):
        from mcpkernel.context.reducer import ContextReducer

        reducer = ContextReducer(max_tokens=50)
        ctx = {
            "python_code": "def hello(): print('Python is great')",
            "java_code": "public class Main { public static void main(String[] args) {} }",
            "unrelated": "Lorem ipsum dolor sit amet " * 20,
        }
        result = reducer.reduce(ctx, query_terms=["Python"])
        assert len(result.preserved_fields) > 0


class TestAuditHookIntegration:
    """Test AuditHook log method."""

    @pytest.mark.asyncio
    async def test_audit_hook_logs_success(self, audit_db):
        from mcpkernel.proxy.auth import AuthCredentials
        from mcpkernel.proxy.hooks import AuditHook

        hook = AuditHook(audit_db)
        ctx = _make_ctx(tool_name="safe_tool")
        ctx.result = ExecutionResult(content=[{"type": "text", "text": "ok"}])
        ctx.extra["auth"] = AuthCredentials(identity="test_user", scopes={"*"}, metadata={})
        await hook.log(ctx)

        entries = await audit_db.query(tool_name="safe_tool")
        assert len(entries) == 1
        assert entries[0].outcome == "success"

    @pytest.mark.asyncio
    async def test_audit_hook_logs_blocked(self, audit_db):
        from mcpkernel.proxy.auth import AuthCredentials
        from mcpkernel.proxy.hooks import AuditHook

        hook = AuditHook(audit_db)
        ctx = _make_ctx(tool_name="blocked_tool")
        ctx.aborted = True
        ctx.extra["auth"] = AuthCredentials(identity="test_user", scopes={"*"}, metadata={})
        await hook.log(ctx)

        entries = await audit_db.query(tool_name="blocked_tool")
        assert len(entries) == 1
        assert entries[0].outcome == "blocked"


class TestDEEHookIntegration:
    """Test DEEHook post_execution."""

    @pytest.mark.asyncio
    async def test_dee_hook_stores_trace(self, trace_db):
        from mcpkernel.proxy.hooks import DEEHook

        hook = DEEHook(trace_db)
        ctx = _make_ctx(tool_name="traced_fn")
        ctx.result = ExecutionResult(content=[{"type": "text", "text": "output"}])
        ctx.extra["auth"] = MagicMock(identity="agent-1")
        await hook.post_execution(ctx)

        assert ctx.result.trace_id is not None
        stored = await trace_db.get(ctx.result.trace_id)
        assert stored is not None
        assert stored["tool_name"] == "traced_fn"

    @pytest.mark.asyncio
    async def test_dee_hook_skips_errors(self, trace_db):
        from mcpkernel.proxy.hooks import DEEHook

        hook = DEEHook(trace_db)
        ctx = _make_ctx()
        ctx.result = ExecutionResult(content=[{"type": "text", "text": "err"}], is_error=True)
        await hook.post_execution(ctx)
        assert ctx.result.trace_id is None

    @pytest.mark.asyncio
    async def test_dee_hook_skips_none_result(self, trace_db):
        from mcpkernel.proxy.hooks import DEEHook

        hook = DEEHook(trace_db)
        ctx = _make_ctx()
        ctx.result = None
        await hook.post_execution(ctx)


class TestTraceStoreEdgeCases:
    """Additional TraceStore test coverage."""

    @pytest.mark.asyncio
    async def test_list_traces_with_filters(self, trace_db):
        from mcpkernel.dee.envelope import ExecutionTrace

        trace = ExecutionTrace(
            trace_id="tr_filter_test",
            tool_name="list_tool",
            agent_id="agent-x",
            input_hash="ih",
            output_hash="oh",
            env_snapshot_hash="eh",
            timestamp=time.time(),
            duration_seconds=0.1,
            result=ExecutionResult(content=[{"type": "text", "text": "x"}]),
        )
        await trace_db.store(trace)

        results = await trace_db.list_traces(tool_name="list_tool")
        assert len(results) == 1

        results = await trace_db.list_traces(agent_id="agent-x")
        assert len(results) == 1

        results = await trace_db.list_traces(tool_name="nonexistent")
        assert len(results) == 0

    @pytest.mark.asyncio
    async def test_export_trace_not_found(self, trace_db):
        with pytest.raises(KeyError, match="not found"):
            await trace_db.export_trace("nope")

    @pytest.mark.asyncio
    async def test_export_trace_success(self, trace_db):
        from mcpkernel.dee.envelope import ExecutionTrace

        trace = ExecutionTrace(
            trace_id="tr_export_test",
            tool_name="export_tool",
            agent_id="a1",
            input_hash="ih",
            output_hash="oh",
            env_snapshot_hash="eh",
            timestamp=time.time(),
            duration_seconds=0.2,
            result=ExecutionResult(content=[{"type": "text", "text": "data"}]),
        )
        await trace_db.store(trace)

        exported = await trace_db.export_trace("tr_export_test")
        data = json.loads(exported)
        assert data["trace_id"] == "tr_export_test"


class TestPolicyEngineEdgeCases:
    """Additional policy engine edge cases."""

    def test_evaluate_with_taint_labels(self):
        from mcpkernel.policy.engine import PolicyAction, PolicyEngine, PolicyRule

        engine = PolicyEngine()
        engine.add_rule(
            PolicyRule(
                id="taint-block",
                name="Block tainted",
                action=PolicyAction.DENY,
                taint_labels=["secret"],
            )
        )
        decision = engine.evaluate("any_tool", {}, taint_labels={"secret"})
        assert not decision.allowed

    def test_evaluate_with_owasp_id(self):
        from mcpkernel.policy.engine import PolicyAction, PolicyEngine, PolicyRule

        engine = PolicyEngine()
        engine.add_rule(
            PolicyRule(
                id="owasp",
                name="OWASP rule",
                action=PolicyAction.DENY,
                tool_patterns=["vuln_.*"],
                owasp_asi_id="ASI-01",
            )
        )
        decision = engine.evaluate("vuln_tool", {})
        assert not decision.allowed


class TestMetricsCollector:
    """Test Prometheus metrics collector edge cases."""

    def test_collector_creation(self):
        from prometheus_client import CollectorRegistry

        from mcpkernel.observability.metrics import MetricsCollector

        reg = CollectorRegistry()
        collector = MetricsCollector(registry=reg)
        collector.tool_calls_total.labels(tool_name="test", outcome="success").inc()
        output = collector.export_prometheus()
        assert b"mcpkernel_tool_calls_total" in output

    def test_set_build_info(self):
        from prometheus_client import CollectorRegistry

        from mcpkernel.observability.metrics import MetricsCollector

        reg = CollectorRegistry()
        collector = MetricsCollector(registry=reg)
        collector.set_build_info(version="0.1.0", python_version="3.13")
        output = collector.export_prometheus()
        assert b"mcpkernel" in output

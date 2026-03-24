"""Tests for third-party integrations — Langfuse, Guardrails, Registry, Agent Scan."""

from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING
from unittest.mock import AsyncMock, MagicMock

import pytest

if TYPE_CHECKING:
    from mcpkernel.proxy.interceptor import InterceptorContext


# ====================================================================
# Langfuse Exporter Tests
# ====================================================================
class TestLangfuseExporter:
    """Tests for the Langfuse exporter."""

    def test_config_defaults(self) -> None:
        from mcpkernel.integrations.langfuse import LangfuseConfig

        cfg = LangfuseConfig()
        assert cfg.enabled is False
        assert cfg.host == "https://cloud.langfuse.com"
        assert cfg.batch_size == 50
        assert cfg.max_retries == 3

    def test_exporter_skips_when_disabled(self) -> None:
        from mcpkernel.integrations.langfuse import LangfuseExporter

        exporter = LangfuseExporter()
        assert exporter._config.enabled is False

    @pytest.mark.asyncio
    async def test_export_audit_entry_disabled(self) -> None:
        """When disabled, export_audit_entry is a no-op."""
        from mcpkernel.integrations.langfuse import LangfuseExporter

        exporter = LangfuseExporter()
        # Should not raise
        await exporter.export_audit_entry(MagicMock())
        assert len(exporter._batch) == 0

    @pytest.mark.asyncio
    async def test_export_audit_entry_enqueues(self) -> None:
        """When enabled, events are enqueued in the batch."""
        from mcpkernel.audit.logger import AuditEntry
        from mcpkernel.integrations.langfuse import LangfuseConfig, LangfuseExporter

        cfg = LangfuseConfig(
            enabled=True,
            public_key="pk-test",
            secret_key="sk-test",  # noqa: S106
            host="https://localhost",
            batch_size=100,
        )
        exporter = LangfuseExporter(config=cfg)
        # Don't start the HTTP client — just test enqueue logic
        exporter._started = False
        exporter._config.enabled = True  # ensure events pass the guard

        entry = AuditEntry(
            event_type="tool_call",
            tool_name="test_tool",
            agent_id="agent-1",
        )
        # Manually set enabled+started to bypass start()
        exporter._config.enabled = True
        await exporter.export_audit_entry(entry)
        assert len(exporter._batch) == 1
        assert exporter._batch[0]["type"] == "trace-create"

    @pytest.mark.asyncio
    async def test_export_dee_trace_enqueues(self) -> None:
        """DEE traces produce trace-create + span-create events."""
        from mcpkernel.integrations.langfuse import LangfuseConfig, LangfuseExporter

        cfg = LangfuseConfig(
            enabled=True,
            public_key="pk-test",
            secret_key="sk-test",  # noqa: S106
            batch_size=100,
        )
        exporter = LangfuseExporter(config=cfg)

        trace = {
            "trace_id": "trace-001",
            "tool_name": "test_tool",
            "duration_seconds": 0.5,
            "input_hash": "abc123",
            "output_hash": "def456",
        }
        await exporter.export_dee_trace(trace)
        assert len(exporter._batch) == 2
        assert exporter._batch[0]["type"] == "trace-create"
        assert exporter._batch[1]["type"] == "span-create"

    @pytest.mark.asyncio
    async def test_flush_sends_batch(self) -> None:
        """Flush sends the batch to Langfuse API."""
        from mcpkernel.integrations.langfuse import LangfuseConfig, LangfuseExporter

        cfg = LangfuseConfig(
            enabled=True,
            public_key="pk-test",
            secret_key="sk-test",  # noqa: S106
            batch_size=100,
        )
        exporter = LangfuseExporter(config=cfg)

        mock_client = AsyncMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_client.post = AsyncMock(return_value=mock_resp)
        exporter._client = mock_client
        exporter._started = True

        exporter._batch = [{"type": "trace-create", "body": {}}]
        await exporter.flush()
        mock_client.post.assert_called_once()
        assert len(exporter._batch) == 0

    @pytest.mark.asyncio
    async def test_flush_retries_on_429(self) -> None:
        """Flush retries on rate-limit (429)."""
        from mcpkernel.integrations.langfuse import LangfuseConfig, LangfuseExporter

        cfg = LangfuseConfig(
            enabled=True,
            public_key="pk-test",
            secret_key="sk-test",  # noqa: S106
            batch_size=100,
            max_retries=1,
        )
        exporter = LangfuseExporter(config=cfg)

        mock_client = AsyncMock()
        resp_429 = MagicMock(status_code=429)
        resp_200 = MagicMock(status_code=200)
        mock_client.post = AsyncMock(side_effect=[resp_429, resp_200])
        exporter._client = mock_client
        exporter._started = True

        exporter._batch = [{"type": "event-create", "body": {}}]
        await exporter.flush()
        assert mock_client.post.call_count == 2

    @pytest.mark.asyncio
    async def test_shutdown_flushes(self) -> None:
        """Shutdown flushes remaining events and closes client."""
        from mcpkernel.integrations.langfuse import LangfuseConfig, LangfuseExporter

        cfg = LangfuseConfig(
            enabled=True,
            public_key="pk-test",
            secret_key="sk-test",  # noqa: S106
        )
        exporter = LangfuseExporter(config=cfg)

        mock_client = AsyncMock()
        mock_client.aclose = AsyncMock()
        mock_client.post = AsyncMock(return_value=MagicMock(status_code=200))
        exporter._client = mock_client
        exporter._started = True
        exporter._flush_task = None

        exporter._batch = [{"type": "trace-create", "body": {}}]
        await exporter.shutdown()
        mock_client.post.assert_called_once()
        mock_client.aclose.assert_called_once()
        assert exporter._started is False

    def test_epoch_to_iso(self) -> None:
        from mcpkernel.integrations.langfuse import _epoch_to_iso

        result = _epoch_to_iso(0)
        assert "1970" in result

    def test_audit_entry_to_event_types(self) -> None:
        """tool_call events become trace-create, others become event-create."""
        from mcpkernel.audit.logger import AuditEntry
        from mcpkernel.integrations.langfuse import _audit_entry_to_langfuse_event

        tc = AuditEntry(event_type="tool_call", tool_name="t1", agent_id="a1")
        event_tc = _audit_entry_to_langfuse_event(tc, "test")
        assert event_tc["type"] == "trace-create"

        other = AuditEntry(event_type="policy_violation", tool_name="t1", agent_id="a1")
        event_other = _audit_entry_to_langfuse_event(other, "test")
        assert event_other["type"] == "event-create"


# ====================================================================
# Guardrails Validator Tests
# ====================================================================
class TestGuardrailsValidator:
    """Tests for the Guardrails AI validator wrapper."""

    def test_config_defaults(self) -> None:
        from mcpkernel.integrations.guardrails import GuardrailsConfig

        cfg = GuardrailsConfig()
        assert cfg.enabled is False
        assert cfg.pii_validator is True
        assert cfg.on_fail == "noop"

    def test_not_available_when_disabled(self) -> None:
        from mcpkernel.integrations.guardrails import GuardrailsConfig, GuardrailsValidator

        v = GuardrailsValidator(config=GuardrailsConfig(enabled=False))
        assert v.available is False

    @pytest.mark.asyncio
    async def test_validate_text_returns_empty_when_unavailable(self) -> None:
        from mcpkernel.integrations.guardrails import GuardrailsConfig, GuardrailsValidator

        v = GuardrailsValidator(config=GuardrailsConfig(enabled=False))
        result = await v.validate_text("test data")
        assert result == []

    @pytest.mark.asyncio
    async def test_validate_dict_returns_empty_when_unavailable(self) -> None:
        from mcpkernel.integrations.guardrails import GuardrailsConfig, GuardrailsValidator

        v = GuardrailsValidator(config=GuardrailsConfig(enabled=False))
        result = await v.validate_dict({"key": "value"})
        assert result == []

    @pytest.mark.asyncio
    async def test_validate_dict_scans_nested_strings(self) -> None:
        """When available, nested strings in dicts are scanned."""
        from mcpkernel.integrations.guardrails import GuardrailsConfig, GuardrailsValidator

        v = GuardrailsValidator(config=GuardrailsConfig(enabled=True))
        # Mock the availability and validate_text
        v._init_attempted = True
        v._available = True

        detections = []

        async def mock_validate(text: str, *, field_path: str = "") -> list:
            return detections

        v.validate_text = mock_validate  # type: ignore[assignment]
        result = await v.validate_dict({"nested": {"deep": "test value"}})
        assert result == []

    def test_detection_dataclass(self) -> None:
        from mcpkernel.integrations.guardrails import GuardrailsDetection
        from mcpkernel.taint.tracker import TaintLabel

        d = GuardrailsDetection(
            validator_name="DetectPII",
            label=TaintLabel.PII,
            entity_type="EMAIL",
            matched_text="test@example.com...",
            confidence=0.95,
            field_path="data.email",
        )
        assert d.label == TaintLabel.PII
        assert d.confidence == 0.95


# ====================================================================
# MCP Registry Tests
# ====================================================================
class TestMCPRegistry:
    """Tests for the MCP Registry client."""

    def test_config_defaults(self) -> None:
        from mcpkernel.integrations.registry import RegistryConfig

        cfg = RegistryConfig()
        assert cfg.enabled is True
        assert "modelcontextprotocol" in cfg.registry_url

    def test_server_display_name(self) -> None:
        from mcpkernel.integrations.registry import RegistryServer

        s = RegistryServer(name="test-server", is_verified=True)
        assert "✓" in s.display_name

        s2 = RegistryServer(name="another", is_verified=False)
        assert "✓" not in s2.display_name

    def test_parse_server(self) -> None:
        from mcpkernel.integrations.registry import _parse_server

        data = {
            "name": "filesystem",
            "description": "File system access",
            "version": "1.0.0",
            "transports": ["stdio"],
            "categories": ["files"],
            "verified": True,
        }
        s = _parse_server(data)
        assert s.name == "filesystem"
        assert s.is_verified is True
        assert "stdio" in s.transport

    def test_parse_server_alternative_keys(self) -> None:
        """Parser handles alternative key names from different API versions."""
        from mcpkernel.integrations.registry import _parse_server

        data = {
            "id": "my-server",
            "tags": ["database"],
            "repository": {"url": "https://github.com/test/test"},
        }
        s = _parse_server(data)
        assert s.name == "my-server"
        assert "database" in s.categories
        assert "github.com" in s.repository_url

    @pytest.mark.asyncio
    async def test_search_returns_empty_on_error(self) -> None:
        from mcpkernel.integrations.registry import MCPRegistry, RegistryConfig

        cfg = RegistryConfig(registry_url="http://invalid-host-that-does-not-exist:9999")
        r = MCPRegistry(config=cfg)
        servers = await r.search("test")
        assert servers == []
        await r.close()

    @pytest.mark.asyncio
    async def test_search_with_mock(self) -> None:
        from mcpkernel.integrations.registry import MCPRegistry, RegistryConfig

        cfg = RegistryConfig(registry_url="http://test")
        r = MCPRegistry(config=cfg)

        mock_client = AsyncMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "servers": [
                {"name": "filesystem", "description": "FS", "transports": ["stdio"]},
                {"name": "git", "description": "Git", "transports": ["sse"]},
            ]
        }
        mock_client.get = AsyncMock(return_value=mock_resp)
        r._client = mock_client

        servers = await r.search("fs", limit=10)
        assert len(servers) == 2
        assert servers[0].name == "filesystem"
        await r.close()

    @pytest.mark.asyncio
    async def test_get_server_not_found(self) -> None:
        from mcpkernel.integrations.registry import MCPRegistry, RegistryConfig

        cfg = RegistryConfig(registry_url="http://test")
        r = MCPRegistry(config=cfg)

        mock_client = AsyncMock()
        mock_resp = MagicMock(status_code=404)
        mock_client.get = AsyncMock(return_value=mock_resp)
        r._client = mock_client

        result = await r.get_server("nonexistent")
        assert result is None
        await r.close()

    @pytest.mark.asyncio
    async def test_validate_server_not_found(self) -> None:
        from mcpkernel.integrations.registry import MCPRegistry, RegistryConfig

        cfg = RegistryConfig(registry_url="http://test")
        r = MCPRegistry(config=cfg)

        mock_client = AsyncMock()
        mock_resp = MagicMock(status_code=404)
        mock_client.get = AsyncMock(return_value=mock_resp)
        r._client = mock_client

        result = await r.validate_server("nonexistent")
        assert result["valid"] is False
        await r.close()

    @pytest.mark.asyncio
    async def test_validate_server_found(self) -> None:
        from mcpkernel.integrations.registry import MCPRegistry, RegistryConfig

        cfg = RegistryConfig(registry_url="http://test")
        r = MCPRegistry(config=cfg)

        mock_client = AsyncMock()
        mock_resp = MagicMock(status_code=200)
        mock_resp.json.return_value = {
            "name": "filesystem",
            "verified": True,
            "version": "1.0",
            "transports": ["stdio"],
        }
        mock_client.get = AsyncMock(return_value=mock_resp)
        r._client = mock_client

        result = await r.validate_server("filesystem")
        assert result["valid"] is True
        assert result["verified"] is True
        await r.close()

    @pytest.mark.asyncio
    async def test_list_servers_caches(self) -> None:
        """Second call uses cache."""
        from mcpkernel.integrations.registry import MCPRegistry, RegistryConfig

        cfg = RegistryConfig(registry_url="http://test", cache_ttl_seconds=300)
        r = MCPRegistry(config=cfg)

        mock_client = AsyncMock()
        mock_resp = MagicMock(status_code=200)
        mock_resp.json.return_value = [{"name": "srv1"}, {"name": "srv2"}]
        mock_client.get = AsyncMock(return_value=mock_resp)
        r._client = mock_client

        await r.list_servers()
        await r.list_servers()
        # Only one actual HTTP call — second was cached
        assert mock_client.get.call_count == 1
        await r.close()


# ====================================================================
# Agent Scan Tests
# ====================================================================
class TestAgentScanner:
    """Tests for the Snyk Agent Scan bridge."""

    def test_config_defaults(self) -> None:
        from mcpkernel.integrations.agent_scan import AgentScanConfig

        cfg = AgentScanConfig()
        assert cfg.binary_name == "agent-scan"
        assert cfg.timeout_seconds == 120
        assert cfg.auto_generate_policy is True

    def test_finding_is_blocking(self) -> None:
        from mcpkernel.integrations.agent_scan import ScanFinding

        crit = ScanFinding(rule_id="R1", severity="critical", title="Critical", description="desc")
        assert crit.is_blocking is True

        high = ScanFinding(rule_id="R2", severity="high", title="High", description="desc")
        assert high.is_blocking is True

        medium = ScanFinding(rule_id="R3", severity="medium", title="Medium", description="desc")
        assert medium.is_blocking is False

    def test_report_properties(self) -> None:
        from mcpkernel.integrations.agent_scan import ScanFinding, ScanReport

        findings = [
            ScanFinding(rule_id="R1", severity="critical", title="C", description="d"),
            ScanFinding(rule_id="R2", severity="high", title="H", description="d"),
            ScanFinding(rule_id="R3", severity="medium", title="M", description="d"),
        ]
        report = ScanReport(findings=findings)
        assert report.critical_count == 1
        assert report.high_count == 1
        assert report.has_blockers is True

    def test_report_no_blockers(self) -> None:
        from mcpkernel.integrations.agent_scan import ScanFinding, ScanReport

        findings = [ScanFinding(rule_id="R1", severity="low", title="L", description="d")]
        report = ScanReport(findings=findings)
        assert report.has_blockers is False

    def test_parse_scan_output_valid_json(self) -> None:
        from mcpkernel.integrations.agent_scan import _parse_scan_output

        output = json.dumps(
            {
                "findings": [
                    {
                        "rule_id": "PJ-001",
                        "severity": "critical",
                        "title": "Prompt injection",
                        "description": "Tool vulnerable to prompt injection",
                        "server_name": "filesystem",
                        "tool_name": "read_file",
                        "category": "prompt_injection",
                    }
                ],
                "servers_scanned": 1,
                "version": "1.0.0",
            }
        )
        report = _parse_scan_output(output)
        assert len(report.findings) == 1
        assert report.findings[0].rule_id == "PJ-001"
        assert report.findings[0].severity == "critical"
        assert report.servers_scanned == 1

    def test_parse_scan_output_invalid_json(self) -> None:
        from mcpkernel.integrations.agent_scan import _parse_scan_output

        report = _parse_scan_output("not json")
        assert len(report.findings) == 0
        assert report.raw_output == "not json"

    def test_parse_scan_output_alternative_keys(self) -> None:
        """Parser handles mcp-scan-style keys."""
        from mcpkernel.integrations.agent_scan import _parse_scan_output

        output = json.dumps(
            {
                "vulnerabilities": [
                    {
                        "id": "TS-001",
                        "severity": "high",
                        "name": "Tool shadowing",
                        "message": "A tool shadows another",
                        "type": "tool_shadowing",
                    }
                ],
                "server_count": 2,
            }
        )
        report = _parse_scan_output(output)
        assert len(report.findings) == 1
        assert report.findings[0].rule_id == "TS-001"
        assert report.findings[0].title == "Tool shadowing"

    def test_report_to_policy_rules(self) -> None:
        from mcpkernel.integrations.agent_scan import AgentScanner, ScanFinding, ScanReport

        findings = [
            ScanFinding(
                rule_id="PJ-001",
                severity="critical",
                title="Prompt Injection",
                description="Vuln",
                tool_name="read_file",
                category="prompt_injection",
            ),
            ScanFinding(
                rule_id="TS-002",
                severity="medium",
                title="Tool Shadowing",
                description="Shadow",
                server_name="fs",
                category="tool_shadowing",
            ),
        ]
        report = ScanReport(findings=findings)

        scanner = AgentScanner()
        rules = scanner.report_to_policy_rules(report)
        assert len(rules) == 2
        assert rules[0]["action"] == "deny"
        assert rules[0]["tool_patterns"] == ["read_file"]
        assert rules[1]["action"] == "log"
        assert rules[1]["tool_patterns"] == ["fs:.*"]

    @pytest.mark.asyncio
    async def test_scan_directory_unavailable(self) -> None:
        from mcpkernel.integrations.agent_scan import AgentScanConfig, AgentScanner

        cfg = AgentScanConfig(binary_name="nonexistent-binary-xyz")
        scanner = AgentScanner(config=cfg)
        # Force binary path check
        scanner._binary_path = ""
        report = await scanner.scan_directory(Path("."))
        assert "not available" in report.raw_output


# ====================================================================
# Config Integration Tests
# ====================================================================
class TestConfigIntegration:
    """Test that integration configs are wired into MCPKernelSettings."""

    def test_langfuse_config_in_settings(self) -> None:
        from mcpkernel.config import MCPKernelSettings

        settings = MCPKernelSettings()
        assert hasattr(settings, "langfuse")
        assert settings.langfuse.enabled is False

    def test_guardrails_config_in_settings(self) -> None:
        from mcpkernel.config import MCPKernelSettings

        settings = MCPKernelSettings()
        assert hasattr(settings, "guardrails_ai")
        assert settings.guardrails_ai.enabled is False
        assert settings.guardrails_ai.pii_validator is True

    def test_registry_config_in_settings(self) -> None:
        from mcpkernel.config import MCPKernelSettings

        settings = MCPKernelSettings()
        assert hasattr(settings, "registry")
        assert settings.registry.enabled is True

    def test_agent_scan_config_in_settings(self) -> None:
        from mcpkernel.config import MCPKernelSettings

        settings = MCPKernelSettings()
        assert hasattr(settings, "agent_scan")
        assert settings.agent_scan.binary_name == "agent-scan"


# ====================================================================
# Hook Integration Tests
# ====================================================================
class TestHookIntegration:
    """Test that hooks accept integration parameters."""

    def test_taint_hook_accepts_guardrails(self) -> None:
        from mcpkernel.proxy.hooks import TaintHook

        mock_tracker = MagicMock()
        mock_gr = MagicMock()
        hook = TaintHook(mock_tracker, guardrails_validator=mock_gr)
        assert hook._guardrails is mock_gr

    def test_observability_hook_accepts_langfuse(self) -> None:
        from mcpkernel.proxy.hooks import ObservabilityHook

        mock_metrics = MagicMock()
        mock_lf = MagicMock()
        hook = ObservabilityHook(mock_metrics, langfuse_exporter=mock_lf)
        assert hook._langfuse is mock_lf

    def test_taint_hook_works_without_guardrails(self) -> None:
        from mcpkernel.proxy.hooks import TaintHook

        mock_tracker = MagicMock()
        hook = TaintHook(mock_tracker)
        assert hook._guardrails is None

    def test_observability_hook_works_without_langfuse(self) -> None:
        from mcpkernel.proxy.hooks import ObservabilityHook

        mock_metrics = MagicMock()
        hook = ObservabilityHook(mock_metrics)
        assert hook._langfuse is None


# ====================================================================
# ObservabilityHook Langfuse Export Path Tests
# ====================================================================
class TestObservabilityHookLangfuse:
    """Test ObservabilityHook.log() Langfuse export code path."""

    def _make_ctx(
        self,
        *,
        aborted: bool = False,
        is_error: bool = False,
        trace_id: str = "trace-001",
    ) -> InterceptorContext:
        from mcpkernel.proxy.interceptor import (
            ExecutionResult,
            InterceptorContext,
            MCPToolCall,
        )

        call = MCPToolCall(
            request_id=1,
            tool_name="test_tool",
            arguments={"key": "value"},
            raw_jsonrpc={"jsonrpc": "2.0", "method": "tools/call", "id": 1},
        )
        result = ExecutionResult(
            content=[{"type": "text", "text": "ok"}],
            is_error=is_error,
            trace_id=trace_id,
        )
        return InterceptorContext(
            call=call,
            result=result,
            policy_decision="allow",
            taint_labels={"pii"},
            aborted=aborted,
        )

    @pytest.mark.asyncio
    async def test_log_calls_langfuse_export(self) -> None:
        """When langfuse_exporter is set, log() creates an AuditEntry and exports it."""
        from mcpkernel.proxy.hooks import ObservabilityHook

        mock_langfuse = AsyncMock()
        mock_langfuse.export_audit_entry = AsyncMock()
        mock_metrics = MagicMock()

        hook = ObservabilityHook(mock_metrics, langfuse_exporter=mock_langfuse)
        ctx = self._make_ctx()

        await hook.log(ctx)

        mock_langfuse.export_audit_entry.assert_awaited_once()
        entry = mock_langfuse.export_audit_entry.call_args[0][0]
        assert entry.event_type == "tool_call"
        assert entry.tool_name == "test_tool"
        assert entry.outcome == "success"
        assert "pii" in entry.details["taint_labels"]

    @pytest.mark.asyncio
    async def test_log_langfuse_blocked_outcome(self) -> None:
        """Aborted context yields outcome='blocked' in the exported entry."""
        from mcpkernel.proxy.hooks import ObservabilityHook

        mock_langfuse = AsyncMock()
        mock_langfuse.export_audit_entry = AsyncMock()

        hook = ObservabilityHook(MagicMock(), langfuse_exporter=mock_langfuse)
        ctx = self._make_ctx(aborted=True)

        await hook.log(ctx)

        entry = mock_langfuse.export_audit_entry.call_args[0][0]
        assert entry.outcome == "blocked"

    @pytest.mark.asyncio
    async def test_log_langfuse_error_outcome(self) -> None:
        """Error result yields outcome='error' in the exported entry."""
        from mcpkernel.proxy.hooks import ObservabilityHook

        mock_langfuse = AsyncMock()
        mock_langfuse.export_audit_entry = AsyncMock()

        hook = ObservabilityHook(MagicMock(), langfuse_exporter=mock_langfuse)
        ctx = self._make_ctx(is_error=True)

        await hook.log(ctx)

        entry = mock_langfuse.export_audit_entry.call_args[0][0]
        assert entry.outcome == "error"

    @pytest.mark.asyncio
    async def test_log_langfuse_exception_is_nonfatal(self) -> None:
        """If langfuse export raises, log() swallows the exception."""
        from mcpkernel.proxy.hooks import ObservabilityHook

        mock_langfuse = AsyncMock()
        mock_langfuse.export_audit_entry = AsyncMock(side_effect=RuntimeError("connection lost"))

        hook = ObservabilityHook(MagicMock(), langfuse_exporter=mock_langfuse)
        ctx = self._make_ctx()

        # Should not raise
        await hook.log(ctx)

    @pytest.mark.asyncio
    async def test_log_without_langfuse_skips_export(self) -> None:
        """When langfuse_exporter is None, no export is attempted."""
        from mcpkernel.proxy.hooks import ObservabilityHook

        hook = ObservabilityHook(MagicMock(), langfuse_exporter=None)
        ctx = self._make_ctx()

        # Should complete without error
        await hook.log(ctx)

    @pytest.mark.asyncio
    async def test_log_langfuse_agent_id_from_auth(self) -> None:
        """Agent ID is extracted from ctx.extra['auth'] when present."""
        from mcpkernel.proxy.hooks import ObservabilityHook

        mock_langfuse = AsyncMock()
        mock_langfuse.export_audit_entry = AsyncMock()

        hook = ObservabilityHook(MagicMock(), langfuse_exporter=mock_langfuse)
        ctx = self._make_ctx()
        ctx.extra["auth"] = MagicMock(identity="agent-42")

        await hook.log(ctx)

        entry = mock_langfuse.export_audit_entry.call_args[0][0]
        assert entry.agent_id == "agent-42"


# ====================================================================
# TaintHook Guardrails Integration Path Tests
# ====================================================================
class TestTaintHookGuardrails:
    """Test TaintHook.pre_execution() Guardrails integration code path."""

    def _make_ctx(self) -> InterceptorContext:
        from mcpkernel.proxy.interceptor import InterceptorContext, MCPToolCall

        call = MCPToolCall(
            request_id=2,
            tool_name="read_file",
            arguments={"path": "/etc/passwd", "email": "user@example.com"},
            raw_jsonrpc={"jsonrpc": "2.0", "method": "tools/call", "id": 2},
        )
        return InterceptorContext(call=call)

    @pytest.mark.asyncio
    async def test_guardrails_detections_added_to_taint_labels(self) -> None:
        """Detections from guardrails.validate_dict() are added to ctx.taint_labels."""
        from mcpkernel.integrations.guardrails import GuardrailsDetection
        from mcpkernel.proxy.hooks import TaintHook
        from mcpkernel.taint.tracker import TaintLabel

        detection = GuardrailsDetection(
            validator_name="DetectPII",
            label=TaintLabel.PII,
            entity_type="EMAIL",
            matched_text="user@example.com",
            confidence=0.99,
            field_path="email",
        )

        mock_guardrails = AsyncMock()
        mock_guardrails.available = True
        mock_guardrails.validate_dict = AsyncMock(return_value=[detection])

        mock_tracker = MagicMock()
        hook = TaintHook(
            mock_tracker,
            detect_fn=lambda args: [],
            guardrails_validator=mock_guardrails,
        )
        ctx = self._make_ctx()

        await hook.pre_execution(ctx)

        assert "pii" in ctx.taint_labels
        mock_guardrails.validate_dict.assert_awaited_once()
        mock_tracker.mark.assert_called_once_with(
            "user@example.com",
            TaintLabel.PII,
            source_id=ctx.call.correlation_id,
            metadata={
                "field": "email",
                "tool": "read_file",
                "validator": "DetectPII",
            },
        )

    @pytest.mark.asyncio
    async def test_guardrails_multiple_detections(self) -> None:
        """Multiple guardrails detections all get added to taint_labels."""
        from mcpkernel.integrations.guardrails import GuardrailsDetection
        from mcpkernel.proxy.hooks import TaintHook
        from mcpkernel.taint.tracker import TaintLabel

        detections = [
            GuardrailsDetection(
                validator_name="DetectPII",
                label=TaintLabel.PII,
                entity_type="EMAIL",
                matched_text="user@example.com",
                confidence=0.99,
                field_path="email",
            ),
            GuardrailsDetection(
                validator_name="DetectSecrets",
                label=TaintLabel.SECRET,
                entity_type="API_KEY",
                matched_text="sk-...",
                confidence=0.95,
                field_path="token",
            ),
        ]

        mock_guardrails = AsyncMock()
        mock_guardrails.available = True
        mock_guardrails.validate_dict = AsyncMock(return_value=detections)

        mock_tracker = MagicMock()
        hook = TaintHook(
            mock_tracker,
            detect_fn=lambda args: [],
            guardrails_validator=mock_guardrails,
        )
        ctx = self._make_ctx()

        await hook.pre_execution(ctx)

        assert "pii" in ctx.taint_labels
        assert "secret" in ctx.taint_labels
        assert mock_tracker.mark.call_count == 2

    @pytest.mark.asyncio
    async def test_guardrails_exception_is_nonfatal(self) -> None:
        """If guardrails.validate_dict() raises, it's swallowed (non-fatal)."""
        from mcpkernel.proxy.hooks import TaintHook

        mock_guardrails = AsyncMock()
        mock_guardrails.available = True
        mock_guardrails.validate_dict = AsyncMock(side_effect=RuntimeError("guard crash"))

        mock_tracker = MagicMock()
        hook = TaintHook(
            mock_tracker,
            detect_fn=lambda args: [],
            guardrails_validator=mock_guardrails,
        )
        ctx = self._make_ctx()

        # Should not raise
        await hook.pre_execution(ctx)
        assert len(ctx.taint_labels) == 0

    @pytest.mark.asyncio
    async def test_guardrails_skipped_when_not_available(self) -> None:
        """When guardrails.available is False, validate_dict is not called."""
        from mcpkernel.proxy.hooks import TaintHook

        mock_guardrails = AsyncMock()
        mock_guardrails.available = False
        mock_guardrails.validate_dict = AsyncMock()

        mock_tracker = MagicMock()
        hook = TaintHook(
            mock_tracker,
            detect_fn=lambda args: [],
            guardrails_validator=mock_guardrails,
        )
        ctx = self._make_ctx()

        await hook.pre_execution(ctx)

        mock_guardrails.validate_dict.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_guardrails_combined_with_detect_fn(self) -> None:
        """Both detect_fn and guardrails detections contribute to taint_labels."""
        from mcpkernel.integrations.guardrails import GuardrailsDetection
        from mcpkernel.proxy.hooks import TaintHook
        from mcpkernel.taint.tracker import TaintLabel

        # detect_fn returns a detection
        detect_result = MagicMock()
        detect_result.label = TaintLabel.USER_INPUT
        detect_result.matched_text = "/etc/passwd"
        detect_result.field_path = "path"

        def mock_detect_fn(args: dict) -> list:
            return [detect_result]

        # guardrails returns a detection
        gr_detection = GuardrailsDetection(
            validator_name="DetectPII",
            label=TaintLabel.PII,
            entity_type="EMAIL",
            matched_text="user@example.com",
            confidence=0.99,
            field_path="email",
        )
        mock_guardrails = AsyncMock()
        mock_guardrails.available = True
        mock_guardrails.validate_dict = AsyncMock(return_value=[gr_detection])

        mock_tracker = MagicMock()
        hook = TaintHook(
            mock_tracker,
            detect_fn=mock_detect_fn,
            guardrails_validator=mock_guardrails,
        )
        ctx = self._make_ctx()

        await hook.pre_execution(ctx)

        assert "user_input" in ctx.taint_labels
        assert "pii" in ctx.taint_labels
        # detect_fn mark + guardrails mark = 2 calls
        assert mock_tracker.mark.call_count == 2


# ====================================================================
# Agent Scan URL Validation Tests
# ====================================================================
class TestAgentScanURLValidation:
    """Test SSRF protection in scan_server_url()."""

    @pytest.mark.asyncio
    async def test_rejects_file_scheme(self) -> None:
        """file:// URLs are rejected."""
        from mcpkernel.integrations.agent_scan import AgentScanner

        scanner = AgentScanner()
        scanner._binary_path = "/usr/bin/true"  # pretend available
        report = await scanner.scan_server_url("file:///etc/passwd")
        assert "Invalid URL scheme" in report.raw_output

    @pytest.mark.asyncio
    async def test_rejects_ftp_scheme(self) -> None:
        """ftp:// URLs are rejected."""
        from mcpkernel.integrations.agent_scan import AgentScanner

        scanner = AgentScanner()
        scanner._binary_path = "/usr/bin/true"
        report = await scanner.scan_server_url("ftp://evil.com/payload")
        assert "Invalid URL scheme" in report.raw_output

    @pytest.mark.asyncio
    async def test_rejects_javascript_scheme(self) -> None:
        """javascript: URLs are rejected."""
        from mcpkernel.integrations.agent_scan import AgentScanner

        scanner = AgentScanner()
        scanner._binary_path = "/usr/bin/true"
        report = await scanner.scan_server_url("javascript:alert(1)")
        assert "Invalid URL scheme" in report.raw_output

    @pytest.mark.asyncio
    async def test_rejects_data_scheme(self) -> None:
        """data: URLs are rejected."""
        from mcpkernel.integrations.agent_scan import AgentScanner

        scanner = AgentScanner()
        scanner._binary_path = "/usr/bin/true"
        report = await scanner.scan_server_url("data:text/html,<script>")
        assert "Invalid URL scheme" in report.raw_output

    @pytest.mark.asyncio
    async def test_rejects_empty_scheme(self) -> None:
        """URLs without a recognized scheme are rejected."""
        from mcpkernel.integrations.agent_scan import AgentScanner

        scanner = AgentScanner()
        scanner._binary_path = "/usr/bin/true"
        report = await scanner.scan_server_url("//evil.com/path")
        assert "Invalid URL scheme" in report.raw_output

    @pytest.mark.asyncio
    async def test_accepts_http_scheme(self) -> None:
        """http:// URLs pass validation (scan itself may fail, but URL check passes)."""
        from unittest.mock import patch

        from mcpkernel.integrations.agent_scan import AgentScanner

        scanner = AgentScanner()
        scanner._binary_path = "/usr/bin/true"

        with patch.object(scanner, "_run_scan", new_callable=AsyncMock) as mock_run:
            from mcpkernel.integrations.agent_scan import ScanReport

            mock_run.return_value = ScanReport()
            await scanner.scan_server_url("http://localhost:8080/mcp")
            mock_run.assert_awaited_once_with(["--url", "http://localhost:8080/mcp"])

    @pytest.mark.asyncio
    async def test_accepts_https_scheme(self) -> None:
        """https:// URLs pass validation."""
        from unittest.mock import patch

        from mcpkernel.integrations.agent_scan import AgentScanner

        scanner = AgentScanner()
        scanner._binary_path = "/usr/bin/true"

        with patch.object(scanner, "_run_scan", new_callable=AsyncMock) as mock_run:
            from mcpkernel.integrations.agent_scan import ScanReport

            mock_run.return_value = ScanReport()
            await scanner.scan_server_url("https://mcp.example.com/sse")
            mock_run.assert_awaited_once_with(["--url", "https://mcp.example.com/sse"])

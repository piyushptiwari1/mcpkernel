"""Tests for mcpkernel.cli — CLI commands via Typer CliRunner.

Targets the biggest coverage gap: cli.py at 46%.
Covers: manifest-import, manifest-validate, serve, trace-list, trace-export,
        replay, audit-query, audit-verify, scan, version, config-show, init,
        validate-policy.
"""

from __future__ import annotations

import json
from pathlib import Path  # noqa: TC003
from unittest.mock import AsyncMock, MagicMock, patch

from typer.testing import CliRunner

from mcpkernel.cli import app

runner = CliRunner()


# ── Helpers ────────────────────────────────────────────────────────────


def _create_agent_yaml(repo: Path, *, compliance: bool = True) -> None:
    """Write a minimal agent.yaml with optional compliance section."""
    content = (
        "name: test-agent\n"
        "version: 1.0.0\n"
        "description: A test agent for CLI testing\n"
        "tools:\n"
        "  - read_file\n"
        "  - write_file\n"
        "skills:\n"
        "  - code-review\n"
    )
    if compliance:
        content += (
            "compliance:\n  risk_tier: medium\n  frameworks:\n    - FINRA\n  supervision:\n    level: supervised\n"
        )
    (repo / "agent.yaml").write_text(content)


def _create_tool_schema(repo: Path, tool_name: str) -> None:
    """Write a tool schema YAML under tools/."""
    tools_dir = repo / "tools"
    tools_dir.mkdir(exist_ok=True)
    (tools_dir / f"{tool_name}.yaml").write_text(
        f"name: {tool_name}\n"
        f"description: Test tool {tool_name}\n"
        "version: '1.0'\n"
        "input_schema:\n"
        "  type: object\n"
        "  properties:\n"
        "    path:\n"
        "      type: string\n"
        "  required:\n"
        "    - path\n"
        "annotations:\n"
        "  read_only: true\n"
        "  requires_confirmation: false\n"
    )


# ── version ────────────────────────────────────────────────────────────


class TestVersionCommand:
    def test_version_outputs_version_string(self):
        result = runner.invoke(app, ["version"])
        assert result.exit_code == 0
        assert "mcpkernel" in result.output

    def test_version_contains_semver(self):
        result = runner.invoke(app, ["version"])
        # Should contain at least x.y.z pattern
        import re

        assert re.search(r"\d+\.\d+\.\d+", result.output)


# ── init ───────────────────────────────────────────────────────────────


class TestInitCommand:
    def test_init_creates_directory_structure(self, tmp_path: Path):
        result = runner.invoke(app, ["init", str(tmp_path)])
        assert result.exit_code == 0
        assert (tmp_path / ".mcpkernel" / "config.yaml").exists()
        assert (tmp_path / ".mcpkernel" / "policies").is_dir()
        assert (tmp_path / ".mcpkernel" / "policies" / "default.yaml").exists()

    def test_init_outputs_success_message(self, tmp_path: Path):
        result = runner.invoke(app, ["init", str(tmp_path)])
        assert "✓ Initialized MCPKernel" in result.output

    def test_init_idempotent(self, tmp_path: Path):
        """Running init twice should not error or overwrite."""
        runner.invoke(app, ["init", str(tmp_path)])
        result = runner.invoke(app, ["init", str(tmp_path)])
        assert result.exit_code == 0


# ── config-show ────────────────────────────────────────────────────────


class TestConfigShowCommand:
    def test_config_show_outputs_json(self):
        result = runner.invoke(app, ["config-show"])
        assert result.exit_code == 0
        # Output should be valid JSON
        parsed = json.loads(result.output)
        assert "proxy" in parsed
        assert "sandbox" in parsed

    def test_config_show_with_yaml(self, tmp_path: Path):
        config_file = tmp_path / "test.yaml"
        config_file.write_text("proxy:\n  host: 0.0.0.0\n  port: 9999\n")
        result = runner.invoke(app, ["config-show", "-c", str(config_file)])
        assert result.exit_code == 0
        parsed = json.loads(result.output)
        assert parsed["proxy"]["port"] == 9999


# ── validate-policy ────────────────────────────────────────────────────


class TestValidatePolicyCommand:
    def test_validate_policy_valid_file(self, sample_policy_yaml: Path):
        result = runner.invoke(app, ["validate-policy", str(sample_policy_yaml)])
        assert result.exit_code == 0
        assert "✓ Loaded" in result.output
        assert "2 valid rules" in result.output

    def test_validate_policy_invalid_file(self, tmp_path: Path):
        bad = tmp_path / "bad.yaml"
        bad.write_text("not_rules: true\n")
        result = runner.invoke(app, ["validate-policy", str(bad)])
        assert result.exit_code == 1
        assert "✗ Validation failed" in result.output

    def test_validate_policy_missing_file(self, tmp_path: Path):
        result = runner.invoke(app, ["validate-policy", str(tmp_path / "nope.yaml")])
        assert result.exit_code == 1

    def test_validate_policy_directory(self, tmp_path: Path):
        """Validate a directory containing multiple policy files."""
        (tmp_path / "a.yaml").write_text(
            "rules:\n  - id: A-001\n    name: Rule A\n    action: deny\n    tool_patterns: ['.*']\n"
        )
        (tmp_path / "b.yaml").write_text(
            "rules:\n  - id: B-001\n    name: Rule B\n    action: audit\n    tool_patterns: ['.*']\n"
        )
        result = runner.invoke(app, ["validate-policy", str(tmp_path)])
        assert result.exit_code == 0
        assert "2 valid rules" in result.output


# ── manifest-import ────────────────────────────────────────────────────


class TestManifestImportCommand:
    def test_manifest_import_success(self, tmp_path: Path):
        _create_agent_yaml(tmp_path, compliance=True)
        result = runner.invoke(app, ["manifest-import", str(tmp_path)])
        assert result.exit_code == 0
        assert "✓ Loaded agent manifest: test-agent" in result.output
        assert "v1.0.0" in result.output
        assert "Risk tier: medium" in result.output
        assert "FINRA" in result.output

    def test_manifest_import_with_output(self, tmp_path: Path):
        repo = tmp_path / "repo"
        repo.mkdir()
        _create_agent_yaml(repo, compliance=True)
        output_file = tmp_path / "output" / "rules.yaml"
        result = runner.invoke(app, ["manifest-import", str(repo), "-o", str(output_file)])
        assert result.exit_code == 0
        assert output_file.exists()
        assert "Exported to" in result.output

    def test_manifest_import_no_compliance(self, tmp_path: Path):
        _create_agent_yaml(tmp_path, compliance=False)
        result = runner.invoke(app, ["manifest-import", str(tmp_path)])
        assert result.exit_code == 0
        assert "✓ Loaded agent manifest" in result.output

    def test_manifest_import_missing_agent_yaml(self, tmp_path: Path):
        result = runner.invoke(app, ["manifest-import", str(tmp_path)])
        assert result.exit_code == 1
        assert "✗ Failed to load agent manifest" in result.output

    def test_manifest_import_invalid_agent_yaml(self, tmp_path: Path):
        (tmp_path / "agent.yaml").write_text("not_valid: true\n")
        result = runner.invoke(app, ["manifest-import", str(tmp_path)])
        assert result.exit_code == 1
        assert "✗ Failed to load agent manifest" in result.output

    def test_manifest_import_shows_generated_rules(self, tmp_path: Path):
        _create_agent_yaml(tmp_path, compliance=True)
        result = runner.invoke(app, ["manifest-import", str(tmp_path)])
        assert result.exit_code == 0
        assert "MCPKernel policy rule(s)" in result.output


# ── manifest-validate ──────────────────────────────────────────────────


class TestManifestValidateCommand:
    def test_manifest_validate_success(self, tmp_path: Path):
        _create_agent_yaml(tmp_path, compliance=True)
        result = runner.invoke(app, ["manifest-validate", str(tmp_path)])
        assert result.exit_code == 0
        assert "✓ agent.yaml valid: test-agent" in result.output
        assert "v1.0.0" in result.output

    def test_manifest_validate_shows_tools_count(self, tmp_path: Path):
        _create_agent_yaml(tmp_path)
        result = runner.invoke(app, ["manifest-validate", str(tmp_path)])
        assert result.exit_code == 0
        assert "Tools declared:" in result.output

    def test_manifest_validate_shows_compliance(self, tmp_path: Path):
        _create_agent_yaml(tmp_path, compliance=True)
        result = runner.invoke(app, ["manifest-validate", str(tmp_path)])
        assert result.exit_code == 0
        assert "Compliance: risk_tier=medium" in result.output

    def test_manifest_validate_no_compliance(self, tmp_path: Path):
        _create_agent_yaml(tmp_path, compliance=False)
        result = runner.invoke(app, ["manifest-validate", str(tmp_path)])
        assert result.exit_code == 0
        assert "Compliance: not configured" in result.output

    def test_manifest_validate_missing_agent_yaml(self, tmp_path: Path):
        result = runner.invoke(app, ["manifest-validate", str(tmp_path)])
        assert result.exit_code == 1
        assert "✗ Validation failed" in result.output

    def test_manifest_validate_with_tool_schemas(self, tmp_path: Path):
        _create_agent_yaml(tmp_path)
        _create_tool_schema(tmp_path, "read_file")
        result = runner.invoke(app, ["manifest-validate", str(tmp_path)])
        assert result.exit_code == 0
        assert "Tool schemas loaded:" in result.output
        assert "read_file" in result.output
        assert "read-only" in result.output

    def test_manifest_validate_with_soul_md(self, tmp_path: Path):
        _create_agent_yaml(tmp_path)
        (tmp_path / "SOUL.md").write_text("# Agent Soul\nBe helpful and accurate.")
        result = runner.invoke(app, ["manifest-validate", str(tmp_path)])
        assert result.exit_code == 0
        assert "SOUL.md:" in result.output

    def test_manifest_validate_with_rules_md(self, tmp_path: Path):
        _create_agent_yaml(tmp_path)
        (tmp_path / "RULES.md").write_text("# Rules\n- Never delete files")
        result = runner.invoke(app, ["manifest-validate", str(tmp_path)])
        assert result.exit_code == 0
        assert "RULES.md:" in result.output


# ── scan ───────────────────────────────────────────────────────────────


class TestScanCommand:
    def test_scan_clean_file(self, tmp_path: Path):
        f = tmp_path / "clean.py"
        f.write_text("x = 1 + 2\nprint(x)\n")
        result = runner.invoke(app, ["scan", str(f)])
        assert result.exit_code == 0
        assert "✓ No dangerous patterns" in result.output

    def test_scan_dangerous_file(self, tmp_path: Path):
        f = tmp_path / "bad.py"
        f.write_text("data = eval(input())\n")
        result = runner.invoke(app, ["scan", str(f)])
        # Should exit 1 for critical findings
        assert result.exit_code == 1
        assert "issue(s)" in result.output

    def test_scan_missing_file(self, tmp_path: Path):
        result = runner.invoke(app, ["scan", str(tmp_path / "nope.py")])
        assert result.exit_code == 1
        assert "File not found" in result.output


# ── serve ──────────────────────────────────────────────────────────────


class TestServeCommand:
    def test_serve_is_registered(self):
        """Verify that the serve command is registered in the app."""
        command_names = [cmd.callback.__name__ for cmd in app.registered_commands if cmd.callback]
        assert "serve" in command_names

    @patch("mcpkernel.proxy.server.start_proxy_server")
    @patch("mcpkernel.config.load_config")
    @patch("mcpkernel.utils.configure_logging")
    def test_serve_invokes_proxy_server(self, mock_logging, mock_config, mock_start):
        """Test serve calls start_proxy_server with correct settings."""
        mock_settings = MagicMock()
        mock_settings.proxy = MagicMock()
        mock_config.return_value = mock_settings
        result = runner.invoke(
            app,
            ["serve", "--host", "0.0.0.0", "--port", "9000"],  # noqa: S104
        )
        assert result.exit_code == 0
        mock_start.assert_called_once_with(mock_settings)
        assert mock_settings.proxy.host == "0.0.0.0"  # noqa: S104
        assert mock_settings.proxy.port == 9000


# ── trace-list ─────────────────────────────────────────────────────────


class TestTraceListCommand:
    @patch("mcpkernel.dee.trace_store.TraceStore")
    def test_trace_list_no_traces(self, mock_store_cls, tmp_path: Path):
        """Test trace-list when no traces exist."""
        db_path = str(tmp_path / "traces.db")
        mock_store = AsyncMock()
        mock_store.list_traces.return_value = []
        mock_store_cls.return_value = mock_store

        result = runner.invoke(app, ["trace-list", "--db", db_path])
        assert result.exit_code == 0
        assert "No traces found" in result.output

    @patch("mcpkernel.dee.trace_store.TraceStore")
    def test_trace_list_with_traces(self, mock_store_cls, tmp_path: Path):
        """Test trace-list displays traces correctly."""
        db_path = str(tmp_path / "traces.db")
        mock_store = AsyncMock()
        mock_store.list_traces.return_value = [
            {
                "trace_id": "abc123def456",
                "tool_name": "execute_code",
                "input_hash": "in12345678",
                "output_hash": "out1234567",
                "duration_seconds": 1.234,
            }
        ]
        mock_store_cls.return_value = mock_store

        result = runner.invoke(app, ["trace-list", "--db", db_path])
        assert result.exit_code == 0
        assert "abc123def456"[:12] in result.output
        assert "execute_code" in result.output


# ── trace-export ───────────────────────────────────────────────────────


class TestTraceExportCommand:
    @patch("mcpkernel.dee.trace_store.TraceStore")
    def test_trace_export_found(self, mock_store_cls, tmp_path: Path):
        db_path = str(tmp_path / "traces.db")
        mock_store = AsyncMock()
        mock_store.export_trace.return_value = '{"trace_id": "abc123"}'
        mock_store_cls.return_value = mock_store

        result = runner.invoke(app, ["trace-export", "abc123", "--db", db_path])
        assert result.exit_code == 0
        assert "abc123" in result.output

    @patch("mcpkernel.dee.trace_store.TraceStore")
    def test_trace_export_not_found(self, mock_store_cls, tmp_path: Path):
        db_path = str(tmp_path / "traces.db")
        mock_store = AsyncMock()
        mock_store.export_trace.return_value = None
        mock_store_cls.return_value = mock_store

        result = runner.invoke(app, ["trace-export", "nonexistent", "--db", db_path])
        assert result.exit_code == 1


# ── audit-query ────────────────────────────────────────────────────────


class TestAuditQueryCommand:
    @patch("mcpkernel.audit.exporter.export_audit_logs")
    @patch("mcpkernel.audit.logger.AuditLogger")
    def test_audit_query_no_entries(self, mock_logger_cls, mock_export, tmp_path: Path):
        db_path = str(tmp_path / "audit.db")
        mock_logger = AsyncMock()
        mock_logger.query.return_value = []
        mock_logger_cls.return_value = mock_logger

        result = runner.invoke(app, ["audit-query", "--db", db_path])
        assert result.exit_code == 0
        assert "No audit entries found" in result.output

    @patch("mcpkernel.audit.exporter.export_audit_logs")
    @patch("mcpkernel.audit.logger.AuditLogger")
    def test_audit_query_with_entries(self, mock_logger_cls, mock_export, tmp_path: Path):
        db_path = str(tmp_path / "audit.db")
        mock_logger = AsyncMock()
        mock_logger.query.return_value = [{"event": "tool_call"}]
        mock_logger_cls.return_value = mock_logger
        mock_export.return_value = '{"event": "tool_call"}'

        result = runner.invoke(app, ["audit-query", "--db", db_path])
        assert result.exit_code == 0
        assert "tool_call" in result.output


# ── audit-verify ───────────────────────────────────────────────────────


class TestAuditVerifyCommand:
    @patch("mcpkernel.audit.logger.AuditLogger")
    def test_audit_verify_valid(self, mock_logger_cls, tmp_path: Path):
        db_path = str(tmp_path / "audit.db")
        mock_logger = AsyncMock()
        mock_logger.verify_integrity.return_value = {
            "integrity_valid": True,
            "total_entries": 42,
        }
        mock_logger_cls.return_value = mock_logger

        result = runner.invoke(app, ["audit-verify", "--db", db_path])
        assert result.exit_code == 0
        assert "✓ Integrity valid" in result.output
        assert "42 entries" in result.output

    @patch("mcpkernel.audit.logger.AuditLogger")
    def test_audit_verify_tampered(self, mock_logger_cls, tmp_path: Path):
        db_path = str(tmp_path / "audit.db")
        mock_logger = AsyncMock()
        mock_logger.verify_integrity.return_value = {
            "integrity_valid": False,
            "total_entries": 10,
            "tampered_entries": 3,
        }
        mock_logger_cls.return_value = mock_logger

        result = runner.invoke(app, ["audit-verify", "--db", db_path])
        assert result.exit_code == 1


# ── replay ─────────────────────────────────────────────────────────────


class TestReplayCommand:
    @patch("mcpkernel.sandbox.create_backend")
    @patch("mcpkernel.config.load_config")
    @patch("mcpkernel.dee.replay.validate_replay_integrity")
    @patch("mcpkernel.dee.replay.replay")
    @patch("mcpkernel.dee.trace_store.TraceStore")
    def test_replay_match(
        self, mock_store_cls, mock_replay, mock_validate, mock_config, mock_backend_fn, tmp_path: Path
    ):
        db_path = str(tmp_path / "traces.db")
        mock_store = AsyncMock()
        mock_store.get.return_value = {
            "output_hash": "aaaa1111bbbb2222",
        }
        mock_store_cls.return_value = mock_store

        mock_new_trace = MagicMock()
        mock_new_trace.output_hash = "aaaa1111bbbb2222"
        mock_replay.return_value = mock_new_trace
        mock_validate.return_value = True

        mock_settings = MagicMock()
        mock_config.return_value = mock_settings
        mock_backend = MagicMock()
        mock_backend_fn.return_value = mock_backend

        result = runner.invoke(app, ["replay", "trace-abc", "--db", db_path])
        assert result.exit_code == 0
        assert "✓ MATCH" in result.output

    @patch("mcpkernel.dee.trace_store.TraceStore")
    def test_replay_trace_not_found(self, mock_store_cls, tmp_path: Path):
        db_path = str(tmp_path / "traces.db")
        mock_store = AsyncMock()
        mock_store.get.return_value = None
        mock_store_cls.return_value = mock_store

        result = runner.invoke(app, ["replay", "nonexistent", "--db", db_path])
        assert result.exit_code == 1


# ── No-args shows help ────────────────────────────────────────────────


class TestNoArgsHelp:
    def test_no_args_shows_help(self):
        result = runner.invoke(app, [])
        # Typer with no_args_is_help=True exits with code 0 or 2
        assert result.exit_code in (0, 2)
        assert "gateway" in result.output.lower() or "usage" in result.output.lower()

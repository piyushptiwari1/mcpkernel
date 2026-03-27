"""Tests for multi-client MCP server installer."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING
from unittest.mock import patch

if TYPE_CHECKING:
    from pathlib import Path

from mcpkernel.integrations.installer import (
    _backup_config,
    _mcpkernel_server_config,
    install_to_target,
    uninstall_from_target,
)


class TestMcpkernelServerConfig:
    """Tests for server config generation."""

    def test_tools_mode(self) -> None:
        config = _mcpkernel_server_config("tools")
        assert config["args"] == ["mcp-serve"]

    def test_proxy_mode(self) -> None:
        config = _mcpkernel_server_config("proxy")
        assert "serve" in config["args"]
        assert "--transport" in config["args"]


class TestBackupConfig:
    """Tests for config backup."""

    def test_creates_backup(self, tmp_path: Path) -> None:
        config_file = tmp_path / "config.json"
        config_file.write_text('{"existing": true}')
        backup = _backup_config(config_file)
        assert backup is not None
        assert backup.exists()
        assert backup.read_text() == '{"existing": true}'

    def test_no_backup_for_missing_file(self, tmp_path: Path) -> None:
        config_file = tmp_path / "nonexistent.json"
        backup = _backup_config(config_file)
        assert backup is None


class TestInstallToTarget:
    """Tests for install_to_target()."""

    def test_unsupported_target(self) -> None:
        result = install_to_target("unknown_ide")
        assert not result.success
        assert "Unsupported" in result.message

    def test_install_claude(self, tmp_path: Path) -> None:
        config_path = tmp_path / "claude_desktop_config.json"
        with patch(
            "mcpkernel.integrations.installer._get_target_config_path",
            return_value=config_path,
        ):
            result = install_to_target("claude", mode="tools")
            assert result.success
            assert config_path.exists()

            config = json.loads(config_path.read_text())
            assert "mcpkernel" in config["mcpServers"]
            assert "mcp-serve" in config["mcpServers"]["mcpkernel"]["args"]

    def test_install_cursor(self, tmp_path: Path) -> None:
        config_path = tmp_path / "mcp.json"
        with patch(
            "mcpkernel.integrations.installer._get_target_config_path",
            return_value=config_path,
        ):
            result = install_to_target("cursor")
            assert result.success
            config = json.loads(config_path.read_text())
            assert "mcpkernel" in config["mcpServers"]

    def test_install_zed(self, tmp_path: Path) -> None:
        config_path = tmp_path / "settings.json"
        with patch(
            "mcpkernel.integrations.installer._get_target_config_path",
            return_value=config_path,
        ):
            result = install_to_target("zed")
            assert result.success
            config = json.loads(config_path.read_text())
            assert "mcpkernel" in config["context_servers"]

    def test_install_openclaw(self, tmp_path: Path) -> None:
        config_path = tmp_path / "openclaw.json"
        with patch(
            "mcpkernel.integrations.installer._get_target_config_path",
            return_value=config_path,
        ):
            result = install_to_target("openclaw")
            assert result.success
            config = json.loads(config_path.read_text())
            assert "mcpkernel" in config["mcp"]["servers"]

    def test_no_overwrite_without_force(self, tmp_path: Path) -> None:
        config_path = tmp_path / "config.json"
        config_path.write_text(json.dumps({"mcpServers": {"mcpkernel": {"command": "old"}}}))
        with patch(
            "mcpkernel.integrations.installer._get_target_config_path",
            return_value=config_path,
        ):
            result = install_to_target("claude")
            assert not result.success
            assert "already configured" in result.message

    def test_force_overwrite(self, tmp_path: Path) -> None:
        config_path = tmp_path / "config.json"
        config_path.write_text(json.dumps({"mcpServers": {"mcpkernel": {"command": "old"}}}))
        with patch(
            "mcpkernel.integrations.installer._get_target_config_path",
            return_value=config_path,
        ):
            result = install_to_target("claude", force=True)
            assert result.success
            assert result.backup_path is not None

    def test_creates_backup(self, tmp_path: Path) -> None:
        config_path = tmp_path / "config.json"
        config_path.write_text(json.dumps({"existing": True}))
        with patch(
            "mcpkernel.integrations.installer._get_target_config_path",
            return_value=config_path,
        ):
            result = install_to_target("cursor")
            assert result.success
            assert result.backup_path is not None
            assert result.backup_path.exists()

    def test_preserves_existing_config(self, tmp_path: Path) -> None:
        config_path = tmp_path / "config.json"
        config_path.write_text(json.dumps({"mcpServers": {"other": {"command": "other"}}}))
        with patch(
            "mcpkernel.integrations.installer._get_target_config_path",
            return_value=config_path,
        ):
            result = install_to_target("claude")
            assert result.success
            config = json.loads(config_path.read_text())
            assert "other" in config["mcpServers"]
            assert "mcpkernel" in config["mcpServers"]


class TestUninstallFromTarget:
    """Tests for uninstall_from_target()."""

    def test_uninstall_unsupported(self) -> None:
        result = uninstall_from_target("unknown_ide")
        assert not result.success

    def test_uninstall_claude(self, tmp_path: Path) -> None:
        config_path = tmp_path / "config.json"
        config_path.write_text(
            json.dumps(
                {
                    "mcpServers": {
                        "mcpkernel": {"command": "mcpkernel", "args": ["mcp-serve"]},
                        "other": {"command": "other"},
                    }
                }
            )
        )
        with patch(
            "mcpkernel.integrations.installer._get_target_config_path",
            return_value=config_path,
        ):
            result = uninstall_from_target("claude")
            assert result.success
            config = json.loads(config_path.read_text())
            assert "mcpkernel" not in config["mcpServers"]
            assert "other" in config["mcpServers"]

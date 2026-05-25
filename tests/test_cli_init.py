"""Tests for the ``mcpkernel init`` scaffolder (v0.3.0 .env addition + --force)."""

from __future__ import annotations

from typing import TYPE_CHECKING

from typer.testing import CliRunner

from mcpkernel.cli import app

if TYPE_CHECKING:
    from pathlib import Path

runner = CliRunner()


def test_init_scaffolds_env_and_config(tmp_path: Path) -> None:
    result = runner.invoke(app, ["init", str(tmp_path)])
    assert result.exit_code == 0, result.output

    expected = [
        tmp_path / ".env",
        tmp_path / ".mcpkernel" / "config.yaml",
        tmp_path / ".mcpkernel" / "policies" / "default.yaml",
    ]
    for p in expected:
        assert p.exists(), f"missing {p}"
        assert p.read_text().strip(), f"empty {p}"

    env_body = (tmp_path / ".env").read_text()
    assert "MCPKERNEL_PROXY__PORT" in env_body
    assert "MCPKERNEL_SECRETS_BACKEND" in env_body


def test_init_skips_existing_without_force(tmp_path: Path) -> None:
    env = tmp_path / ".env"
    env.write_text("PREEXISTING=1\n")

    result = runner.invoke(app, ["init", str(tmp_path)])
    assert result.exit_code == 0
    assert env.read_text() == "PREEXISTING=1\n"


def test_init_force_overwrites(tmp_path: Path) -> None:
    env = tmp_path / ".env"
    env.write_text("PREEXISTING=1\n")

    result = runner.invoke(app, ["init", str(tmp_path), "--force"])
    assert result.exit_code == 0
    assert "PREEXISTING" not in env.read_text()
    assert "MCPKERNEL_" in env.read_text()


def test_init_rejects_unknown_preset(tmp_path: Path) -> None:
    result = runner.invoke(app, ["init", str(tmp_path), "--preset", "bogus"])
    assert result.exit_code == 1

"""Tests for the pluggable secrets backends."""

from __future__ import annotations

import pytest

from mcpkernel.secrets import (
    EnvBackend,
    SecretsBackend,
    SecretsBackendError,
    _reset_default_backend_for_tests,
    get_backend,
    resolve,
)


@pytest.fixture(autouse=True)
def _clear_cache() -> None:
    _reset_default_backend_for_tests()
    yield
    _reset_default_backend_for_tests()


def test_env_backend_reads_from_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_xxx")
    b = EnvBackend()
    assert b.get("github_token") == "ghp_xxx"
    assert b.get("github.token") == "ghp_xxx"
    assert b.get("github-token") == "ghp_xxx"


def test_env_backend_missing_returns_none(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("DOES_NOT_EXIST", raising=False)
    assert EnvBackend().get("does_not_exist") is None


def test_get_backend_default_is_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("MCPKERNEL_SECRETS_BACKEND", raising=False)
    b = get_backend()
    assert b.name == "env"
    assert isinstance(b, SecretsBackend)


def test_get_backend_explicit_name(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("MCPKERNEL_SECRETS_BACKEND", raising=False)
    assert get_backend("env").name == "env"


def test_get_backend_unknown_raises() -> None:
    with pytest.raises(SecretsBackendError, match="Unknown secrets backend"):
        get_backend("nope")


def test_get_backend_vault_missing_creds(monkeypatch: pytest.MonkeyPatch) -> None:
    pytest.importorskip("hvac")
    monkeypatch.delenv("VAULT_ADDR", raising=False)
    monkeypatch.delenv("VAULT_TOKEN", raising=False)
    with pytest.raises(SecretsBackendError, match="VAULT_ADDR"):
        get_backend("vault")


def test_resolve_returns_plain_value_unchanged() -> None:
    assert resolve("plain") == "plain"
    assert resolve("") == ""
    assert resolve(None) is None


def test_resolve_secret_uri(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MCPKERNEL_SECRETS_BACKEND", "env")
    monkeypatch.setenv("MY_API_KEY", "s3cret")
    assert resolve("secret://my_api_key") == "s3cret"


def test_resolve_missing_secret_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MCPKERNEL_SECRETS_BACKEND", "env")
    monkeypatch.delenv("ABSENT_SECRET", raising=False)
    with pytest.raises(SecretsBackendError, match="not found"):
        resolve("secret://absent_secret")


def test_resolve_with_explicit_backend(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FOO", "bar")
    assert resolve("secret://foo", backend=EnvBackend()) == "bar"

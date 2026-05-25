"""Pluggable secrets backends.

MCPKernel needs to resolve secrets (JWT signing keys, upstream API tokens,
DEE signing material, database URLs, …) from sources other than env vars in
production deployments. This module provides a thin abstraction.

Usage
-----
::

    from mcpkernel.secrets import get_backend, resolve

    backend = get_backend()                # honours MCPKERNEL_SECRETS_BACKEND
    api_key = backend.get("github_token")  # → "ghp_…"

    # In configs that may contain ``secret://NAME`` URIs:
    real_value = resolve("secret://github_token")

Backends
--------
- ``env`` — read uppercased ``NAME`` from ``os.environ`` (default; zero deps)
- ``vault`` — HashiCorp Vault KV v2 (requires ``hvac``)
- ``aws`` — AWS Secrets Manager (requires ``boto3``)
- ``gcp`` — Google Secret Manager (requires ``google-cloud-secret-manager``)

All cloud SDKs are lazy-imported so installing them stays optional.
"""

from __future__ import annotations

import os
from typing import Protocol, runtime_checkable

__all__ = [
    "AwsSecretsManagerBackend",
    "EnvBackend",
    "GcpSecretManagerBackend",
    "SecretsBackend",
    "SecretsBackendError",
    "VaultBackend",
    "get_backend",
    "resolve",
]

SECRET_URI_PREFIX = "secret://"  # noqa: S105 - URI scheme, not a password


class SecretsBackendError(RuntimeError):
    """Raised when a backend cannot be initialised or a lookup fails."""


@runtime_checkable
class SecretsBackend(Protocol):
    """Read-only key/value secret lookup."""

    name: str

    def get(self, key: str) -> str | None:
        """Return the secret value for ``key`` or ``None`` if absent."""
        ...


# ---------------------------------------------------------------------------
# env backend
# ---------------------------------------------------------------------------
class EnvBackend:
    """Resolve secrets from process environment variables.

    Keys are upper-cased and dots/dashes replaced with underscores, so
    ``backend.get("github.token")`` reads ``GITHUB_TOKEN``.
    """

    name = "env"

    def get(self, key: str) -> str | None:
        env_key = key.upper().replace(".", "_").replace("-", "_")
        return os.environ.get(env_key)


# ---------------------------------------------------------------------------
# HashiCorp Vault
# ---------------------------------------------------------------------------
class VaultBackend:
    """HashiCorp Vault KV v2 backend.

    Reads ``VAULT_ADDR`` / ``VAULT_TOKEN`` / ``VAULT_NAMESPACE`` and a
    ``MCPKERNEL_VAULT_MOUNT`` (default ``secret``) for the KV mount point.
    Keys are interpreted as relative Vault paths; the returned value is the
    ``value`` field if present, otherwise the first field of the secret.
    """

    name = "vault"

    def __init__(self) -> None:
        try:
            import hvac
        except ImportError as exc:  # pragma: no cover - depends on extras
            msg = "VaultBackend requires the 'hvac' package. Install with: pip install hvac"
            raise SecretsBackendError(msg) from exc

        addr = os.environ.get("VAULT_ADDR")
        token = os.environ.get("VAULT_TOKEN")
        if not addr or not token:
            msg = "VAULT_ADDR and VAULT_TOKEN must be set for VaultBackend"
            raise SecretsBackendError(msg)

        kwargs = {"url": addr, "token": token}
        if ns := os.environ.get("VAULT_NAMESPACE"):
            kwargs["namespace"] = ns
        self._client = hvac.Client(**kwargs)
        self._mount = os.environ.get("MCPKERNEL_VAULT_MOUNT", "secret")

    def get(self, key: str) -> str | None:
        try:
            resp = self._client.secrets.kv.v2.read_secret_version(
                path=key,
                mount_point=self._mount,
                raise_on_deleted_version=False,
            )
        except Exception:
            return None
        data = resp.get("data", {}).get("data", {}) if isinstance(resp, dict) else {}
        if not data:
            return None
        if "value" in data:
            return str(data["value"])
        first_key = next(iter(data))
        return str(data[first_key])


# ---------------------------------------------------------------------------
# AWS Secrets Manager
# ---------------------------------------------------------------------------
class AwsSecretsManagerBackend:
    """AWS Secrets Manager backend.

    Uses the standard ``boto3`` credential chain. Keys are passed to
    ``GetSecretValue`` as-is. JSON payloads are returned verbatim; binary
    secrets are base64-decoded by boto3 and decoded as UTF-8.
    """

    name = "aws"

    def __init__(self) -> None:
        try:
            import boto3
        except ImportError as exc:  # pragma: no cover
            msg = "AwsSecretsManagerBackend requires 'boto3'. Install with: pip install boto3"
            raise SecretsBackendError(msg) from exc

        region = os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION")
        self._client = boto3.client("secretsmanager", region_name=region)

    def get(self, key: str) -> str | None:
        try:
            resp = self._client.get_secret_value(SecretId=key)
        except Exception:
            return None
        if "SecretString" in resp:
            return str(resp["SecretString"])
        if "SecretBinary" in resp:
            return resp["SecretBinary"].decode("utf-8", errors="replace")
        return None


# ---------------------------------------------------------------------------
# GCP Secret Manager
# ---------------------------------------------------------------------------
class GcpSecretManagerBackend:
    """Google Cloud Secret Manager backend.

    Uses application default credentials. Reads ``GOOGLE_CLOUD_PROJECT`` for
    the project ID; keys are interpreted as secret names (latest version is
    fetched).
    """

    name = "gcp"

    def __init__(self) -> None:
        try:
            from google.cloud import secretmanager
        except ImportError as exc:  # pragma: no cover
            msg = "GcpSecretManagerBackend requires 'google-cloud-secret-manager'."
            raise SecretsBackendError(msg) from exc

        project = os.environ.get("GOOGLE_CLOUD_PROJECT")
        if not project:
            msg = "GOOGLE_CLOUD_PROJECT must be set for GcpSecretManagerBackend"
            raise SecretsBackendError(msg)
        self._project = project
        self._client = secretmanager.SecretManagerServiceClient()

    def get(self, key: str) -> str | None:
        path = f"projects/{self._project}/secrets/{key}/versions/latest"
        try:
            resp = self._client.access_secret_version(request={"name": path})
        except Exception:
            return None
        return resp.payload.data.decode("utf-8", errors="replace")


# ---------------------------------------------------------------------------
# Factory + resolver
# ---------------------------------------------------------------------------
_BACKENDS: dict[str, type] = {
    "env": EnvBackend,
    "vault": VaultBackend,
    "aws": AwsSecretsManagerBackend,
    "gcp": GcpSecretManagerBackend,
}

_DEFAULT_BACKEND: SecretsBackend | None = None


def get_backend(name: str | None = None) -> SecretsBackend:
    """Return a configured secrets backend.

    ``name`` defaults to ``MCPKERNEL_SECRETS_BACKEND`` (which itself defaults
    to ``env``). The returned backend for the default invocation is cached
    per-process.
    """
    global _DEFAULT_BACKEND

    if name is None:
        name = os.environ.get("MCPKERNEL_SECRETS_BACKEND", "env").lower()
        if _DEFAULT_BACKEND is not None and _DEFAULT_BACKEND.name == name:
            return _DEFAULT_BACKEND

    if name not in _BACKENDS:
        msg = f"Unknown secrets backend '{name}'. Choose one of: {', '.join(_BACKENDS)}"
        raise SecretsBackendError(msg)

    backend = _BACKENDS[name]()
    if name == os.environ.get("MCPKERNEL_SECRETS_BACKEND", "env").lower():
        _DEFAULT_BACKEND = backend
    return backend


def resolve(value: str | None, *, backend: SecretsBackend | None = None) -> str | None:
    """Resolve ``secret://NAME`` URIs to their concrete value.

    Non-URI values are returned unchanged. Missing secrets raise
    :class:`SecretsBackendError` rather than silently returning ``None`` —
    callers should never deploy with unresolved secret references.
    """
    if not value or not isinstance(value, str) or not value.startswith(SECRET_URI_PREFIX):
        return value

    key = value[len(SECRET_URI_PREFIX) :]
    backend = backend or get_backend()
    resolved = backend.get(key)
    if resolved is None:
        msg = f"Secret '{key}' not found in backend '{backend.name}'"
        raise SecretsBackendError(msg)
    return resolved


def _reset_default_backend_for_tests() -> None:
    """Test helper — clear the cached default backend."""
    global _DEFAULT_BACKEND
    _DEFAULT_BACKEND = None

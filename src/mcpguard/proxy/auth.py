"""Authentication backends for the proxy gateway."""

from __future__ import annotations

import hmac
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any

from mcpguard.utils import AuthError, get_logger

logger = get_logger(__name__)


@dataclass
class AuthCredentials:
    """Validated caller identity."""

    identity: str
    scopes: set[str]
    metadata: dict[str, Any]


class AuthBackend(ABC):
    """Base class for pluggable authentication backends."""

    @abstractmethod
    async def authenticate(self, headers: dict[str, str]) -> AuthCredentials:
        """Validate the request and return credentials.

        Raises :class:`AuthError` on failure.
        """


class APIKeyAuth(AuthBackend):
    """Static API key authentication using ``Authorization: Bearer <key>``."""

    def __init__(self, valid_keys: list[str]) -> None:
        # Store hashed keys to avoid timing-based comparison leaking key material
        self._hashed_keys = {self._hash_key(k) for k in valid_keys}

    @staticmethod
    def _hash_key(key: str) -> str:
        import hashlib

        return hashlib.sha256(key.encode()).hexdigest()

    async def authenticate(self, headers: dict[str, str]) -> AuthCredentials:
        auth_header = headers.get("authorization", "")
        if not auth_header.lower().startswith("bearer "):
            raise AuthError("Missing or malformed Authorization header")

        token = auth_header[7:]
        token_hash = self._hash_key(token)

        if token_hash not in self._hashed_keys:
            raise AuthError("Invalid API key")

        return AuthCredentials(
            identity=f"apikey:{token_hash[:12]}",
            scopes={"*"},
            metadata={"auth_method": "api_key"},
        )


class NoAuth(AuthBackend):
    """Passthrough — allows all requests (development mode)."""

    async def authenticate(self, headers: dict[str, str]) -> AuthCredentials:
        return AuthCredentials(
            identity="anonymous",
            scopes={"*"},
            metadata={"auth_method": "none"},
        )


def create_auth_backend(config: Any) -> AuthBackend:
    """Factory: build the appropriate auth backend from config."""
    from mcpguard.config import AuthConfig

    if not isinstance(config, AuthConfig) or not config.enabled:
        return NoAuth()

    if config.api_keys:
        return APIKeyAuth(config.api_keys)

    # OAuth2 / mTLS would be added here — for now fall back to NoAuth
    return NoAuth()

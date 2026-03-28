"""Authentication backends for the proxy gateway."""

from __future__ import annotations

import time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, ClassVar

from mcpkernel.utils import AuthError, get_logger

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


class OAuth2Auth(AuthBackend):
    """JWT-based OAuth2 authentication using a remote JWKS endpoint.

    Validates the ``Authorization: Bearer <jwt>`` header by:
    1. Fetching the JWKS key set from ``jwks_url`` (cached).
    2. Decoding and verifying the JWT signature.
    3. Checking issuer and audience claims when configured.
    """

    # JWKS cache: {url: (keys_dict, fetch_timestamp)}
    _jwks_cache: ClassVar[dict[str, tuple[dict[str, Any], float]]] = {}
    _JWKS_TTL_SECONDS: ClassVar[int] = 300  # 5 minutes

    def __init__(
        self,
        jwks_url: str,
        issuer: str | None = None,
        audience: str | None = None,
    ) -> None:
        self._jwks_url = jwks_url
        self._issuer = issuer
        self._audience = audience

    def _get_cached_jwks(self) -> dict[str, Any] | None:
        entry = self._jwks_cache.get(self._jwks_url)
        if entry is None:
            return None
        keys, ts = entry
        if time.monotonic() - ts > self._JWKS_TTL_SECONDS:
            return None
        return keys

    async def _fetch_jwks(self) -> dict[str, Any]:
        """Fetch JWKS from the configured URL (with caching)."""
        cached = self._get_cached_jwks()
        if cached is not None:
            return cached

        import httpx

        try:
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.get(self._jwks_url)
                resp.raise_for_status()
                jwks_data: dict[str, Any] = resp.json()
        except Exception as exc:
            raise AuthError(f"Failed to fetch JWKS from {self._jwks_url}: {exc}") from exc

        self._jwks_cache[self._jwks_url] = (jwks_data, time.monotonic())
        return jwks_data

    async def authenticate(self, headers: dict[str, str]) -> AuthCredentials:
        try:
            import jwt
            from jwt import PyJWKClient
        except ImportError as exc:
            raise AuthError("PyJWT[crypto] not installed — run: pip install PyJWT[crypto]") from exc

        auth_header = headers.get("authorization", "")
        if not auth_header.lower().startswith("bearer "):
            raise AuthError("Missing or malformed Authorization header")

        token = auth_header[7:].strip()
        if not token:
            raise AuthError("Empty bearer token")

        jwks_data = await self._fetch_jwks()

        try:
            if hasattr(PyJWKClient, "from_jwk_set_cache"):
                jwk_client = PyJWKClient.from_jwk_set_cache(jwks_data)
            else:
                jwk_client = PyJWKClient(self._jwks_url)
            signing_key = jwk_client.get_signing_key_from_jwt(token)

            decode_options: dict[str, Any] = {"algorithms": ["RS256", "RS384", "RS512", "ES256", "ES384", "ES512"]}
            if self._issuer:
                decode_options["issuer"] = self._issuer
            if self._audience:
                decode_options["audience"] = self._audience

            payload: dict[str, Any] = jwt.decode(
                token,
                signing_key.key,
                **decode_options,
            )
        except jwt.ExpiredSignatureError as exc:
            raise AuthError("Token has expired") from exc
        except jwt.InvalidAudienceError as exc:
            raise AuthError("Invalid token audience") from exc
        except jwt.InvalidIssuerError as exc:
            raise AuthError("Invalid token issuer") from exc
        except jwt.InvalidTokenError as exc:
            raise AuthError(f"Invalid JWT: {exc}") from exc

        # Extract identity and scopes from standard claims
        subject = payload.get("sub", "unknown")
        scope_str = payload.get("scope", payload.get("scp", ""))
        scopes: set[str] = set(scope_str.split()) if isinstance(scope_str, str) and scope_str else {"*"}

        return AuthCredentials(
            identity=f"oauth2:{subject}",
            scopes=scopes,
            metadata={
                "auth_method": "oauth2",
                "issuer": payload.get("iss"),
                "audience": payload.get("aud"),
                "expires_at": payload.get("exp"),
            },
        )


class MTLSAuth(AuthBackend):
    """Mutual TLS (mTLS) client certificate authentication.

    Validates the client certificate presented during the TLS handshake
    against a trusted CA certificate.  The certificate's Common Name (CN)
    or Subject Alternative Name (SAN) is used as the identity.

    In production the TLS termination happens in the ASGI server (uvicorn)
    or a reverse proxy.  The client cert is forwarded via the
    ``X-Client-Cert`` header (PEM-encoded, URL-encoded) or obtained from
    the ASGI connection scope.
    """

    def __init__(self, ca_cert_path: str) -> None:
        self._ca_cert_path = ca_cert_path

    def _load_ca_cert(self) -> Any:
        """Load the trusted CA certificate."""
        from cryptography import x509

        with open(self._ca_cert_path, "rb") as fh:
            pem_data = fh.read()

        try:
            return x509.load_pem_x509_certificate(pem_data)
        except Exception as exc:
            raise AuthError(f"Failed to load CA certificate: {exc}") from exc

    @staticmethod
    def _parse_client_cert(pem_str: str) -> Any:
        """Parse a PEM-encoded client certificate."""
        import urllib.parse

        from cryptography import x509

        decoded = urllib.parse.unquote(pem_str)
        try:
            return x509.load_pem_x509_certificate(decoded.encode())
        except Exception as exc:
            raise AuthError(f"Invalid client certificate: {exc}") from exc

    @staticmethod
    def _verify_cert(client_cert: Any, ca_cert: Any) -> None:
        """Verify the client cert was issued by the trusted CA."""
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

        try:
            ca_public_key = ca_cert.public_key()
            if isinstance(ca_public_key, rsa.RSAPublicKey):
                ca_public_key.verify(
                    client_cert.signature,
                    client_cert.tbs_certificate_bytes,
                    padding.PKCS1v15(),
                    client_cert.signature_hash_algorithm,
                )
            elif isinstance(ca_public_key, ec.EllipticCurvePublicKey):
                ca_public_key.verify(
                    client_cert.signature,
                    client_cert.tbs_certificate_bytes,
                    ec.ECDSA(client_cert.signature_hash_algorithm),
                )
            else:
                raise AuthError(f"Unsupported CA key type: {type(ca_public_key)}")
        except InvalidSignature as exc:
            raise AuthError("Client certificate not signed by trusted CA") from exc

    @staticmethod
    def _extract_identity(client_cert: Any) -> str:
        """Extract CN from the certificate subject."""
        from cryptography.x509.oid import NameOID

        cn_attrs = client_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        if cn_attrs:
            return str(cn_attrs[0].value)
        return str(client_cert.subject)

    async def authenticate(self, headers: dict[str, str]) -> AuthCredentials:
        # Client cert can come from X-Client-Cert header (set by reverse proxy)
        # or X-SSL-Client-Cert / X-Forwarded-Tls-Client-Cert
        client_cert_pem = (
            headers.get("x-client-cert")
            or headers.get("x-ssl-client-cert")
            or headers.get("x-forwarded-tls-client-cert")
        )

        if not client_cert_pem:
            raise AuthError("No client certificate provided (expected X-Client-Cert header)")

        ca_cert = self._load_ca_cert()
        client_cert = self._parse_client_cert(client_cert_pem)
        self._verify_cert(client_cert, ca_cert)

        identity = self._extract_identity(client_cert)
        logger.info("mtls_authenticated", identity=identity)

        return AuthCredentials(
            identity=f"mtls:{identity}",
            scopes={"*"},
            metadata={
                "auth_method": "mtls",
                "cert_subject": str(client_cert.subject),
                "cert_serial": str(client_cert.serial_number),
            },
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
    from mcpkernel.config import AuthConfig

    if not isinstance(config, AuthConfig) or not config.enabled:
        return NoAuth()

    if config.api_keys:
        return APIKeyAuth(config.api_keys)

    if config.oauth2_jwks_url or config.oauth2_issuer:
        if not config.oauth2_jwks_url:
            raise AuthError("oauth2_jwks_url is required when oauth2_issuer is set")
        return OAuth2Auth(
            jwks_url=config.oauth2_jwks_url,
            issuer=config.oauth2_issuer,
            audience=config.oauth2_audience,
        )

    if config.mtls_ca_cert:
        return MTLSAuth(ca_cert_path=str(config.mtls_ca_cert))

    return NoAuth()

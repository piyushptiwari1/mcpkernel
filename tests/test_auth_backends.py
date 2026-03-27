"""Tests for OAuth2Auth and MTLSAuth backends."""

from __future__ import annotations

import datetime
from typing import TYPE_CHECKING
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from mcpkernel.proxy.auth import (
    APIKeyAuth,
    MTLSAuth,
    OAuth2Auth,
    create_auth_backend,
)
from mcpkernel.utils import AuthError

if TYPE_CHECKING:
    from pathlib import Path

# =====================================================================
# OAuth2Auth
# =====================================================================


class TestOAuth2Auth:
    """Tests for JWT-based OAuth2 authentication."""

    @pytest.mark.asyncio
    async def test_missing_auth_header(self) -> None:
        auth = OAuth2Auth(jwks_url="https://example.com/.well-known/jwks.json")
        with pytest.raises(AuthError, match="Missing or malformed"):
            await auth.authenticate({})

    @pytest.mark.asyncio
    async def test_non_bearer_header(self) -> None:
        auth = OAuth2Auth(jwks_url="https://example.com/.well-known/jwks.json")
        with pytest.raises(AuthError, match="Missing or malformed"):
            await auth.authenticate({"authorization": "Basic abc123"})

    @pytest.mark.asyncio
    async def test_empty_bearer_token(self) -> None:
        auth = OAuth2Auth(jwks_url="https://example.com/.well-known/jwks.json")
        with pytest.raises(AuthError, match="Empty bearer token"):
            await auth.authenticate({"authorization": "Bearer "})

    @pytest.mark.asyncio
    async def test_jwks_fetch_failure(self) -> None:
        auth = OAuth2Auth(jwks_url="https://example.com/.well-known/jwks.json")
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=Exception("connection failed"))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with (
            patch("httpx.AsyncClient", return_value=mock_client),
            pytest.raises(AuthError, match="Failed to fetch JWKS"),
        ):
            await auth.authenticate({"authorization": "Bearer some.jwt.token"})

    @pytest.mark.asyncio
    async def test_pyjwt_not_installed(self) -> None:
        auth = OAuth2Auth(jwks_url="https://example.com/.well-known/jwks.json")
        with patch.dict("sys.modules", {"jwt": None}), pytest.raises(AuthError, match="PyJWT"):
            await auth.authenticate({"authorization": "Bearer some.jwt.token"})

    @pytest.mark.asyncio
    async def test_successful_authentication(self) -> None:
        """Test OAuth2 auth with a fully mocked JWT flow."""
        auth = OAuth2Auth(
            jwks_url="https://example.com/.well-known/jwks.json",
            issuer="https://example.com",
            audience="my-api",
        )

        # Mock the JWKS fetch
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json.return_value = {"keys": [{"kty": "RSA", "kid": "test-key"}]}
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        # Mock PyJWT decode
        mock_signing_key = MagicMock()
        mock_signing_key.key = "test-key-material"

        mock_jwk_client = MagicMock()
        mock_jwk_client.get_signing_key_from_jwt.return_value = mock_signing_key

        decoded_payload = {
            "sub": "user-123",
            "iss": "https://example.com",
            "aud": "my-api",
            "exp": 99999999999,
            "scope": "read write admin",
        }

        with (
            patch("httpx.AsyncClient", return_value=mock_client),
            patch("jwt.decode", return_value=decoded_payload),
            patch("jwt.PyJWKClient", return_value=mock_jwk_client),
        ):
            creds = await auth.authenticate({"authorization": "Bearer valid.jwt.token"})

        assert creds.identity == "oauth2:user-123"
        assert creds.scopes == {"read", "write", "admin"}
        assert creds.metadata["auth_method"] == "oauth2"
        assert creds.metadata["issuer"] == "https://example.com"

    @pytest.mark.asyncio
    async def test_expired_token(self) -> None:
        import jwt as pyjwt

        auth = OAuth2Auth(jwks_url="https://example.com/.well-known/jwks.json")

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json.return_value = {"keys": []}
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        mock_signing_key = MagicMock()
        mock_signing_key.key = "k"
        mock_jwk_client = MagicMock()
        mock_jwk_client.get_signing_key_from_jwt.return_value = mock_signing_key

        with (
            patch("httpx.AsyncClient", return_value=mock_client),
            patch("jwt.decode", side_effect=pyjwt.ExpiredSignatureError("expired")),
            patch("jwt.PyJWKClient", return_value=mock_jwk_client),
            pytest.raises(AuthError, match="expired"),
        ):
            await auth.authenticate({"authorization": "Bearer expired.jwt.token"})

    @pytest.mark.asyncio
    async def test_invalid_audience(self) -> None:
        import jwt as pyjwt

        auth = OAuth2Auth(
            jwks_url="https://example.com/.well-known/jwks.json",
            audience="expected-audience",
        )

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json.return_value = {"keys": []}
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        mock_signing_key = MagicMock()
        mock_signing_key.key = "k"
        mock_jwk_client = MagicMock()
        mock_jwk_client.get_signing_key_from_jwt.return_value = mock_signing_key

        with (
            patch("httpx.AsyncClient", return_value=mock_client),
            patch("jwt.decode", side_effect=pyjwt.InvalidAudienceError("bad aud")),
            patch("jwt.PyJWKClient", return_value=mock_jwk_client),
            pytest.raises(AuthError, match="audience"),
        ):
            await auth.authenticate({"authorization": "Bearer bad.aud.token"})

    def test_jwks_cache(self) -> None:
        """JWKS responses should be cached."""
        auth = OAuth2Auth(jwks_url="https://example.com/.well-known/jwks.json")
        # Clear class-level cache
        OAuth2Auth._jwks_cache.clear()
        assert auth._get_cached_jwks() is None

    @pytest.mark.asyncio
    async def test_scopes_from_scp_claim(self) -> None:
        """Should also accept 'scp' claim for scopes."""
        auth = OAuth2Auth(jwks_url="https://example.com/.well-known/jwks.json")

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json.return_value = {"keys": []}
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        mock_signing_key = MagicMock()
        mock_signing_key.key = "k"
        mock_jwk_client = MagicMock()
        mock_jwk_client.get_signing_key_from_jwt.return_value = mock_signing_key

        decoded = {"sub": "user-1", "scp": "admin"}

        with (
            patch("httpx.AsyncClient", return_value=mock_client),
            patch("jwt.decode", return_value=decoded),
            patch("jwt.PyJWKClient", return_value=mock_jwk_client),
        ):
            creds = await auth.authenticate({"authorization": "Bearer tok"})
        assert creds.scopes == {"admin"}


# =====================================================================
# MTLSAuth
# =====================================================================


class TestMTLSAuth:
    """Tests for mutual TLS client certificate authentication."""

    def _make_ca_and_client_certs(self, tmp_path: Path) -> tuple[Path, str]:
        """Generate a self-signed CA + client cert for testing."""
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID

        # CA key/cert
        ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test CA")])
        ca_cert = (
            x509.CertificateBuilder()
            .subject_name(ca_name)
            .issuer_name(ca_name)
            .public_key(ca_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.now(datetime.UTC))
            .not_valid_after(datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(ca_key, hashes.SHA256())
        )

        ca_path = tmp_path / "ca.pem"
        ca_path.write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))

        # Client key/cert signed by CA
        client_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        client_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test-client")])
        client_cert = (
            x509.CertificateBuilder()
            .subject_name(client_name)
            .issuer_name(ca_name)
            .public_key(client_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.now(datetime.UTC))
            .not_valid_after(datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=365))
            .sign(ca_key, hashes.SHA256())
        )

        client_pem = client_cert.public_bytes(serialization.Encoding.PEM).decode()
        return ca_path, client_pem

    @pytest.mark.asyncio
    async def test_no_client_cert_header(self, tmp_path: Path) -> None:
        ca_path = tmp_path / "ca.pem"
        ca_path.touch()
        auth = MTLSAuth(ca_cert_path=str(ca_path))
        with pytest.raises(AuthError, match="No client certificate"):
            await auth.authenticate({})

    @pytest.mark.asyncio
    async def test_invalid_ca_cert(self, tmp_path: Path) -> None:
        ca_path = tmp_path / "ca.pem"
        ca_path.write_text("not a cert")
        auth = MTLSAuth(ca_cert_path=str(ca_path))
        with pytest.raises(AuthError, match="Failed to load CA"):
            await auth.authenticate({"x-client-cert": "some-cert-pem"})

    @pytest.mark.asyncio
    async def test_invalid_client_cert(self, tmp_path: Path) -> None:
        ca_path, _ = self._make_ca_and_client_certs(tmp_path)
        auth = MTLSAuth(ca_cert_path=str(ca_path))
        with pytest.raises(AuthError, match="Invalid client certificate"):
            await auth.authenticate({"x-client-cert": "not-a-valid-cert"})

    @pytest.mark.asyncio
    async def test_successful_mtls_auth(self, tmp_path: Path) -> None:
        ca_path, client_pem = self._make_ca_and_client_certs(tmp_path)
        auth = MTLSAuth(ca_cert_path=str(ca_path))

        creds = await auth.authenticate({"x-client-cert": client_pem})
        assert creds.identity == "mtls:test-client"
        assert creds.metadata["auth_method"] == "mtls"

    @pytest.mark.asyncio
    async def test_x_ssl_client_cert_header(self, tmp_path: Path) -> None:
        """Should also accept X-SSL-Client-Cert header."""
        ca_path, client_pem = self._make_ca_and_client_certs(tmp_path)
        auth = MTLSAuth(ca_cert_path=str(ca_path))

        creds = await auth.authenticate({"x-ssl-client-cert": client_pem})
        assert creds.identity == "mtls:test-client"

    @pytest.mark.asyncio
    async def test_x_forwarded_tls_header(self, tmp_path: Path) -> None:
        """Should also accept X-Forwarded-Tls-Client-Cert header."""
        ca_path, client_pem = self._make_ca_and_client_certs(tmp_path)
        auth = MTLSAuth(ca_cert_path=str(ca_path))

        creds = await auth.authenticate({"x-forwarded-tls-client-cert": client_pem})
        assert creds.identity == "mtls:test-client"

    @pytest.mark.asyncio
    async def test_untrusted_client_cert(self, tmp_path: Path) -> None:
        """Client cert signed by a different CA should fail."""
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID

        # Create the "trusted" CA
        ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Trusted CA")])
        ca_cert = (
            x509.CertificateBuilder()
            .subject_name(ca_name)
            .issuer_name(ca_name)
            .public_key(ca_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.now(datetime.UTC))
            .not_valid_after(datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(ca_key, hashes.SHA256())
        )
        ca_path = tmp_path / "trusted_ca.pem"
        ca_path.write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))

        # Create a DIFFERENT CA and sign the client cert with it
        rogue_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        rogue_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Rogue CA")])
        client_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        client_cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "rogue-client")]))
            .issuer_name(rogue_name)
            .public_key(client_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.now(datetime.UTC))
            .not_valid_after(datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=365))
            .sign(rogue_key, hashes.SHA256())
        )
        client_pem = client_cert.public_bytes(serialization.Encoding.PEM).decode()

        auth = MTLSAuth(ca_cert_path=str(ca_path))
        with pytest.raises(AuthError, match="not signed by trusted CA"):
            await auth.authenticate({"x-client-cert": client_pem})


# =====================================================================
# create_auth_backend factory
# =====================================================================


class TestCreateAuthBackendFactory:
    """Test the factory function with the new backends."""

    def test_oauth2_with_jwks_url(self) -> None:
        from mcpkernel.config import AuthConfig

        config = AuthConfig(
            enabled=True,
            oauth2_jwks_url="https://login.example.com/.well-known/jwks.json",
            oauth2_issuer="https://login.example.com",
            oauth2_audience="my-api",
        )
        backend = create_auth_backend(config)
        assert isinstance(backend, OAuth2Auth)

    def test_oauth2_issuer_only_raises(self) -> None:
        from mcpkernel.config import AuthConfig

        config = AuthConfig(enabled=True, oauth2_issuer="https://example.com")
        with pytest.raises(AuthError, match="oauth2_jwks_url is required"):
            create_auth_backend(config)

    def test_mtls_backend(self, tmp_path: Path) -> None:
        from mcpkernel.config import AuthConfig

        ca = tmp_path / "ca.pem"
        ca.touch()
        config = AuthConfig(enabled=True, mtls_ca_cert=ca)
        backend = create_auth_backend(config)
        assert isinstance(backend, MTLSAuth)

    def test_api_keys_take_priority_over_oauth2(self) -> None:
        """When api_keys are set, they should be used even if oauth2 is configured."""
        from mcpkernel.config import AuthConfig

        config = AuthConfig(
            enabled=True,
            api_keys=["key-1"],
            oauth2_jwks_url="https://example.com/.well-known/jwks.json",
        )
        backend = create_auth_backend(config)
        assert isinstance(backend, APIKeyAuth)

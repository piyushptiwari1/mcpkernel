"""Tests for production-hardening specs (SPEC-012 through SPEC-026)."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest

# =====================================================================
# SPEC-012: Dynamic version strings
# =====================================================================


class TestDynamicVersion:
    """Version should come from __init__ not hardcoded."""

    def test_version_string_exists(self):
        from mcpkernel import __version__

        assert __version__
        assert isinstance(__version__, str)

    @pytest.mark.asyncio
    async def test_health_returns_package_version(self):
        from httpx import ASGITransport, AsyncClient

        from mcpkernel import __version__
        from mcpkernel.proxy.server import create_proxy_app

        app = create_proxy_app()
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/health")
            assert resp.json()["version"] == __version__

    @pytest.mark.asyncio
    async def test_status_returns_package_version(self):
        from httpx import ASGITransport, AsyncClient

        from mcpkernel import __version__
        from mcpkernel.proxy.server import create_proxy_app

        app = create_proxy_app()
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/status")
            assert resp.json()["version"] == __version__


# =====================================================================
# SPEC-013: CORS hardening
# =====================================================================


class TestCORSHardening:
    """CORS default should be restrictive, not wildcard."""

    def test_default_cors_origins_empty(self):
        from mcpkernel.config import MCPKernelSettings

        settings = MCPKernelSettings()
        assert settings.proxy.cors_origins == []

    def test_cors_origins_not_wildcard_by_default(self):
        from mcpkernel.config import MCPKernelSettings

        settings = MCPKernelSettings()
        assert "*" not in settings.proxy.cors_origins


# =====================================================================
# SPEC-014: Content-length crash protection
# =====================================================================


class TestContentLengthProtection:
    """Malformed Content-Length should not crash the server."""

    @pytest.mark.asyncio
    async def test_malformed_content_length_returns_413(self):
        from httpx import ASGITransport, AsyncClient

        from mcpkernel.proxy.server import create_proxy_app

        app = create_proxy_app()
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post(
                "/mcp/legacy",
                content=b'{"jsonrpc":"2.0","method":"tools/call","params":{"name":"test"},"id":1}',
                headers={"Content-Type": "application/json", "Content-Length": "abc"},
            )
            assert resp.status_code == 413


# =====================================================================
# SPEC-015: Error sanitization
# =====================================================================


class TestErrorSanitization:
    """Upstream errors should not leak internal details."""

    @pytest.mark.asyncio
    async def test_upstream_error_is_sanitized(self):
        from unittest.mock import AsyncMock, patch

        from mcpkernel.proxy.interceptor import MCPToolCall
        from mcpkernel.proxy.server import _forward_to_upstream

        mock_manager = MagicMock()
        mock_manager.connections = {"test": MagicMock(connected=True)}
        mock_manager.call_tool = AsyncMock(side_effect=RuntimeError("secret internal error details"))

        with patch("mcpkernel.proxy.server._upstream_manager", mock_manager):
            call = MCPToolCall(tool_name="test_tool", arguments={"x": 1}, request_id="test-1", raw_jsonrpc={})
            result = await _forward_to_upstream(call)
            assert result.is_error is True
            # Must NOT contain the raw exception text
            error_text = result.content[0]["text"]
            assert "secret internal error" not in error_text
            assert error_text == "Upstream server error"


# =====================================================================
# SPEC-016: TLS wiring
# =====================================================================


class TestTLSWiring:
    """TLS cert/key should be passed to uvicorn when configured."""

    def test_tls_kwargs_passed_to_uvicorn(self, tmp_path: Path):
        from unittest.mock import patch

        from mcpkernel.config import MCPKernelSettings
        from mcpkernel.proxy.server import start_proxy_server

        cert = tmp_path / "test-cert.pem"
        key = tmp_path / "test-key.pem"
        cert.touch()
        key.touch()

        settings = MCPKernelSettings()
        settings.proxy.tls_cert = cert
        settings.proxy.tls_key = key

        with patch("mcpkernel.proxy.server.uvicorn") as mock_uvicorn:
            mock_uvicorn.run = MagicMock()
            start_proxy_server(settings)
            call_kwargs = mock_uvicorn.run.call_args
            assert call_kwargs.kwargs.get("ssl_certfile") == str(cert)
            assert call_kwargs.kwargs.get("ssl_keyfile") == str(key)

    def test_no_tls_kwargs_without_config(self):
        from unittest.mock import patch

        from mcpkernel.config import MCPKernelSettings
        from mcpkernel.proxy.server import start_proxy_server

        settings = MCPKernelSettings()
        # No TLS config

        with patch("mcpkernel.proxy.server.uvicorn") as mock_uvicorn:
            mock_uvicorn.run = MagicMock()
            start_proxy_server(settings)
            call_kwargs = mock_uvicorn.run.call_args
            all_kwargs = {**dict(call_kwargs.kwargs)}
            assert "ssl_certfile" not in all_kwargs
            assert "ssl_keyfile" not in all_kwargs


# =====================================================================
# SPEC-017: HealthCheck wiring
# =====================================================================


class TestHealthCheckWiring:
    """HealthCheck aggregator should be used in /health."""

    @pytest.mark.asyncio
    async def test_health_returns_service_name(self):
        from httpx import ASGITransport, AsyncClient

        from mcpkernel.proxy.server import create_proxy_app

        app = create_proxy_app()
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/health")
            data = resp.json()
            assert data["service"] == "mcpkernel"
            assert data["status"] == "healthy"

    @pytest.mark.asyncio
    async def test_health_returns_mode(self):
        from httpx import ASGITransport, AsyncClient

        from mcpkernel.proxy.server import create_proxy_app

        app = create_proxy_app()
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/health")
            data = resp.json()
            assert "mode" in data


# =====================================================================
# SPEC-018: Auth backends — OAuth2, mTLS, API keys
# =====================================================================


class TestAuthBackends:
    """OAuth2 and mTLS backends are now implemented."""

    def test_oauth2_creates_backend(self):
        from mcpkernel.config import AuthConfig
        from mcpkernel.proxy.auth import OAuth2Auth, create_auth_backend

        config = AuthConfig(enabled=True, oauth2_jwks_url="https://example.com/.well-known/jwks.json")
        backend = create_auth_backend(config)
        assert isinstance(backend, OAuth2Auth)

    def test_oauth2_issuer_without_jwks_raises_error(self):
        from mcpkernel.config import AuthConfig
        from mcpkernel.proxy.auth import create_auth_backend
        from mcpkernel.utils import AuthError

        config = AuthConfig(enabled=True, oauth2_issuer="https://example.com")
        with pytest.raises(AuthError, match="oauth2_jwks_url is required"):
            create_auth_backend(config)

    def test_mtls_creates_backend(self, tmp_path: Path):
        from mcpkernel.config import AuthConfig
        from mcpkernel.proxy.auth import MTLSAuth, create_auth_backend

        ca = tmp_path / "ca.pem"
        ca.touch()
        config = AuthConfig(enabled=True, mtls_ca_cert=ca)
        backend = create_auth_backend(config)
        assert isinstance(backend, MTLSAuth)

    def test_api_keys_still_works(self):
        from mcpkernel.config import AuthConfig
        from mcpkernel.proxy.auth import APIKeyAuth, create_auth_backend

        config = AuthConfig(enabled=True, api_keys=["test-key-123"])
        backend = create_auth_backend(config)
        assert isinstance(backend, APIKeyAuth)

    def test_disabled_auth_returns_noauth(self):
        from mcpkernel.config import AuthConfig
        from mcpkernel.proxy.auth import NoAuth, create_auth_backend

        config = AuthConfig(enabled=False)
        backend = create_auth_backend(config)
        assert isinstance(backend, NoAuth)


# =====================================================================
# SPEC-019: Unique request_id
# =====================================================================


class TestUniqueRequestId:
    """request_id should be unique, not hardcoded."""

    def test_generate_request_id_unique(self):
        from mcpkernel.utils import generate_request_id

        ids = {generate_request_id() for _ in range(100)}
        assert len(ids) == 100

    def test_generate_request_id_format(self):
        from mcpkernel.utils import generate_request_id

        rid = generate_request_id()
        assert isinstance(rid, str)
        assert len(rid) > 0


# =====================================================================
# SPEC-020: py.typed marker
# =====================================================================


class TestPyTypedMarker:
    """PEP 561 py.typed marker should exist."""

    def test_py_typed_exists(self):
        marker = Path(__file__).parent.parent / "src" / "mcpkernel" / "py.typed"
        assert marker.exists(), "py.typed marker file missing"

    def test_py_typed_empty_or_small(self):
        marker = Path(__file__).parent.parent / "src" / "mcpkernel" / "py.typed"
        assert marker.stat().st_size <= 100  # marker file should be empty or very small


# =====================================================================
# SPEC-021: __main__.py
# =====================================================================


class TestMainModule:
    """python -m mcpkernel should be supported."""

    def test_main_module_exists(self):
        main = Path(__file__).parent.parent / "src" / "mcpkernel" / "__main__.py"
        assert main.exists()

    def test_main_module_importable(self):
        import importlib

        spec = importlib.util.find_spec("mcpkernel.__main__")
        assert spec is not None


# =====================================================================
# SPEC-025: MCP version pin
# =====================================================================


class TestMCPVersionPin:
    """MCP dependency should be pinned to >=1.23,<2."""

    def test_pyproject_mcp_pin(self):
        import tomllib

        pyproject = Path(__file__).parent.parent / "pyproject.toml"
        with open(pyproject, "rb") as f:
            data = tomllib.load(f)
        deps = data["project"]["dependencies"]
        mcp_deps = [d for d in deps if d.startswith("mcp")]
        assert len(mcp_deps) == 1
        assert ">=1.23" in mcp_deps[0]
        assert "<2" in mcp_deps[0]


# =====================================================================
# SPEC-026: HealthCheck default version
# =====================================================================


class TestHealthCheckDefaults:
    """HealthCheck default version should be empty string."""

    def test_default_version_empty(self):
        from mcpkernel.observability.health import HealthCheck

        hc = HealthCheck()
        assert hc._version == ""

    @pytest.mark.asyncio
    async def test_health_report_empty_version(self):
        from mcpkernel.observability.health import HealthCheck

        hc = HealthCheck()
        report = await hc.check()
        assert report.version == ""

    @pytest.mark.asyncio
    async def test_health_report_custom_version(self):
        from mcpkernel.observability.health import HealthCheck

        hc = HealthCheck(version="1.2.3")
        report = await hc.check()
        assert report.version == "1.2.3"

    @pytest.mark.asyncio
    async def test_health_report_with_components(self):
        from mcpkernel.observability.health import ComponentHealth, HealthCheck, HealthStatus

        hc = HealthCheck(version="0.1.2")

        async def _check_ok() -> ComponentHealth:
            return ComponentHealth(name="test", status=HealthStatus.HEALTHY)

        hc.register("test", _check_ok)
        report = await hc.check()
        assert report.status == HealthStatus.HEALTHY
        assert len(report.components) == 1
        assert report.components[0].name == "test"

    @pytest.mark.asyncio
    async def test_health_report_unhealthy_propagates(self):
        from mcpkernel.observability.health import ComponentHealth, HealthCheck, HealthStatus

        hc = HealthCheck()

        async def _check_bad() -> ComponentHealth:
            return ComponentHealth(name="broken", status=HealthStatus.UNHEALTHY)

        hc.register("broken", _check_bad)
        report = await hc.check()
        assert report.status == HealthStatus.UNHEALTHY

    @pytest.mark.asyncio
    async def test_health_report_exception_becomes_unhealthy(self):
        from mcpkernel.observability.health import HealthCheck, HealthStatus

        hc = HealthCheck()

        async def _check_crash() -> None:
            raise RuntimeError("boom")

        hc.register("crash", _check_crash)
        report = await hc.check()
        assert report.status == HealthStatus.UNHEALTHY
        assert report.components[0].details["error"] == "boom"

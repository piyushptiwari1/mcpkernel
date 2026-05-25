"""Tests for the HMAC-gated /health/secret endpoint."""

from __future__ import annotations

import pytest


@pytest.mark.asyncio
async def test_health_secret_hidden_without_token(monkeypatch: pytest.MonkeyPatch) -> None:
    from httpx import ASGITransport, AsyncClient

    from mcpkernel.proxy.server import create_proxy_app

    monkeypatch.delenv("MCPKERNEL_HEALTH_TOKEN", raising=False)
    app = create_proxy_app()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/health/secret")
        assert resp.status_code == 404


@pytest.mark.asyncio
async def test_health_secret_rejects_missing_credentials(monkeypatch: pytest.MonkeyPatch) -> None:
    from httpx import ASGITransport, AsyncClient

    from mcpkernel.proxy.server import create_proxy_app

    monkeypatch.setenv("MCPKERNEL_HEALTH_TOKEN", "topsecret")
    app = create_proxy_app()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/health/secret")
        assert resp.status_code == 401


@pytest.mark.asyncio
async def test_health_secret_rejects_wrong_token(monkeypatch: pytest.MonkeyPatch) -> None:
    from httpx import ASGITransport, AsyncClient

    from mcpkernel.proxy.server import create_proxy_app

    monkeypatch.setenv("MCPKERNEL_HEALTH_TOKEN", "topsecret")
    app = create_proxy_app()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get(
            "/health/secret",
            headers={"Authorization": "Bearer wrong"},
        )
        assert resp.status_code == 401


@pytest.mark.asyncio
async def test_health_secret_accepts_bearer_token(monkeypatch: pytest.MonkeyPatch) -> None:
    from httpx import ASGITransport, AsyncClient

    from mcpkernel.proxy.server import create_proxy_app

    monkeypatch.setenv("MCPKERNEL_HEALTH_TOKEN", "topsecret")
    app = create_proxy_app()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get(
            "/health/secret",
            headers={"Authorization": "Bearer topsecret"},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["service"] == "mcpkernel"
        assert "config" in body
        assert "taint_mode" in body["config"]


@pytest.mark.asyncio
async def test_health_secret_accepts_custom_header(monkeypatch: pytest.MonkeyPatch) -> None:
    from httpx import ASGITransport, AsyncClient

    from mcpkernel.proxy.server import create_proxy_app

    monkeypatch.setenv("MCPKERNEL_HEALTH_TOKEN", "topsecret")
    app = create_proxy_app()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get(
            "/health/secret",
            headers={"X-MCPKernel-Health-Token": "topsecret"},
        )
        assert resp.status_code == 200

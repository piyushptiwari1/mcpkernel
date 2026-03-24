"""MCP Registry integration — discover and validate MCP servers.

Connects to the official MCP Server Registry
(https://github.com/modelcontextprotocol/registry) to discover, search,
and validate upstream MCP servers.

Usage::

    registry = MCPRegistry()
    servers = await registry.search("filesystem")
    details = await registry.get_server("@modelcontextprotocol/server-filesystem")
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from mcpkernel.utils import get_logger

logger = get_logger(__name__)

# The official MCP registry API endpoint
_DEFAULT_REGISTRY_URL = "https://registry.modelcontextprotocol.io"


@dataclass
class RegistryConfig:
    """Configuration for MCP Registry integration."""

    enabled: bool = True
    registry_url: str = _DEFAULT_REGISTRY_URL
    cache_ttl_seconds: int = 300
    timeout_seconds: float = 10.0


@dataclass
class RegistryServer:
    """A server entry from the MCP Registry."""

    name: str
    description: str = ""
    version: str = ""
    repository_url: str = ""
    transport: list[str] = field(default_factory=list)
    categories: list[str] = field(default_factory=list)
    homepage: str = ""
    is_verified: bool = False
    install_command: str = ""

    @property
    def display_name(self) -> str:
        """Human-friendly display name with verification badge."""
        badge = " ✓" if self.is_verified else ""
        return f"{self.name}{badge}"


class MCPRegistry:
    """Client for the official MCP Server Registry.

    Provides search, listing, and validation of MCP servers from the
    community registry.
    """

    def __init__(self, config: RegistryConfig | None = None) -> None:
        self._config = config or RegistryConfig()
        self._client: Any = None
        self._cache: dict[str, Any] = {}
        self._cache_ts: float = 0

    async def _ensure_client(self) -> Any:
        """Lazily create the HTTP client."""
        if self._client is None:
            import httpx

            self._client = httpx.AsyncClient(
                base_url=self._config.registry_url,
                timeout=self._config.timeout_seconds,
                headers={"Accept": "application/json"},
            )
        return self._client

    async def close(self) -> None:
        """Close the HTTP client."""
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    async def search(self, query: str, *, limit: int = 20) -> list[RegistryServer]:
        """Search the registry for servers matching the query.

        Parameters
        ----------
        query:
            Free-text search query (e.g. "filesystem", "git", "database").
        limit:
            Maximum results to return.

        Returns
        -------
        list[RegistryServer]
            Matching server entries, sorted by relevance.
        """
        client = await self._ensure_client()

        try:
            resp = await client.get(
                "/api/v0/servers",
                params={"q": query, "limit": limit},
            )
            if resp.status_code != 200:
                logger.warning("registry search failed", status=resp.status_code)
                return []

            data = resp.json()
            servers_data = data if isinstance(data, list) else data.get("servers", [])
            return [_parse_server(s) for s in servers_data[:limit]]

        except Exception as exc:
            logger.warning("registry search error", error=str(exc))
            return []

    async def list_servers(self, *, limit: int = 50) -> list[RegistryServer]:
        """List all available servers from the registry.

        Uses a local cache to avoid repeated requests.
        """
        import time

        now = time.time()
        if self._cache.get("list") and (now - self._cache_ts) < self._config.cache_ttl_seconds:
            cached: list[RegistryServer] = self._cache["list"]
            return cached[:limit]

        client = await self._ensure_client()

        try:
            resp = await client.get("/api/v0/servers", params={"limit": limit})
            if resp.status_code != 200:
                logger.warning("registry list failed", status=resp.status_code)
                return []

            data = resp.json()
            servers_data = data if isinstance(data, list) else data.get("servers", [])
            servers = [_parse_server(s) for s in servers_data]
            self._cache["list"] = servers
            self._cache_ts = now
            return servers[:limit]

        except Exception as exc:
            logger.warning("registry list error", error=str(exc))
            return []

    async def get_server(self, name: str) -> RegistryServer | None:
        """Get details for a specific server by name.

        Parameters
        ----------
        name:
            Server name/identifier (e.g. ``@modelcontextprotocol/server-filesystem``).
        """
        client = await self._ensure_client()

        try:
            import urllib.parse

            safe_name = urllib.parse.quote(name, safe="@")
            resp = await client.get(f"/api/v0/servers/{safe_name}")
            if resp.status_code == 404:
                return None
            if resp.status_code != 200:
                logger.warning("registry get failed", status=resp.status_code, name=name)
                return None

            return _parse_server(resp.json())

        except Exception as exc:
            logger.warning("registry get error", error=str(exc), name=name)
            return None

    async def validate_server(self, name: str) -> dict[str, Any]:
        """Validate a server entry — check it exists and has expected metadata.

        Returns a dict with validation results.
        """
        server = await self.get_server(name)
        if server is None:
            return {
                "valid": False,
                "name": name,
                "error": "Server not found in registry",
            }

        return {
            "valid": True,
            "name": server.name,
            "verified": server.is_verified,
            "version": server.version,
            "transports": server.transport,
            "categories": server.categories,
            "repository": server.repository_url,
        }


def _parse_server(data: dict[str, Any]) -> RegistryServer:
    """Parse a server dict from the registry API response."""
    return RegistryServer(
        name=data.get("name", data.get("id", "unknown")),
        description=data.get("description", ""),
        version=data.get("version", data.get("version_detail", {}).get("version", "")),
        repository_url=data.get("repository", {}).get("url", data.get("repository_url", "")),
        transport=data.get("transports", data.get("transport", [])),
        categories=data.get("categories", data.get("tags", [])),
        homepage=data.get("homepage", ""),
        is_verified=data.get("is_verified", data.get("verified", False)),
        install_command=data.get("install_command", ""),
    )

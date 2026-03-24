"""MCP/A2A proxy gateway — mandatory chokepoint for all agent tool calls."""

from mcpkernel.proxy.interceptor import HookPhase, InterceptorPipeline, PluginHook
from mcpkernel.proxy.server import create_proxy_app, get_upstream_manager, start_proxy_server
from mcpkernel.proxy.upstream import UpstreamConnection, UpstreamManager

__all__ = [
    "HookPhase",
    "InterceptorPipeline",
    "PluginHook",
    "UpstreamConnection",
    "UpstreamManager",
    "create_proxy_app",
    "get_upstream_manager",
    "start_proxy_server",
]

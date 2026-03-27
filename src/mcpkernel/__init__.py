"""mcpkernel — The mandatory, deterministic MCP/A2A gateway.

Turns every agent tool call into a provably replayable, taint-safe,
policy-enforced execution.

Quick start::

    from mcpkernel import MCPKernelProxy

    async with MCPKernelProxy(upstream=["http://localhost:3000/mcp"]) as proxy:
        result = await proxy.call_tool("read_file", {"path": "data.csv"})
"""

from __future__ import annotations

__version__ = "0.1.3"
__all__ = [
    "POLICY_PRESETS",
    "AuthError",
    "ConfigError",
    "MCPKernelError",
    "MCPKernelProxy",
    "PolicyViolation",
    "SandboxError",
    "TaintViolation",
    "__version__",
    "protect",
]

from mcpkernel.api import POLICY_PRESETS, MCPKernelProxy, protect
from mcpkernel.utils import (
    AuthError,
    ConfigError,
    MCPKernelError,
    PolicyViolation,
    SandboxError,
    TaintViolation,
)

"""mcpkernel — The mandatory, deterministic MCP/A2A gateway.

Turns every agent tool call into a provably replayable, taint-safe,
policy-enforced execution.
"""

from __future__ import annotations

__version__ = "0.1.0"
__all__ = [
    "AuthError",
    "ConfigError",
    "MCPKernelError",
    "PolicyViolation",
    "SandboxError",
    "TaintViolation",
    "__version__",
]

from mcpkernel.utils import (
    AuthError,
    ConfigError,
    MCPKernelError,
    PolicyViolation,
    SandboxError,
    TaintViolation,
)

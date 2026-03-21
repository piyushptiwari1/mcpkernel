"""mcpguard — The mandatory, deterministic MCP/A2A gateway.

Turns every agent tool call into a provably replayable, taint-safe,
policy-enforced execution.
"""

from __future__ import annotations

__version__ = "0.1.0"
__all__ = [
    "__version__",
    "MCPGuardError",
    "AuthError",
    "PolicyViolation",
    "SandboxError",
    "TaintViolation",
    "ConfigError",
]

from mcpguard.utils import (
    AuthError,
    ConfigError,
    MCPGuardError,
    PolicyViolation,
    SandboxError,
    TaintViolation,
)

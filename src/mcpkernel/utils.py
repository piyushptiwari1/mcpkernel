"""Shared utilities, exception hierarchy, hashing helpers, and logging setup."""

from __future__ import annotations

import hashlib
import secrets
import time
from typing import TYPE_CHECKING, Any

import structlog

if TYPE_CHECKING:
    from pathlib import Path


# ---------------------------------------------------------------------------
# Exception hierarchy
# ---------------------------------------------------------------------------
class MCPKernelError(Exception):
    """Base exception for all mcpkernel errors."""


class ConfigError(MCPKernelError):
    """Configuration loading or validation failed."""


class AuthError(MCPKernelError):
    """Authentication or authorization failure."""


class PolicyViolation(MCPKernelError):  # noqa: N818
    """A policy rule blocked the operation."""

    def __init__(self, rule_id: str, message: str, *, details: dict[str, Any] | None = None) -> None:
        self.rule_id = rule_id
        self.details = details or {}
        super().__init__(f"[{rule_id}] {message}")


class SandboxError(MCPKernelError):
    """Sandbox creation or execution failed."""


class TaintViolation(MCPKernelError):  # noqa: N818
    """Tainted data reached a disallowed sink."""

    def __init__(self, source_type: str, sink_type: str, *, details: dict[str, Any] | None = None) -> None:
        self.source_type = source_type
        self.sink_type = sink_type
        self.details = details or {}
        super().__init__(f"Tainted data ({source_type}) reached sink ({sink_type})")


class DriftDetected(MCPKernelError):  # noqa: N818
    """Replay produced different output than original execution."""


class ReplayError(MCPKernelError):
    """Trace replay failed."""


# ---------------------------------------------------------------------------
# Hashing helpers
# ---------------------------------------------------------------------------
def sha256_hex(data: bytes) -> str:
    """Return the SHA-256 hex digest of *data*."""
    return hashlib.sha256(data).hexdigest()


def sha256_json(obj: Any) -> str:
    """Deterministic SHA-256 of a JSON-serialisable object.

    Keys are sorted, no whitespace, to guarantee reproducibility.
    """
    import json

    canonical = json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)
    return sha256_hex(canonical.encode())


def merkle_root(hashes: list[str]) -> str:
    """Compute a Merkle root from a list of hex-digest strings."""
    if not hashes:
        return sha256_hex(b"")
    level = list(hashes)
    while len(level) > 1:
        next_level: list[str] = []
        for i in range(0, len(level), 2):
            left = level[i]
            right = level[i + 1] if i + 1 < len(level) else left
            combined = hashlib.sha256((left + right).encode()).hexdigest()
            next_level.append(combined)
        level = next_level
    return level[0]


def hash_directory(path: Path) -> str:
    """Return a Merkle root of SHA-256 hashes of all files under *path*."""
    file_hashes: list[str] = []
    for fpath in sorted(path.rglob("*")):
        if fpath.is_file():
            file_hashes.append(sha256_hex(fpath.read_bytes()))
    return merkle_root(file_hashes)


# ---------------------------------------------------------------------------
# ID generation
# ---------------------------------------------------------------------------
def generate_trace_id() -> str:
    """Generate a URL-safe trace identifier."""
    return f"tr_{secrets.token_urlsafe(16)}"


def generate_request_id() -> str:
    """Generate a short request correlation ID."""
    return f"req_{secrets.token_urlsafe(12)}"


# ---------------------------------------------------------------------------
# Timing
# ---------------------------------------------------------------------------
class Timer:
    """Simple context-manager timer returning elapsed seconds."""

    def __init__(self) -> None:
        self.start: float = 0.0
        self.elapsed: float = 0.0

    def __enter__(self) -> Timer:
        self.start = time.perf_counter()
        return self

    def __exit__(self, *_: object) -> None:
        self.elapsed = time.perf_counter() - self.start


# ---------------------------------------------------------------------------
# Structured logging setup
# ---------------------------------------------------------------------------
def configure_logging(*, json_output: bool = True, level: str = "INFO") -> None:
    """Configure structlog for mcpkernel.

    * *json_output*: emit JSON lines (production) vs. colored console (dev).
    * *level*: stdlib log level name.
    """
    import logging

    shared_processors: list[structlog.types.Processor] = [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.UnicodeDecoder(),
    ]

    if json_output:
        renderer: structlog.types.Processor = structlog.processors.JSONRenderer()
    else:
        renderer = structlog.dev.ConsoleRenderer()

    structlog.configure(
        processors=[
            *shared_processors,
            structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
        ],
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )

    formatter = structlog.stdlib.ProcessorFormatter(
        processors=[
            structlog.stdlib.ProcessorFormatter.remove_processors_meta,
            renderer,
        ],
        foreign_pre_chain=shared_processors,
    )

    handler = logging.StreamHandler()
    handler.setFormatter(formatter)
    root_logger = logging.getLogger()
    root_logger.handlers = [handler]
    root_logger.setLevel(getattr(logging, level.upper(), logging.INFO))


def get_logger(name: str) -> structlog.stdlib.BoundLogger:
    """Return a bound structlog logger for *name*."""
    return structlog.get_logger(name)  # type: ignore[no-any-return]

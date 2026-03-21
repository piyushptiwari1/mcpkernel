"""Environment snapshot utilities for DEE."""

from __future__ import annotations

import os
from typing import TYPE_CHECKING

from mcpguard.utils import hash_directory, sha256_hex, sha256_json

if TYPE_CHECKING:
    from pathlib import Path


def take_environment_snapshot(
    *,
    workspace_path: Path | None = None,
    include_env_vars: bool = True,
) -> str:
    """Compute a composite hash representing the current execution environment.

    Combines: workspace file tree hash + sorted env-var hash.
    """
    parts: list[str] = []

    # Filesystem hash
    if workspace_path and workspace_path.exists():
        parts.append(hash_directory(workspace_path))
    else:
        parts.append(sha256_hex(b"no-workspace"))

    # Environment variables hash
    if include_env_vars:
        # Only include MCPGUARD_* and a curated set to avoid noise
        filtered_env = {
            k: v for k, v in sorted(os.environ.items()) if k.startswith("MCPGUARD_") or k in _TRACKED_ENV_VARS
        }
        parts.append(sha256_json(filtered_env))
    else:
        parts.append(sha256_hex(b"no-env"))

    combined = ":".join(parts)
    return sha256_hex(combined.encode())


_TRACKED_ENV_VARS = frozenset(
    {
        "PATH",
        "PYTHONPATH",
        "LANG",
        "LC_ALL",
        "HOME",
        "USER",
    }
)

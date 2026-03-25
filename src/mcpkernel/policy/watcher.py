"""Policy hot-reload watcher — monitors policy YAML files and reloads on changes."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import TYPE_CHECKING

from mcpkernel.utils import get_logger

if TYPE_CHECKING:
    from mcpkernel.policy.engine import PolicyEngine

logger = get_logger(__name__)


async def watch_policy_files(
    engine: PolicyEngine,
    paths: list[Path],
    *,
    poll_interval: float = 1.0,
) -> None:
    """Watch policy file paths and reload rules on change.

    Uses file modification time polling for broad compatibility.
    Falls back gracefully if ``watchfiles`` is available.

    Args:
        engine: The policy engine to reload rules into.
        paths: List of policy file or directory paths to watch.
        poll_interval: Seconds between polling checks.
    """
    try:
        await _watch_with_watchfiles(engine, paths)
    except ImportError:
        logger.info("watchfiles not installed, using polling fallback")
        await _watch_with_polling(engine, paths, poll_interval=poll_interval)


async def _watch_with_watchfiles(engine: PolicyEngine, paths: list[Path]) -> None:
    """Watch using the ``watchfiles`` library (efficient inotify/kqueue)."""
    import watchfiles

    str_paths = [str(p) for p in paths if p.exists()]
    if not str_paths:
        logger.warning("no valid policy paths to watch")
        return

    logger.info("policy hot-reload started (watchfiles)", paths=str_paths)
    async for changes in watchfiles.awatch(*str_paths):
        for _change_type, changed_path in changes:
            changed = Path(changed_path)
            if changed.suffix not in (".yaml", ".yml"):
                continue
            await _reload_file(engine, changed)


async def _watch_with_polling(
    engine: PolicyEngine,
    paths: list[Path],
    *,
    poll_interval: float = 1.0,
) -> None:
    """Fallback: watch using mtime polling."""
    mtimes: dict[Path, float] = {}

    # Collect initial mtimes
    yaml_files = _collect_yaml_files(paths)
    for f in yaml_files:
        mtimes[f] = f.stat().st_mtime

    logger.info("policy hot-reload started (polling)", files=len(mtimes), interval=poll_interval)

    while True:
        await asyncio.sleep(poll_interval)
        current_files = _collect_yaml_files(paths)
        for f in current_files:
            try:
                mtime = f.stat().st_mtime
            except OSError:
                continue
            if f not in mtimes or mtimes[f] < mtime:
                mtimes[f] = mtime
                await _reload_file(engine, f)


def _collect_yaml_files(paths: list[Path]) -> list[Path]:
    """Collect all YAML files from the given paths (files or directories)."""
    files: list[Path] = []
    for p in paths:
        if not p.exists():
            continue
        if p.is_file() and p.suffix in (".yaml", ".yml"):
            files.append(p)
        elif p.is_dir():
            files.extend(p.glob("*.yaml"))
            files.extend(p.glob("*.yml"))
    return files


async def _reload_file(engine: PolicyEngine, path: Path) -> None:
    """Reload rules from a single policy file into the engine."""
    from mcpkernel.policy.loader import load_policy_file

    try:
        rules = load_policy_file(path)
        # Remove old rules from this file, then add new ones
        for rule in rules:
            engine.remove_rule(rule.id)
        engine.add_rules(rules)
        logger.info(
            "policy rules reloaded",
            path=str(path),
            rule_count=len(rules),
        )
    except Exception:
        logger.warning("failed to reload policy file", path=str(path), exc_info=True)

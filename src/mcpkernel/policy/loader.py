"""Policy file loader — parse YAML policy definitions."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from mcpkernel.policy.engine import PolicyAction, PolicyRule
from mcpkernel.utils import ConfigError, get_logger

logger = get_logger(__name__)


def load_policy_file(path: str | Path) -> list[PolicyRule]:
    """Load policy rules from a YAML file.

    Expected format:
        rules:
          - id: RULE-001
            name: Block shell exec
            action: deny
            tool_patterns: ["shell_*", "exec_*"]
            ...
    """
    path = Path(path)
    if not path.exists():
        raise ConfigError(f"Policy file not found: {path}")

    with open(path) as f:
        data = yaml.safe_load(f)

    if not isinstance(data, dict) or "rules" not in data:
        raise ConfigError(f"Invalid policy file — missing 'rules' key: {path}")

    rules = []
    for raw in data["rules"]:
        rule = _parse_rule(raw, source=str(path))
        if rule:
            rules.append(rule)

    logger.info("policy file loaded", path=str(path), rules=len(rules))
    return rules


def load_policy_dir(directory: str | Path) -> list[PolicyRule]:
    """Load all .yaml/.yml policy files from a directory."""
    directory = Path(directory)
    if not directory.is_dir():
        raise ConfigError(f"Policy directory not found: {directory}")

    rules: list[PolicyRule] = []
    for p in sorted(directory.glob("*.y*ml")):
        if p.suffix in (".yaml", ".yml"):
            rules.extend(load_policy_file(p))

    logger.info("policy directory loaded", dir=str(directory), total_rules=len(rules))
    return rules


def _parse_rule(raw: dict[str, Any], source: str) -> PolicyRule | None:
    """Parse a single rule dict into a PolicyRule."""
    rule_id = raw.get("id")
    if not rule_id:
        logger.warning("skipping rule without id", source=source)
        return None

    action_str = raw.get("action", "deny")
    try:
        action = PolicyAction(action_str)
    except ValueError:
        logger.warning("unknown action, defaulting to deny", action=action_str, rule_id=rule_id)
        action = PolicyAction.DENY

    return PolicyRule(
        id=rule_id,
        name=raw.get("name", rule_id),
        description=raw.get("description", ""),
        action=action,
        priority=raw.get("priority", 100),
        tool_patterns=raw.get("tool_patterns", []),
        argument_patterns=raw.get("argument_patterns", {}),
        taint_labels=raw.get("taint_labels", []),
        owasp_asi_id=raw.get("owasp_asi_id", ""),
        conditions=raw.get("conditions", {}),
        enabled=raw.get("enabled", True),
    )

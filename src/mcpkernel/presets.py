"""Built-in policy presets for common security postures.

Each preset returns a list of :class:`PolicyRule` objects that can be
fed directly into a :class:`PolicyEngine`.

Usage::

    from mcpkernel.presets import get_preset_rules

    rules = get_preset_rules("strict")
"""

from __future__ import annotations

from mcpkernel.policy.engine import PolicyAction, PolicyRule

# ---------------------------------------------------------------------------
# Permissive - audit everything, block nothing
# ---------------------------------------------------------------------------
_PERMISSIVE_RULES: list[PolicyRule] = [
    PolicyRule(
        id="perm-audit-all",
        name="Audit all calls",
        description="Log every tool call for observability without blocking.",
        action=PolicyAction.AUDIT,
        priority=1000,
        tool_patterns=[".*"],
    ),
]

# ---------------------------------------------------------------------------
# Standard - block dangerous patterns, audit the rest
# ---------------------------------------------------------------------------
_STANDARD_RULES: list[PolicyRule] = [
    PolicyRule(
        id="std-block-exec",
        name="Block code execution",
        description="Deny tools that execute arbitrary code.",
        action=PolicyAction.DENY,
        priority=10,
        tool_patterns=["exec.*", "eval.*", "run_code.*", "execute.*", "shell.*"],
    ),
    PolicyRule(
        id="std-block-delete",
        name="Block destructive file ops",
        description="Deny file deletion tools.",
        action=PolicyAction.DENY,
        priority=20,
        tool_patterns=["delete.*", "remove.*", "rm_.*", "drop_.*"],
    ),
    PolicyRule(
        id="std-block-secrets",
        name="Block secret exfiltration",
        description="Deny calls with tainted secret arguments.",
        action=PolicyAction.DENY,
        priority=30,
        taint_labels=["SECRET", "API_KEY", "PASSWORD", "CREDENTIAL"],
    ),
    PolicyRule(
        id="std-sandbox-write",
        name="Sandbox write operations",
        description="Run filesystem write tools in a sandbox.",
        action=PolicyAction.SANDBOX,
        priority=50,
        tool_patterns=["write_file.*", "create_file.*", "save.*"],
    ),
    PolicyRule(
        id="std-audit-rest",
        name="Audit everything else",
        description="Audit remaining calls.",
        action=PolicyAction.AUDIT,
        priority=1000,
        tool_patterns=[".*"],
    ),
]

# ---------------------------------------------------------------------------
# Strict - deny by default, only allow explicitly safe patterns
# ---------------------------------------------------------------------------
_STRICT_RULES: list[PolicyRule] = [
    PolicyRule(
        id="strict-block-exec",
        name="Block all execution",
        description="Deny any code/shell execution.",
        action=PolicyAction.DENY,
        priority=10,
        tool_patterns=["exec.*", "eval.*", "run_code.*", "execute.*", "shell.*", "bash.*"],
    ),
    PolicyRule(
        id="strict-block-delete",
        name="Block destructive ops",
        action=PolicyAction.DENY,
        priority=10,
        tool_patterns=["delete.*", "remove.*", "rm_.*", "drop_.*", "truncate.*"],
    ),
    PolicyRule(
        id="strict-block-secrets",
        name="Block tainted data",
        action=PolicyAction.DENY,
        priority=10,
        taint_labels=["SECRET", "API_KEY", "PASSWORD", "CREDENTIAL", "PII"],
    ),
    PolicyRule(
        id="strict-block-network",
        name="Block network access",
        action=PolicyAction.DENY,
        priority=10,
        tool_patterns=["fetch.*", "http.*", "curl.*", "wget.*", "request.*"],
    ),
    PolicyRule(
        id="strict-sandbox-write",
        name="Sandbox all writes",
        action=PolicyAction.SANDBOX,
        priority=20,
        tool_patterns=["write.*", "create.*", "save.*", "update.*", "put.*"],
    ),
    PolicyRule(
        id="strict-allow-read",
        name="Allow reads with audit",
        action=PolicyAction.AUDIT,
        priority=50,
        tool_patterns=["read.*", "get.*", "list.*", "search.*", "find.*"],
    ),
]

# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------
_PRESETS: dict[str, list[PolicyRule]] = {
    "permissive": _PERMISSIVE_RULES,
    "standard": _STANDARD_RULES,
    "strict": _STRICT_RULES,
}


def get_preset_rules(name: str) -> list[PolicyRule]:
    """Return a copy of the rules for the named preset.

    Parameters
    ----------
    name:
        One of ``"permissive"``, ``"standard"``, ``"strict"``.

    Raises
    ------
    ValueError:
        If the preset name is unknown.
    """
    if name not in _PRESETS:
        if name == "owasp-asi-2026":
            msg = f"Preset '{name}' is file-based. Load it via policy_paths instead."
        else:
            available = ", ".join(sorted(_PRESETS))
            msg = f"Unknown preset '{name}'. Available: {available}"
        raise ValueError(msg)
    # Return copies so callers can't mutate the built-in sets
    return list(_PRESETS[name])


def list_presets() -> dict[str, str]:
    """Return a dict of ``{preset_name: description}``."""
    from mcpkernel.api import POLICY_PRESETS

    return {name: info["description"] for name, info in POLICY_PRESETS.items()}

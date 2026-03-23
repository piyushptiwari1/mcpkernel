"""Bridge agent manifest compliance config to MCPKernel policy rules.

Reads an ``AgentManifestDefinition`` and produces ``PolicyRule`` objects that
enforce the agent's declared compliance requirements at runtime.

Inspired by the open gitagent specification (MIT-licensed).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from mcpkernel.policy.engine import PolicyAction, PolicyRule
from mcpkernel.utils import get_logger

if TYPE_CHECKING:
    from mcpkernel.agent_manifest.loader import AgentManifestDefinition, ComplianceConfig

logger = get_logger(__name__)


def manifest_to_policy_rules(definition: AgentManifestDefinition) -> list[PolicyRule]:
    """Convert an agent manifest's compliance config into MCPKernel policy rules.

    Parameters
    ----------
    definition:
        The parsed agent manifest definition.

    Returns
    -------
    list[PolicyRule]
        MCPKernel policy rules derived from the compliance section.
    """
    rules: list[PolicyRule] = []
    compliance = definition.compliance

    if compliance is None:
        logger.info("no compliance section — generating permissive defaults", agent=definition.name)
        return _default_rules(definition)

    # -- Risk tier --
    rules.extend(_risk_tier_rules(compliance, definition.name))

    # -- Supervision --
    rules.extend(_supervision_rules(compliance, definition.name))

    # -- Data governance (PII / taint) --
    rules.extend(_data_governance_rules(compliance, definition.name))

    # -- Communications --
    rules.extend(_communications_rules(compliance, definition.name))

    # -- SOD enforcement --
    rules.extend(_sod_rules(compliance, definition.name))

    # -- Recordkeeping enforcement --
    rules.extend(_recordkeeping_rules(compliance, definition.name))

    # -- Model risk --
    rules.extend(_model_risk_rules(compliance, definition.name))

    # -- Vendor management (from dependencies) --
    rules.extend(_vendor_management_rules(definition))

    # -- Framework-specific checks --
    rules.extend(_framework_specific_rules(compliance, definition.name))

    # -- Tool allow-list from agent.yaml tools --
    rules.extend(_tool_allowlist_rules(definition))

    logger.info(
        "agent manifest policy bridge generated rules",
        agent=definition.name,
        rule_count=len(rules),
    )
    return rules


def _default_rules(definition: AgentManifestDefinition) -> list[PolicyRule]:
    """Generate minimal default rules when no compliance section exists."""
    rules = []
    if definition.tools_list:
        rules.append(
            PolicyRule(
                id=f"GA-{definition.name}-TOOLS",
                name=f"manifest:{definition.name} — tool allow-list",
                description="Only allow tools declared in agent.yaml",
                action=PolicyAction.ALLOW,
                priority=50,
                tool_patterns=definition.tools_list,
            )
        )
    return rules


def _risk_tier_rules(compliance: ComplianceConfig, agent_name: str) -> list[PolicyRule]:
    """Map risk_tier to enforcement strictness."""
    rules = []
    tier = compliance.risk_tier

    if tier in ("high", "critical"):
        rules.append(
            PolicyRule(
                id=f"GA-{agent_name}-RISK-AUDIT",
                name=f"manifest:{agent_name} — {tier} risk audit",
                description=f"Audit all tool calls for {tier}-risk agent",
                action=PolicyAction.AUDIT,
                priority=10,
                tool_patterns=[".*"],
            )
        )

    if tier == "critical":
        rules.append(
            PolicyRule(
                id=f"GA-{agent_name}-RISK-SANDBOX",
                name=f"manifest:{agent_name} — critical sandbox",
                description="Sandbox all tool calls for critical-risk agent",
                action=PolicyAction.SANDBOX,
                priority=5,
                tool_patterns=[".*"],
            )
        )

    return rules


def _supervision_rules(compliance: ComplianceConfig, agent_name: str) -> list[PolicyRule]:
    """Map HITL/kill-switch/escalation to policy rules."""
    rules = []
    supervision = compliance.supervision

    if not supervision:
        return rules

    hitl = supervision.get("human_in_the_loop", "none")
    if hitl == "always":
        rules.append(
            PolicyRule(
                id=f"GA-{agent_name}-HITL-ALWAYS",
                name=f"manifest:{agent_name} — HITL always",
                description="Human-in-the-loop required for every tool call",
                action=PolicyAction.WARN,
                priority=15,
                tool_patterns=[".*"],
                conditions={"hitl_required": True},
            )
        )

    for trigger in supervision.get("escalation_triggers", []):
        if "action_type" in trigger:
            action_type = trigger["action_type"]
            rules.append(
                PolicyRule(
                    id=f"GA-{agent_name}-ESCALATE-{action_type}",
                    name=f"manifest:{agent_name} — escalate {action_type}",
                    description=f"Escalation trigger: {action_type}",
                    action=PolicyAction.AUDIT,
                    priority=20,
                    tool_patterns=[f"*{action_type}*"],
                    conditions={"escalation_trigger": action_type},
                )
            )

    return rules


def _data_governance_rules(compliance: ComplianceConfig, agent_name: str) -> list[PolicyRule]:
    """Map PII handling / data classification to taint rules."""
    rules = []
    dg = compliance.data_governance

    if not dg:
        return rules

    pii_handling = dg.get("pii_handling", "allow")
    if pii_handling in ("redact", "encrypt", "prohibit"):
        taint_labels = ["pii", "secret"]
        action = PolicyAction.DENY if pii_handling == "prohibit" else PolicyAction.AUDIT

        rules.append(
            PolicyRule(
                id=f"GA-{agent_name}-PII-{pii_handling.upper()}",
                name=f"manifest:{agent_name} — PII {pii_handling}",
                description=f"PII handling policy: {pii_handling}",
                action=action,
                priority=25,
                tool_patterns=[".*"],
                taint_labels=taint_labels,
                conditions={"pii_handling": pii_handling},
            )
        )

    data_class = dg.get("data_classification", "public")
    if data_class in ("confidential", "restricted"):
        rules.append(
            PolicyRule(
                id=f"GA-{agent_name}-DATACLASS-{data_class.upper()}",
                name=f"manifest:{agent_name} — {data_class} data classification",
                description=f"Block tainted data for {data_class} classification",
                action=PolicyAction.DENY,
                priority=20,
                tool_patterns=[".*"],
                taint_labels=["untrusted_external"],
                conditions={"data_classification": data_class},
            )
        )

    return rules


def _communications_rules(compliance: ComplianceConfig, agent_name: str) -> list[PolicyRule]:
    """Map FINRA 2210 communications rules."""
    rules = []
    comms = compliance.communications

    if not comms:
        return rules

    if comms.get("pre_review_required"):
        rules.append(
            PolicyRule(
                id=f"GA-{agent_name}-COMMS-PREREVIEW",
                name=f"manifest:{agent_name} — communications pre-review",
                description="FINRA 2210: principal pre-review required for communications",
                action=PolicyAction.WARN,
                priority=30,
                tool_patterns=["*communicate*", "*message*", "*email*", "*send*"],
                owasp_asi_id="ASI-03",
                conditions={"pre_review_required": True},
            )
        )

    return rules


def _sod_rules(compliance: ComplianceConfig, agent_name: str) -> list[PolicyRule]:
    """Map segregation of duties conflicts to deny rules.

    Includes deep validation: duplicate role IDs, self-conflicts, handoff
    validation (requires ≥2 roles), and isolation recommendations for
    high/critical tiers.
    """
    rules = []
    sod = compliance.segregation_of_duties

    if not sod:
        return rules

    enforcement = sod.get("enforcement", "advisory")
    action = PolicyAction.DENY if enforcement == "strict" else PolicyAction.WARN

    # Deep SOD validation — detect duplicate role IDs
    roles = sod.get("roles", [])
    role_ids = [r.get("id", "") for r in roles if isinstance(r, dict)]
    seen_ids: set[str] = set()
    for rid in role_ids:
        if rid in seen_ids:
            rules.append(
                PolicyRule(
                    id=f"GA-{agent_name}-SOD-DUPLICATE-{rid}",
                    name=f"manifest:{agent_name} — SOD duplicate role {rid}",
                    description=f"Duplicate role ID '{rid}' in segregation_of_duties",
                    action=PolicyAction.DENY,
                    priority=5,
                    conditions={"sod_duplicate_role": rid},
                )
            )
        seen_ids.add(rid)

    # Generate a rule for each conflict pair
    for conflict_pair in sod.get("conflicts", []):
        if len(conflict_pair) == 2:
            role_a, role_b = conflict_pair

            # Detect self-conflicts
            if role_a == role_b:
                rules.append(
                    PolicyRule(
                        id=f"GA-{agent_name}-SOD-SELF-{role_a}",
                        name=f"manifest:{agent_name} — SOD self-conflict {role_a}",
                        description=f"Role '{role_a}' conflicts with itself",
                        action=PolicyAction.DENY,
                        priority=5,
                        conditions={"sod_self_conflict": role_a},
                    )
                )
                continue

            rules.append(
                PolicyRule(
                    id=f"GA-{agent_name}-SOD-{role_a}-{role_b}",
                    name=f"manifest:{agent_name} — SOD conflict {role_a}/{role_b}",
                    description=f"Segregation of duties: {role_a} and {role_b} cannot be same agent",
                    action=action,
                    priority=10,
                    conditions={
                        "sod_conflict": True,
                        "roles": [role_a, role_b],
                        "enforcement": enforcement,
                    },
                )
            )

    # Handoff validation — if handoffs declared, require ≥2 roles
    handoffs = sod.get("handoffs", [])
    if handoffs and len(role_ids) < 2:
        rules.append(
            PolicyRule(
                id=f"GA-{agent_name}-SOD-HANDOFF-INVALID",
                name=f"manifest:{agent_name} — SOD invalid handoff",
                description="Handoffs declared but fewer than 2 roles defined",
                action=PolicyAction.WARN,
                priority=10,
                conditions={"sod_handoff_invalid": True},
            )
        )

    return rules


def _recordkeeping_rules(compliance: ComplianceConfig, agent_name: str) -> list[PolicyRule]:
    """Generate rules from the recordkeeping configuration."""
    rules = []
    rk = compliance.recordkeeping

    if not rk:
        return rules

    if rk.get("audit_logging") and rk.get("immutable"):
        rules.append(
            PolicyRule(
                id=f"GA-{agent_name}-RK-IMMUTABLE",
                name=f"manifest:{agent_name} — immutable audit logging",
                description="All tool calls must produce immutable audit records",
                action=PolicyAction.AUDIT,
                priority=15,
                tool_patterns=[".*"],
                conditions={
                    "audit_logging": True,
                    "immutable": True,
                    "retention_period": rk.get("retention_period", ""),
                },
            )
        )

    return rules


def _model_risk_rules(compliance: ComplianceConfig, agent_name: str) -> list[PolicyRule]:
    """Generate rules from model_risk configuration."""
    rules = []
    mr = compliance.model_risk

    if not mr:
        return rules

    # Ongoing monitoring requirement (Federal Reserve SR 11-7)
    if mr.get("ongoing_monitoring"):
        rules.append(
            PolicyRule(
                id=f"GA-{agent_name}-MR-MONITORING",
                name=f"manifest:{agent_name} — model risk monitoring",
                description="Federal Reserve SR 11-7: ongoing model risk monitoring required",
                action=PolicyAction.AUDIT,
                priority=20,
                tool_patterns=[".*"],
                conditions={"model_risk_monitoring": True},
            )
        )

    # Validation cadence
    cadence = mr.get("validation_cadence", "")
    if cadence:
        rules.append(
            PolicyRule(
                id=f"GA-{agent_name}-MR-CADENCE",
                name=f"manifest:{agent_name} — model validation cadence",
                description=f"Model risk validation cadence: {cadence}",
                action=PolicyAction.AUDIT,
                priority=25,
                conditions={"validation_cadence": cadence},
            )
        )

    return rules


def _vendor_management_rules(definition: AgentManifestDefinition) -> list[PolicyRule]:
    """Generate rules from vendor_management in dependencies."""
    rules = []
    for dep in definition.dependencies:
        if not isinstance(dep, dict):
            continue
        vendor_mgmt = dep.get("vendor_management", {})
        if not vendor_mgmt:
            continue

        dep_name = dep.get("name", "unknown")

        # SR 23-4 compliance for third-party risk
        if vendor_mgmt.get("due_diligence_required"):
            rules.append(
                PolicyRule(
                    id=f"GA-{definition.name}-VENDOR-{dep_name}",
                    name=f"manifest:{definition.name} — vendor due diligence {dep_name}",
                    description=f"SR 23-4: vendor due diligence required for {dep_name}",
                    action=PolicyAction.AUDIT,
                    priority=20,
                    conditions={
                        "vendor_management": True,
                        "dependency": dep_name,
                        "due_diligence_required": True,
                    },
                )
            )

    return rules


def _framework_specific_rules(compliance: ComplianceConfig, agent_name: str) -> list[PolicyRule]:
    """Generate rules for specific regulatory frameworks (FINRA, SEC, Federal Reserve)."""
    rules = []
    frameworks = {f.lower() for f in compliance.frameworks}
    comms = compliance.communications

    # FINRA-specific: fair_balanced and no_misleading checks
    if "finra" in frameworks and comms:
        if not comms.get("fair_balanced"):
            rules.append(
                PolicyRule(
                    id=f"GA-{agent_name}-FINRA-FAIRBALANCED",
                    name=f"manifest:{agent_name} — FINRA fair_balanced missing",
                    description="FINRA 2210 requires fair_balanced flag in communications",
                    action=PolicyAction.WARN,
                    priority=30,
                    conditions={"framework_check": "finra_fair_balanced"},
                )
            )
        if comms.get("no_misleading") is None:
            rules.append(
                PolicyRule(
                    id=f"GA-{agent_name}-FINRA-NOMISLEADING",
                    name=f"manifest:{agent_name} — FINRA no_misleading missing",
                    description="FINRA 2210 requires no_misleading flag in communications",
                    action=PolicyAction.WARN,
                    priority=30,
                    conditions={"framework_check": "finra_no_misleading"},
                )
            )

    # SEC-specific: audit_logging required
    if "sec" in frameworks:
        rk = compliance.recordkeeping
        if not rk.get("audit_logging"):
            rules.append(
                PolicyRule(
                    id=f"GA-{agent_name}-SEC-AUDITLOG",
                    name=f"manifest:{agent_name} — SEC audit_logging required",
                    description="SEC compliance requires audit_logging in recordkeeping",
                    action=PolicyAction.WARN,
                    priority=25,
                    conditions={"framework_check": "sec_audit_logging"},
                )
            )

    # Federal Reserve: model_risk.ongoing_monitoring
    if "federal_reserve" in frameworks:
        mr = compliance.model_risk
        if not mr.get("ongoing_monitoring"):
            rules.append(
                PolicyRule(
                    id=f"GA-{agent_name}-FED-MONITORING",
                    name=f"manifest:{agent_name} — Federal Reserve monitoring required",
                    description="Federal Reserve SR 11-7 requires ongoing model risk monitoring",
                    action=PolicyAction.WARN,
                    priority=25,
                    conditions={"framework_check": "fed_reserve_monitoring"},
                )
            )

    return rules


def _tool_allowlist_rules(definition: AgentManifestDefinition) -> list[PolicyRule]:
    """If agent.yaml declares specific tools, restrict to only those."""
    if not definition.tools_list:
        return []

    patterns = []
    for tool_name in definition.tools_list:
        patterns.append(tool_name)
        patterns.append(tool_name.replace("-", "_"))

    return [
        PolicyRule(
            id=f"GA-{definition.name}-ALLOW-TOOLS",
            name=f"manifest:{definition.name} — declared tool allow-list",
            description="Only tools declared in agent.yaml are allowed",
            action=PolicyAction.ALLOW,
            priority=50,
            tool_patterns=patterns,
        )
    ]

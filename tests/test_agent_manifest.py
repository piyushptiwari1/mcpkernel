"""Tests for the agent_manifest integration module."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from mcpkernel.agent_manifest.loader import load_agent_manifest
from mcpkernel.agent_manifest.policy_bridge import manifest_to_policy_rules
from mcpkernel.agent_manifest.tool_validator import ToolSchemaValidator
from mcpkernel.policy.engine import PolicyAction

if TYPE_CHECKING:
    from pathlib import Path


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def minimal_manifest_dir(tmp_path: Path) -> Path:
    """Create a minimal agent manifest repo directory."""
    (tmp_path / "agent.yaml").write_text(
        "spec_version: '0.1.0'\nname: test-agent\nversion: 1.0.0\ndescription: A test agent\n"
    )
    (tmp_path / "SOUL.md").write_text("# Soul\n\nI am a test agent.\n")
    return tmp_path


@pytest.fixture()
def full_manifest_dir(tmp_path: Path) -> Path:
    """Create a full agent manifest repo with tools, compliance, hooks, skills."""
    (tmp_path / "agent.yaml").write_text(
        "spec_version: '0.1.0'\n"
        "name: compliance-agent\n"
        "version: 2.0.0\n"
        "description: A compliance analysis agent\n"
        "author: test-org\n"
        "license: Apache-2.0\n"
        "model:\n"
        "  preferred: claude-opus-4-6\n"
        "skills:\n"
        "  - regulatory-analysis\n"
        "  - document-review\n"
        "tools:\n"
        "  - search-regulations\n"
        "  - generate-report\n"
        "runtime:\n"
        "  max_turns: 50\n"
        "  timeout: 300\n"
        "tags:\n"
        "  - compliance\n"
        "  - finra\n"
        "agents:\n"
        "  - name: sub-reviewer\n"
        "    role: reviewer\n"
        "  - name: sub-checker\n"
        "    role: checker\n"
        "a2a:\n"
        "  url: https://example.com/a2a\n"
        "  capabilities: [review, analyze]\n"
        "dependencies:\n"
        "  - name: vendor-api\n"
        "    vendor_management:\n"
        "      due_diligence_required: true\n"
        "compliance:\n"
        "  risk_tier: high\n"
        "  frameworks:\n"
        "    - finra\n"
        "    - sec\n"
        "  supervision:\n"
        "    human_in_the_loop: always\n"
        "    kill_switch: true\n"
        "    escalation_triggers:\n"
        "      - action_type: trade_execution\n"
        "      - action_type: credit_decision\n"
        "  recordkeeping:\n"
        "    audit_logging: true\n"
        "    retention_period: 7y\n"
        "    immutable: true\n"
        "  model_risk:\n"
        "    ongoing_monitoring: true\n"
        "    validation_cadence: quarterly\n"
        "  data_governance:\n"
        "    pii_handling: redact\n"
        "    data_classification: confidential\n"
        "  communications:\n"
        "    pre_review_required: true\n"
        "    fair_balanced: true\n"
        "  segregation_of_duties:\n"
        "    roles:\n"
        "      - id: maker\n"
        "        permissions: [create, submit]\n"
        "      - id: checker\n"
        "        permissions: [review, approve]\n"
        "    conflicts:\n"
        "      - [maker, checker]\n"
        "    enforcement: strict\n"
    )
    # Create tools directory with schemas
    tools_dir = tmp_path / "tools"
    tools_dir.mkdir()
    (tools_dir / "search-regulations.yaml").write_text(
        "name: search-regulations\n"
        "description: Search regulatory databases\n"
        "version: 1.0.0\n"
        "input_schema:\n"
        "  type: object\n"
        "  properties:\n"
        "    query:\n"
        "      type: string\n"
        "      description: Search query\n"
        "    framework:\n"
        "      type: string\n"
        "      enum: [finra, sec, federal_reserve]\n"
        "  required: [query]\n"
        "annotations:\n"
        "  read_only: true\n"
        "  requires_confirmation: false\n"
    )
    (tools_dir / "generate-report.yaml").write_text(
        "name: generate-report\n"
        "description: Generate compliance report\n"
        "version: 1.0.0\n"
        "input_schema:\n"
        "  type: object\n"
        "  properties:\n"
        "    title:\n"
        "      type: string\n"
        "    findings:\n"
        "      type: array\n"
        "  required: [title, findings]\n"
        "annotations:\n"
        "  requires_confirmation: true\n"
    )
    # Create hooks directory
    hooks_dir = tmp_path / "hooks"
    hooks_dir.mkdir()
    (hooks_dir / "hooks.yaml").write_text(
        "hooks:\n"
        "  - event: pre_execution\n"
        "    script: hooks/validate.sh\n"
        "    timeout: 10\n"
        "  - event: post_execution\n"
        "    script: hooks/notify.sh\n"
    )
    # Create skills directory
    skills_dir = tmp_path / "skills"
    skills_dir.mkdir()
    (skills_dir / "regulatory-analysis").mkdir()
    (skills_dir / "regulatory-analysis" / "SKILL.md").write_text("# Regulatory Analysis\n")
    (skills_dir / "document-review").mkdir()
    return tmp_path


# ---------------------------------------------------------------------------
# Loader tests
# ---------------------------------------------------------------------------


class TestAgentManifestLoader:
    """Tests for agent manifest loader."""

    def test_load_minimal(self, minimal_manifest_dir: Path) -> None:
        defn = load_agent_manifest(minimal_manifest_dir)
        assert defn.name == "test-agent"
        assert defn.version == "1.0.0"
        assert defn.description == "A test agent"
        assert defn.compliance is None
        assert defn.tool_schemas == []

    def test_load_full(self, full_manifest_dir: Path) -> None:
        defn = load_agent_manifest(full_manifest_dir)
        assert defn.name == "compliance-agent"
        assert defn.version == "2.0.0"
        assert defn.author == "test-org"
        assert defn.skills == ["regulatory-analysis", "document-review"]
        assert defn.tools_list == ["search-regulations", "generate-report"]
        assert len(defn.tool_schemas) == 2
        assert defn.compliance is not None
        assert defn.compliance.risk_tier == "high"
        assert "finra" in defn.compliance.frameworks

    def test_load_missing_agent_yaml(self, tmp_path: Path) -> None:
        from mcpkernel.utils import ConfigError

        with pytest.raises(ConfigError, match=r"No agent\.yaml found"):
            load_agent_manifest(tmp_path)

    def test_load_missing_required_fields(self, tmp_path: Path) -> None:
        (tmp_path / "agent.yaml").write_text("name: incomplete\n")
        from mcpkernel.utils import ConfigError

        with pytest.raises(ConfigError, match="missing required fields"):
            load_agent_manifest(tmp_path)

    def test_load_invalid_yaml(self, tmp_path: Path) -> None:
        (tmp_path / "agent.yaml").write_text("[]")  # not a mapping
        from mcpkernel.utils import ConfigError

        with pytest.raises(ConfigError, match="must be a YAML mapping"):
            load_agent_manifest(tmp_path)

    def test_tool_schema_parsing(self, full_manifest_dir: Path) -> None:
        defn = load_agent_manifest(full_manifest_dir)
        search = next(s for s in defn.tool_schemas if s.name == "search-regulations")
        assert search.input_schema["type"] == "object"
        assert "query" in search.input_schema["properties"]
        assert search.annotations["read_only"] is True

    def test_no_tools_dir(self, minimal_manifest_dir: Path) -> None:
        defn = load_agent_manifest(minimal_manifest_dir)
        assert defn.tool_schemas == []

    def test_compliance_parsing(self, full_manifest_dir: Path) -> None:
        defn = load_agent_manifest(full_manifest_dir)
        c = defn.compliance
        assert c is not None
        assert c.supervision["human_in_the_loop"] == "always"
        assert c.supervision["kill_switch"] is True
        assert c.data_governance["pii_handling"] == "redact"
        assert c.segregation_of_duties["enforcement"] == "strict"

    def test_soul_md_loaded(self, minimal_manifest_dir: Path) -> None:
        defn = load_agent_manifest(minimal_manifest_dir)
        assert "I am a test agent" in defn.soul_md

    def test_rules_md_absent(self, minimal_manifest_dir: Path) -> None:
        defn = load_agent_manifest(minimal_manifest_dir)
        assert defn.rules_md == ""

    def test_rules_md_loaded(self, tmp_path: Path) -> None:
        (tmp_path / "agent.yaml").write_text("name: r-agent\nversion: 1.0.0\ndescription: Rules agent\n")
        (tmp_path / "RULES.md").write_text("# Rules\n\nNo secrets in logs.\n")
        defn = load_agent_manifest(tmp_path)
        assert "No secrets in logs" in defn.rules_md

    def test_hooks_loaded(self, full_manifest_dir: Path) -> None:
        defn = load_agent_manifest(full_manifest_dir)
        assert len(defn.hooks) == 2
        assert defn.hooks[0].event == "pre_execution"
        assert defn.hooks[0].timeout == 10
        assert defn.hooks[1].event == "post_execution"

    def test_skills_discovered(self, full_manifest_dir: Path) -> None:
        defn = load_agent_manifest(full_manifest_dir)
        assert len(defn.skill_infos) == 2
        names = {s.name for s in defn.skill_infos}
        assert "regulatory-analysis" in names
        assert "document-review" in names
        # Only regulatory-analysis has SKILL.md
        ra = next(s for s in defn.skill_infos if s.name == "regulatory-analysis")
        dr = next(s for s in defn.skill_infos if s.name == "document-review")
        assert ra.has_skill_md is True
        assert dr.has_skill_md is False

    def test_sub_agents_loaded(self, full_manifest_dir: Path) -> None:
        defn = load_agent_manifest(full_manifest_dir)
        assert len(defn.sub_agents) == 2
        assert defn.sub_agents[0].name == "sub-reviewer"
        assert defn.sub_agents[0].role == "reviewer"

    def test_a2a_metadata_loaded(self, full_manifest_dir: Path) -> None:
        defn = load_agent_manifest(full_manifest_dir)
        assert defn.a2a["url"] == "https://example.com/a2a"
        assert "review" in defn.a2a["capabilities"]

    def test_tags_loaded(self, full_manifest_dir: Path) -> None:
        defn = load_agent_manifest(full_manifest_dir)
        assert "compliance" in defn.tags
        assert "finra" in defn.tags

    def test_dependencies_loaded(self, full_manifest_dir: Path) -> None:
        defn = load_agent_manifest(full_manifest_dir)
        assert len(defn.dependencies) == 1
        assert defn.dependencies[0]["name"] == "vendor-api"

    def test_hooks_invalid_yaml(self, tmp_path: Path) -> None:
        (tmp_path / "agent.yaml").write_text("name: h-agent\nversion: 1.0.0\ndescription: Hooks agent\n")
        hooks_dir = tmp_path / "hooks"
        hooks_dir.mkdir()
        (hooks_dir / "hooks.yaml").write_text("[invalid")
        defn = load_agent_manifest(tmp_path)
        assert defn.hooks == []

    def test_sub_agents_string_format(self, tmp_path: Path) -> None:
        (tmp_path / "agent.yaml").write_text(
            "name: s-agent\nversion: 1.0.0\ndescription: Sub agent test\nagents:\n  - simple-agent\n  - another-agent\n"
        )
        defn = load_agent_manifest(tmp_path)
        assert len(defn.sub_agents) == 2
        assert defn.sub_agents[0].name == "simple-agent"


# ---------------------------------------------------------------------------
# Policy bridge tests
# ---------------------------------------------------------------------------


class TestPolicyBridge:
    """Tests for agent manifest → MCPKernel policy conversion."""

    def test_no_compliance_returns_minimal(self, minimal_manifest_dir: Path) -> None:
        defn = load_agent_manifest(minimal_manifest_dir)
        rules = manifest_to_policy_rules(defn)
        assert rules == []

    def test_high_risk_generates_audit(self, full_manifest_dir: Path) -> None:
        defn = load_agent_manifest(full_manifest_dir)
        rules = manifest_to_policy_rules(defn)
        audit_rules = [r for r in rules if "RISK-AUDIT" in r.id]
        assert len(audit_rules) == 1
        assert audit_rules[0].action == PolicyAction.AUDIT

    def test_hitl_always_generates_warn(self, full_manifest_dir: Path) -> None:
        defn = load_agent_manifest(full_manifest_dir)
        rules = manifest_to_policy_rules(defn)
        hitl_rules = [r for r in rules if "HITL" in r.id]
        assert len(hitl_rules) == 1
        assert hitl_rules[0].action == PolicyAction.WARN

    def test_escalation_triggers(self, full_manifest_dir: Path) -> None:
        defn = load_agent_manifest(full_manifest_dir)
        rules = manifest_to_policy_rules(defn)
        escalation_rules = [r for r in rules if "ESCALATE" in r.id]
        assert len(escalation_rules) == 2
        names = {r.id for r in escalation_rules}
        assert "GA-compliance-agent-ESCALATE-trade_execution" in names
        assert "GA-compliance-agent-ESCALATE-credit_decision" in names

    def test_pii_redact_generates_audit(self, full_manifest_dir: Path) -> None:
        defn = load_agent_manifest(full_manifest_dir)
        rules = manifest_to_policy_rules(defn)
        pii_rules = [r for r in rules if "PII" in r.id]
        assert len(pii_rules) == 1
        assert pii_rules[0].action == PolicyAction.AUDIT
        assert "pii" in pii_rules[0].taint_labels

    def test_confidential_data_classification(self, full_manifest_dir: Path) -> None:
        defn = load_agent_manifest(full_manifest_dir)
        rules = manifest_to_policy_rules(defn)
        dc_rules = [r for r in rules if "DATACLASS" in r.id]
        assert len(dc_rules) == 1
        assert dc_rules[0].action == PolicyAction.DENY

    def test_sod_strict_generates_deny(self, full_manifest_dir: Path) -> None:
        defn = load_agent_manifest(full_manifest_dir)
        rules = manifest_to_policy_rules(defn)
        sod_rules = [r for r in rules if r.id.startswith("GA-") and "SOD-maker" in r.id]
        assert len(sod_rules) == 1
        assert sod_rules[0].action == PolicyAction.DENY

    def test_communications_prereview(self, full_manifest_dir: Path) -> None:
        defn = load_agent_manifest(full_manifest_dir)
        rules = manifest_to_policy_rules(defn)
        comms_rules = [r for r in rules if "COMMS" in r.id]
        assert len(comms_rules) == 1
        assert comms_rules[0].owasp_asi_id == "ASI-03"

    def test_tool_allowlist(self, full_manifest_dir: Path) -> None:
        defn = load_agent_manifest(full_manifest_dir)
        rules = manifest_to_policy_rules(defn)
        allowlist = [r for r in rules if "ALLOW-TOOLS" in r.id]
        assert len(allowlist) == 1
        assert "search-regulations" in allowlist[0].tool_patterns
        assert "search_regulations" in allowlist[0].tool_patterns

    def test_critical_risk_generates_sandbox(self, tmp_path: Path) -> None:
        (tmp_path / "agent.yaml").write_text(
            "name: crit-agent\nversion: 1.0.0\ndescription: Critical agent\ncompliance:\n  risk_tier: critical\n"
        )
        defn = load_agent_manifest(tmp_path)
        rules = manifest_to_policy_rules(defn)
        sandbox_rules = [r for r in rules if "SANDBOX" in r.id]
        assert len(sandbox_rules) == 1
        assert sandbox_rules[0].action == PolicyAction.SANDBOX

    def test_full_definition_rule_count(self, full_manifest_dir: Path) -> None:
        defn = load_agent_manifest(full_manifest_dir)
        rules = manifest_to_policy_rules(defn)
        # More rules now with recordkeeping, model_risk, vendor, framework-specific
        assert len(rules) >= 10

    def test_recordkeeping_immutable(self, full_manifest_dir: Path) -> None:
        defn = load_agent_manifest(full_manifest_dir)
        rules = manifest_to_policy_rules(defn)
        rk_rules = [r for r in rules if "RK-IMMUTABLE" in r.id]
        assert len(rk_rules) == 1
        assert rk_rules[0].action == PolicyAction.AUDIT

    def test_model_risk_monitoring(self, full_manifest_dir: Path) -> None:
        defn = load_agent_manifest(full_manifest_dir)
        rules = manifest_to_policy_rules(defn)
        mr_rules = [r for r in rules if "MR-MONITORING" in r.id]
        assert len(mr_rules) == 1
        assert mr_rules[0].action == PolicyAction.AUDIT

    def test_model_risk_cadence(self, full_manifest_dir: Path) -> None:
        defn = load_agent_manifest(full_manifest_dir)
        rules = manifest_to_policy_rules(defn)
        cadence_rules = [r for r in rules if "MR-CADENCE" in r.id]
        assert len(cadence_rules) == 1
        assert cadence_rules[0].conditions["validation_cadence"] == "quarterly"

    def test_vendor_management(self, full_manifest_dir: Path) -> None:
        defn = load_agent_manifest(full_manifest_dir)
        rules = manifest_to_policy_rules(defn)
        vendor_rules = [r for r in rules if "VENDOR" in r.id]
        assert len(vendor_rules) == 1
        assert vendor_rules[0].conditions["dependency"] == "vendor-api"

    def test_framework_finra_no_misleading(self, tmp_path: Path) -> None:
        (tmp_path / "agent.yaml").write_text(
            "name: finra-agent\nversion: 1.0.0\ndescription: FINRA agent\n"
            "compliance:\n"
            "  frameworks: [finra]\n"
            "  communications:\n"
            "    pre_review_required: true\n"
        )
        defn = load_agent_manifest(tmp_path)
        rules = manifest_to_policy_rules(defn)
        nm_rules = [r for r in rules if "NOMISLEADING" in r.id]
        assert len(nm_rules) == 1
        assert nm_rules[0].action == PolicyAction.WARN

    def test_framework_sec_audit_logging(self, tmp_path: Path) -> None:
        (tmp_path / "agent.yaml").write_text(
            "name: sec-agent\nversion: 1.0.0\ndescription: SEC agent\ncompliance:\n  frameworks: [sec]\n"
        )
        defn = load_agent_manifest(tmp_path)
        rules = manifest_to_policy_rules(defn)
        sec_rules = [r for r in rules if "SEC-AUDITLOG" in r.id]
        assert len(sec_rules) == 1

    def test_framework_federal_reserve(self, tmp_path: Path) -> None:
        (tmp_path / "agent.yaml").write_text(
            "name: fed-agent\nversion: 1.0.0\ndescription: Fed agent\ncompliance:\n  frameworks: [federal_reserve]\n"
        )
        defn = load_agent_manifest(tmp_path)
        rules = manifest_to_policy_rules(defn)
        fed_rules = [r for r in rules if "FED-MONITORING" in r.id]
        assert len(fed_rules) == 1

    def test_sod_duplicate_role(self, tmp_path: Path) -> None:
        (tmp_path / "agent.yaml").write_text(
            "name: dup-agent\nversion: 1.0.0\ndescription: Dup agent\n"
            "compliance:\n"
            "  segregation_of_duties:\n"
            "    roles:\n"
            "      - id: maker\n"
            "        permissions: [create]\n"
            "      - id: maker\n"
            "        permissions: [submit]\n"
            "    conflicts: []\n"
            "    enforcement: strict\n"
        )
        defn = load_agent_manifest(tmp_path)
        rules = manifest_to_policy_rules(defn)
        dup_rules = [r for r in rules if "SOD-DUPLICATE" in r.id]
        assert len(dup_rules) == 1
        assert dup_rules[0].action == PolicyAction.DENY

    def test_sod_self_conflict(self, tmp_path: Path) -> None:
        (tmp_path / "agent.yaml").write_text(
            "name: self-agent\nversion: 1.0.0\ndescription: Self conflict agent\n"
            "compliance:\n"
            "  segregation_of_duties:\n"
            "    roles:\n"
            "      - id: admin\n"
            "        permissions: [all]\n"
            "    conflicts:\n"
            "      - [admin, admin]\n"
            "    enforcement: strict\n"
        )
        defn = load_agent_manifest(tmp_path)
        rules = manifest_to_policy_rules(defn)
        self_rules = [r for r in rules if "SOD-SELF" in r.id]
        assert len(self_rules) == 1
        assert self_rules[0].action == PolicyAction.DENY

    def test_sod_handoff_invalid(self, tmp_path: Path) -> None:
        (tmp_path / "agent.yaml").write_text(
            "name: ho-agent\nversion: 1.0.0\ndescription: Handoff agent\n"
            "compliance:\n"
            "  segregation_of_duties:\n"
            "    roles:\n"
            "      - id: solo\n"
            "        permissions: [all]\n"
            "    handoffs:\n"
            "      - from: solo\n"
            "        to: nobody\n"
            "    conflicts: []\n"
            "    enforcement: advisory\n"
        )
        defn = load_agent_manifest(tmp_path)
        rules = manifest_to_policy_rules(defn)
        ho_rules = [r for r in rules if "HANDOFF-INVALID" in r.id]
        assert len(ho_rules) == 1
        assert ho_rules[0].action == PolicyAction.WARN


# ---------------------------------------------------------------------------
# Tool validator tests
# ---------------------------------------------------------------------------


class TestToolSchemaValidator:
    """Tests for tool schema validation."""

    def test_valid_call(self, full_manifest_dir: Path) -> None:
        defn = load_agent_manifest(full_manifest_dir)
        v = ToolSchemaValidator(defn)
        errors = v.validate("search-regulations", {"query": "FINRA Rule 3110"})
        assert errors == []

    def test_missing_required_field(self, full_manifest_dir: Path) -> None:
        defn = load_agent_manifest(full_manifest_dir)
        v = ToolSchemaValidator(defn)
        errors = v.validate("search-regulations", {})
        assert any("Missing required field: query" in e for e in errors)

    def test_wrong_type(self, full_manifest_dir: Path) -> None:
        defn = load_agent_manifest(full_manifest_dir)
        v = ToolSchemaValidator(defn)
        errors = v.validate("search-regulations", {"query": 123})
        assert any("expected string" in e for e in errors)

    def test_enum_violation(self, full_manifest_dir: Path) -> None:
        defn = load_agent_manifest(full_manifest_dir)
        v = ToolSchemaValidator(defn)
        errors = v.validate("search-regulations", {"query": "test", "framework": "invalid"})
        assert any("not in allowed values" in e for e in errors)

    def test_enum_valid(self, full_manifest_dir: Path) -> None:
        defn = load_agent_manifest(full_manifest_dir)
        v = ToolSchemaValidator(defn)
        errors = v.validate("search-regulations", {"query": "test", "framework": "finra"})
        assert errors == []

    def test_unknown_tool(self, full_manifest_dir: Path) -> None:
        defn = load_agent_manifest(full_manifest_dir)
        v = ToolSchemaValidator(defn)
        errors = v.validate("unknown-tool", {})
        assert any("not declared" in e for e in errors)

    def test_is_read_only(self, full_manifest_dir: Path) -> None:
        defn = load_agent_manifest(full_manifest_dir)
        v = ToolSchemaValidator(defn)
        assert v.is_read_only("search-regulations") is True
        assert v.is_read_only("generate-report") is False

    def test_requires_confirmation(self, full_manifest_dir: Path) -> None:
        defn = load_agent_manifest(full_manifest_dir)
        v = ToolSchemaValidator(defn)
        assert v.requires_confirmation("generate-report") is True
        assert v.requires_confirmation("search-regulations") is False

    def test_known_tools(self, full_manifest_dir: Path) -> None:
        defn = load_agent_manifest(full_manifest_dir)
        v = ToolSchemaValidator(defn)
        assert set(v.known_tools) == {"search-regulations", "generate-report"}

    def test_snake_case_lookup(self, full_manifest_dir: Path) -> None:
        defn = load_agent_manifest(full_manifest_dir)
        v = ToolSchemaValidator(defn)
        assert v.has_schema("search_regulations") is True

    def test_generate_report_validation(self, full_manifest_dir: Path) -> None:
        defn = load_agent_manifest(full_manifest_dir)
        v = ToolSchemaValidator(defn)
        errors = v.validate("generate-report", {"title": "Q1 Report", "findings": []})
        assert errors == []

    def test_generate_report_missing_fields(self, full_manifest_dir: Path) -> None:
        defn = load_agent_manifest(full_manifest_dir)
        v = ToolSchemaValidator(defn)
        errors = v.validate("generate-report", {})
        assert len(errors) == 2  # missing title and findings


# ---------------------------------------------------------------------------
# Hook tests
# ---------------------------------------------------------------------------


class TestAgentManifestHook:
    """Tests for the agent manifest proxy hook."""

    @pytest.mark.asyncio
    async def test_allows_declared_tool(self, full_manifest_dir: Path) -> None:
        from mcpkernel.agent_manifest.hooks import AgentManifestHook
        from mcpkernel.proxy.interceptor import InterceptorContext, MCPToolCall

        defn = load_agent_manifest(full_manifest_dir)
        hook = AgentManifestHook(defn)

        ctx = InterceptorContext(
            call=MCPToolCall(
                request_id=1,
                tool_name="search-regulations",
                arguments={"query": "FINRA 3110"},
                raw_jsonrpc={},
            )
        )
        await hook.pre_execution(ctx)
        assert not ctx.aborted
        assert ctx.extra.get("manifest_agent") == "compliance-agent"

    @pytest.mark.asyncio
    async def test_blocks_undeclared_tool(self, full_manifest_dir: Path) -> None:
        from mcpkernel.agent_manifest.hooks import AgentManifestHook
        from mcpkernel.proxy.interceptor import InterceptorContext, MCPToolCall

        defn = load_agent_manifest(full_manifest_dir)
        hook = AgentManifestHook(defn)

        ctx = InterceptorContext(
            call=MCPToolCall(
                request_id=2,
                tool_name="delete-everything",
                arguments={},
                raw_jsonrpc={},
            )
        )
        await hook.pre_execution(ctx)
        assert ctx.aborted
        assert "not declared" in ctx.abort_reason

    @pytest.mark.asyncio
    async def test_blocks_invalid_args(self, full_manifest_dir: Path) -> None:
        from mcpkernel.agent_manifest.hooks import AgentManifestHook
        from mcpkernel.proxy.interceptor import InterceptorContext, MCPToolCall

        defn = load_agent_manifest(full_manifest_dir)
        hook = AgentManifestHook(defn)

        ctx = InterceptorContext(
            call=MCPToolCall(
                request_id=3,
                tool_name="search-regulations",
                arguments={},
                raw_jsonrpc={},
            )
        )
        await hook.pre_execution(ctx)
        assert ctx.aborted
        assert "schema validation failed" in ctx.abort_reason

    @pytest.mark.asyncio
    async def test_allows_tool_with_no_allowlist(self, minimal_manifest_dir: Path) -> None:
        from mcpkernel.agent_manifest.hooks import AgentManifestHook
        from mcpkernel.proxy.interceptor import InterceptorContext, MCPToolCall

        defn = load_agent_manifest(minimal_manifest_dir)
        hook = AgentManifestHook(defn)

        ctx = InterceptorContext(
            call=MCPToolCall(
                request_id=4,
                tool_name="any-tool",
                arguments={"data": "test"},
                raw_jsonrpc={},
            )
        )
        await hook.pre_execution(ctx)
        assert not ctx.aborted

    @pytest.mark.asyncio
    async def test_sets_confirmation_metadata(self, full_manifest_dir: Path) -> None:
        from mcpkernel.agent_manifest.hooks import AgentManifestHook
        from mcpkernel.proxy.interceptor import InterceptorContext, MCPToolCall

        defn = load_agent_manifest(full_manifest_dir)
        hook = AgentManifestHook(defn)

        ctx = InterceptorContext(
            call=MCPToolCall(
                request_id=5,
                tool_name="generate-report",
                arguments={"title": "Q1", "findings": []},
                raw_jsonrpc={},
            )
        )
        await hook.pre_execution(ctx)
        assert not ctx.aborted
        assert ctx.extra.get("manifest_requires_confirmation") is True

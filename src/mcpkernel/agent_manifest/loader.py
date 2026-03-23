"""Load and parse agent manifest definitions from a repository directory.

Reads ``agent.yaml``, optional ``SOUL.md``/``RULES.md``, tool schemas from
``tools/*.yaml``, hooks from ``hooks/hooks.yaml``, skills directories, and the
compliance section to produce a structured ``AgentManifestDefinition``.

Inspired by the open gitagent specification (MIT-licensed).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from mcpkernel.utils import ConfigError, get_logger

logger = get_logger(__name__)


@dataclass
class ToolSchema:
    """Parsed tool definition from ``tools/<name>.yaml``."""

    name: str
    description: str = ""
    version: str = ""
    input_schema: dict[str, Any] = field(default_factory=dict)
    output_schema: dict[str, Any] = field(default_factory=dict)
    annotations: dict[str, Any] = field(default_factory=dict)


@dataclass
class ComplianceConfig:
    """Parsed ``compliance`` section of ``agent.yaml``."""

    risk_tier: str = "low"
    frameworks: list[str] = field(default_factory=list)
    supervision: dict[str, Any] = field(default_factory=dict)
    recordkeeping: dict[str, Any] = field(default_factory=dict)
    model_risk: dict[str, Any] = field(default_factory=dict)
    data_governance: dict[str, Any] = field(default_factory=dict)
    communications: dict[str, Any] = field(default_factory=dict)
    segregation_of_duties: dict[str, Any] = field(default_factory=dict)


@dataclass
class HookDefinition:
    """Parsed hook entry from ``hooks/hooks.yaml``."""

    event: str
    script: str
    timeout: int = 30


@dataclass
class SkillInfo:
    """Minimal info about a discovered skill directory."""

    name: str
    path: Path
    has_skill_md: bool = False


@dataclass
class SubAgentRef:
    """Reference to a sub-agent declared in ``agents`` section."""

    name: str
    role: str = ""
    config: dict[str, Any] = field(default_factory=dict)


@dataclass
class AgentManifestDefinition:
    """Complete parsed agent manifest definition."""

    name: str
    version: str
    description: str = ""
    spec_version: str = ""
    author: str = ""
    license: str = ""
    model: dict[str, Any] = field(default_factory=dict)
    skills: list[str] = field(default_factory=list)
    tools_list: list[str] = field(default_factory=list)
    tool_schemas: list[ToolSchema] = field(default_factory=list)
    runtime: dict[str, Any] = field(default_factory=dict)
    compliance: ComplianceConfig | None = None

    # Extended fields
    soul_md: str = ""
    rules_md: str = ""
    hooks: list[HookDefinition] = field(default_factory=list)
    skill_infos: list[SkillInfo] = field(default_factory=list)
    sub_agents: list[SubAgentRef] = field(default_factory=list)
    a2a: dict[str, Any] = field(default_factory=dict)
    dependencies: list[dict[str, Any]] = field(default_factory=list)
    delegation: dict[str, Any] = field(default_factory=dict)
    tags: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    raw: dict[str, Any] = field(default_factory=dict)
    repo_path: Path | None = None


def load_agent_manifest(repo_path: str | Path) -> AgentManifestDefinition:
    """Load an agent manifest definition from a repository directory.

    Parameters
    ----------
    repo_path:
        Path to the root of a repository containing ``agent.yaml``.

    Returns
    -------
    AgentManifestDefinition
        The parsed agent definition with all resolved metadata.

    Raises
    ------
    ConfigError
        If ``agent.yaml`` is missing or invalid.
    """
    repo_path = Path(repo_path)
    manifest_path = repo_path / "agent.yaml"

    if not manifest_path.exists():
        raise ConfigError(f"No agent.yaml found in {repo_path}")

    with open(manifest_path) as f:
        raw = yaml.safe_load(f)

    if not isinstance(raw, dict):
        raise ConfigError(f"agent.yaml must be a YAML mapping: {manifest_path}")

    # Required fields
    name = raw.get("name")
    version = raw.get("version")
    description = raw.get("description")
    if not name or not version or not description:
        raise ConfigError("agent.yaml missing required fields: name, version, description")

    # Parse compliance section
    compliance = None
    if "compliance" in raw:
        compliance = _parse_compliance(raw["compliance"])

    # Load tool schemas from tools/*.yaml
    tool_schemas = _load_tool_schemas(repo_path / "tools")

    # Load optional markdown files
    soul_md = _load_markdown(repo_path / "SOUL.md")
    rules_md = _load_markdown(repo_path / "RULES.md")

    # Load hooks
    hooks = _load_hooks(repo_path / "hooks" / "hooks.yaml")

    # Discover skills
    skill_infos = _discover_skills(repo_path / "skills")

    # Parse sub-agents
    sub_agents = _parse_sub_agents(raw.get("agents", []))

    definition = AgentManifestDefinition(
        name=name,
        version=version,
        description=description,
        spec_version=raw.get("spec_version", ""),
        author=raw.get("author", ""),
        license=raw.get("license", ""),
        model=raw.get("model", {}),
        skills=raw.get("skills", []),
        tools_list=raw.get("tools", []),
        tool_schemas=tool_schemas,
        runtime=raw.get("runtime", {}),
        compliance=compliance,
        soul_md=soul_md,
        rules_md=rules_md,
        hooks=hooks,
        skill_infos=skill_infos,
        sub_agents=sub_agents,
        a2a=raw.get("a2a", {}),
        dependencies=raw.get("dependencies", []),
        delegation=raw.get("delegation", {}),
        tags=raw.get("tags", []),
        metadata=raw.get("metadata", {}),
        raw=raw,
        repo_path=repo_path,
    )

    logger.info(
        "agent manifest loaded",
        agent=name,
        version=version,
        tools=len(tool_schemas),
        hooks=len(hooks),
        skills=len(skill_infos),
        sub_agents=len(sub_agents),
        has_compliance=compliance is not None,
        has_soul=bool(soul_md),
    )
    return definition


def _parse_compliance(data: dict[str, Any]) -> ComplianceConfig:
    """Parse the compliance section into a structured config."""
    return ComplianceConfig(
        risk_tier=data.get("risk_tier", "low"),
        frameworks=data.get("frameworks", []),
        supervision=data.get("supervision", {}),
        recordkeeping=data.get("recordkeeping", {}),
        model_risk=data.get("model_risk", {}),
        data_governance=data.get("data_governance", {}),
        communications=data.get("communications", {}),
        segregation_of_duties=data.get("segregation_of_duties", {}),
    )


def _load_tool_schemas(tools_dir: Path) -> list[ToolSchema]:
    """Load all tool YAML definitions from the tools/ directory."""
    if not tools_dir.is_dir():
        return []

    schemas: list[ToolSchema] = []
    for p in sorted(tools_dir.glob("*.y*ml")):
        if p.suffix not in (".yaml", ".yml"):
            continue
        try:
            with open(p) as f:
                raw = yaml.safe_load(f)
            if not isinstance(raw, dict):
                logger.warning("skipping non-mapping tool file", path=str(p))
                continue
            schema = ToolSchema(
                name=raw.get("name", p.stem),
                description=raw.get("description", ""),
                version=raw.get("version", ""),
                input_schema=raw.get("input_schema", {}),
                output_schema=raw.get("output_schema", {}),
                annotations=raw.get("annotations", {}),
            )
            schemas.append(schema)
        except yaml.YAMLError:
            logger.warning("failed to parse tool schema", path=str(p))

    return schemas


def _load_markdown(path: Path) -> str:
    """Load a markdown file, returning empty string if absent."""
    if not path.is_file():
        return ""
    return path.read_text(encoding="utf-8").strip()


def _load_hooks(hooks_path: Path) -> list[HookDefinition]:
    """Load hooks from ``hooks/hooks.yaml``."""
    if not hooks_path.is_file():
        return []

    try:
        with open(hooks_path) as f:
            raw = yaml.safe_load(f)
    except yaml.YAMLError:
        logger.warning("failed to parse hooks.yaml", path=str(hooks_path))
        return []

    if not isinstance(raw, dict):
        return []

    hooks: list[HookDefinition] = []
    for entry in raw.get("hooks", []):
        if not isinstance(entry, dict):
            continue
        event = entry.get("event", "")
        script = entry.get("script", "")
        if event and script:
            hooks.append(
                HookDefinition(
                    event=event,
                    script=script,
                    timeout=entry.get("timeout", 30),
                )
            )
    return hooks


def _discover_skills(skills_dir: Path) -> list[SkillInfo]:
    """Discover skill directories under ``skills/``."""
    if not skills_dir.is_dir():
        return []

    infos: list[SkillInfo] = []
    for child in sorted(skills_dir.iterdir()):
        if child.is_dir():
            infos.append(
                SkillInfo(
                    name=child.name,
                    path=child,
                    has_skill_md=(child / "SKILL.md").is_file(),
                )
            )
    return infos


def _parse_sub_agents(agents_data: list[Any]) -> list[SubAgentRef]:
    """Parse the ``agents`` section into sub-agent references."""
    refs: list[SubAgentRef] = []
    if not isinstance(agents_data, list):
        return refs

    for entry in agents_data:
        if isinstance(entry, dict) and "name" in entry:
            refs.append(
                SubAgentRef(
                    name=entry["name"],
                    role=entry.get("role", ""),
                    config={k: v for k, v in entry.items() if k not in ("name", "role")},
                )
            )
        elif isinstance(entry, str):
            refs.append(SubAgentRef(name=entry))
    return refs

"""OpenClaw / ClawHub SKILL.md security scanner.

Parses SKILL.md files (YAML frontmatter + Markdown body) used by
OpenClaw's skill system and scans them for security issues:

- Dangerous shell commands (rm -rf, curl|bash, etc.)
- Exfiltration patterns (uploading secrets, phoning home)
- File system access beyond workspace
- Metadata mismatches (declared vs actual env vars, binaries)
- Hidden instructions embedded in skill prompts

Reference: https://github.com/openclaw/clawhub/blob/main/docs/skill-format.md
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from mcpkernel.utils import get_logger

logger = get_logger(__name__)

# Dangerous shell patterns to flag in skill content
_DANGEROUS_SHELL_PATTERNS: list[tuple[str, str, str]] = [
    # (pattern, title, severity)
    (r"rm\s+(?:-[a-zA-Z]*r[a-zA-Z]*f|--force|--recursive)\s", "Recursive force delete", "critical"),
    (r"curl\s+[^|]*\|\s*(?:bash|sh|zsh)", "Pipe remote script to shell", "critical"),
    (r"wget\s+[^|]*\|\s*(?:bash|sh|zsh)", "Pipe remote script to shell", "critical"),
    (r"eval\s*\(", "Dynamic eval execution", "high"),
    (r"exec\s*\(", "Dynamic exec execution", "high"),
    (r"os\.system\s*\(", "Shell command via os.system", "high"),
    (r"subprocess\.(?:call|run|Popen)\s*\([^)]*shell\s*=\s*True", "Subprocess with shell=True", "high"),
    (r"chmod\s+(?:777|a\+[rwx])", "Overly permissive file permissions", "medium"),
    (r"(?:ssh|scp|rsync)\s+.*@", "Remote access command", "medium"),
    (r"(?:nc|ncat|netcat)\s+", "Netcat network tool", "high"),
    (r"dd\s+if=.*of=", "Direct disk write", "medium"),
]

# Exfiltration patterns
_EXFIL_PATTERNS: list[tuple[str, str, str]] = [
    (r"curl\s+.*-d\s+.*(?:\$|`)", "Data exfiltration via curl POST", "critical"),
    (r"(?:https?://)[^\s]*(?:webhook|exfil|ngrok|requestbin|pipedream)", "Exfiltration endpoint", "critical"),
    (r"base64\s+(?:-e|--encode).*\|.*curl", "Base64 encode + exfiltrate", "critical"),
    (r"cat\s+.*(?:\.env|\.ssh|\.aws|\.gnupg|credentials|token|secret|password)", "Sensitive file access", "high"),
    (r"(?:OPENAI_API_KEY|ANTHROPIC_API_KEY|AWS_SECRET|GITHUB_TOKEN)\b", "Hardcoded API key reference", "medium"),
]

# File system overreach patterns
_FS_OVERREACH: list[tuple[str, str, str]] = [
    (r"(?:~|/home|/Users|/root)/", "Home directory access", "medium"),
    (r"/etc/(?:passwd|shadow|ssh|ssl)", "System config file access", "high"),
    (r"(?:\.\./){2,}", "Deep parent traversal", "high"),
    (r"/(?:proc|sys|dev)/", "System pseudo-filesystem access", "high"),
]

# Hidden instruction patterns in skill body
_HIDDEN_INSTRUCTIONS: list[tuple[str, str, str]] = [
    (r"(?:ignore|forget|disregard)\s+(?:all\s+)?(?:previous|prior|above)", "Override instructions", "critical"),
    (r"you\s+(?:must|should|are required)\s+(?:always|never)", "Behavioral directive", "high"),
    (r"do\s+not\s+(?:tell|reveal|mention|show)\s+(?:the\s+)?user", "Concealment instruction", "critical"),
    (r"(?:silently|secretly|quietly)\s+(?:send|upload|transmit|forward)", "Stealth operation", "critical"),
    (
        r"before\s+(?:responding|answering|replying).*(?:first|always)\s+(?:call|execute|run)",
        "Pre-response hook",
        "high",
    ),
]


def _parse_skill_md(content: str) -> tuple[dict[str, Any], str]:
    """Parse a SKILL.md file into (frontmatter_dict, body_markdown).

    The YAML frontmatter is delimited by ``---`` lines at the start of the file.
    """
    frontmatter: dict[str, Any] = {}
    body = content

    if content.startswith("---"):
        parts = content.split("---", 2)
        if len(parts) >= 3:
            import yaml

            try:
                frontmatter = yaml.safe_load(parts[1]) or {}
            except Exception:
                frontmatter = {"_parse_error": "Invalid YAML frontmatter"}
            body = parts[2]

    return frontmatter, body


def _scan_patterns(
    text: str,
    patterns: list[tuple[str, str, str]],
    category: str,
) -> list[dict[str, Any]]:
    """Scan text against a list of regex patterns."""
    findings = []
    for pattern, title, severity in patterns:
        for match in re.finditer(pattern, text, re.IGNORECASE):
            findings.append(
                {
                    "severity": severity,
                    "category": category,
                    "title": title,
                    "detail": f"Matched: '{match.group()[:80]}'",
                    "line": text[: match.start()].count("\n") + 1,
                }
            )
    return findings


def _check_metadata(frontmatter: dict[str, Any], body: str) -> list[dict[str, Any]]:
    """Check for metadata mismatches and suspicious declarations."""
    findings = []

    # Get metadata (support openclaw, clawdbot, and clawdis aliases)
    metadata = (
        frontmatter.get("metadata", {}).get("openclaw")
        or frontmatter.get("metadata", {}).get("clawdbot")
        or frontmatter.get("metadata", {}).get("clawdis")
        or {}
    )

    # Check for undeclared env vars actually used in the body
    requires = metadata.get("requires", {})
    declared_env = set(requires.get("env", []))
    declared_bins = set(requires.get("bins", []))

    # Find env var references in body
    env_refs = set(re.findall(r"\$\{?([A-Z_][A-Z0-9_]*)\}?", body))
    undeclared = env_refs - declared_env - {"HOME", "PATH", "USER", "PWD", "SHELL", "TERM"}
    if undeclared:
        findings.append(
            {
                "severity": "medium",
                "category": "metadata-mismatch",
                "title": "Undeclared environment variables used",
                "detail": f"Used but not declared in metadata.requires.env: {', '.join(sorted(undeclared))}",
            }
        )

    # Check for suspicious binaries
    suspicious_bins = {"nc", "ncat", "netcat", "nmap", "socat", "telnet", "msfconsole"}
    bad_bins = declared_bins & suspicious_bins
    if bad_bins:
        findings.append(
            {
                "severity": "high",
                "category": "suspicious-dependency",
                "title": "Suspicious binary dependencies declared",
                "detail": f"Declares network/security tool binaries: {', '.join(sorted(bad_bins))}",
            }
        )

    # Missing description
    if not frontmatter.get("description"):
        findings.append(
            {
                "severity": "low",
                "category": "metadata-quality",
                "title": "Missing skill description",
                "detail": "Skills should declare a description in frontmatter",
            }
        )

    return findings


async def scan_skill_file(skill_path: str | Path) -> list[dict[str, Any]]:
    """Scan an OpenClaw SKILL.md file for security issues.

    Parameters
    ----------
    skill_path:
        Path to the SKILL.md file.

    Returns
    -------
    List of finding dicts, each with: severity, category, title, detail.
    """
    path = Path(skill_path)
    if not path.exists():
        return [{"severity": "error", "category": "file", "title": "File not found", "detail": str(path)}]

    content = path.read_text(encoding="utf-8", errors="replace")
    frontmatter, body = _parse_skill_md(content)

    findings: list[dict[str, Any]] = []

    # Check for parse errors
    if "_parse_error" in frontmatter:
        findings.append(
            {
                "severity": "medium",
                "category": "parse-error",
                "title": "YAML frontmatter parse error",
                "detail": frontmatter["_parse_error"],
            }
        )

    # Scan body for dangerous patterns
    findings.extend(_scan_patterns(body, _DANGEROUS_SHELL_PATTERNS, "dangerous-command"))
    findings.extend(_scan_patterns(body, _EXFIL_PATTERNS, "exfiltration"))
    findings.extend(_scan_patterns(body, _FS_OVERREACH, "filesystem-overreach"))
    findings.extend(_scan_patterns(body, _HIDDEN_INSTRUCTIONS, "hidden-instruction"))

    # Also scan frontmatter text (some attacks hide in metadata values)
    fm_text = str(frontmatter)
    findings.extend(_scan_patterns(fm_text, _EXFIL_PATTERNS, "exfiltration-metadata"))
    findings.extend(_scan_patterns(fm_text, _HIDDEN_INSTRUCTIONS, "hidden-instruction-metadata"))

    # Check metadata integrity
    findings.extend(_check_metadata(frontmatter, body))

    # Sort by severity
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "error": 0}
    findings.sort(key=lambda f: severity_order.get(f["severity"], 5))

    logger.info(
        "skill_scan_complete",
        path=str(path),
        findings=len(findings),
        critical=sum(1 for f in findings if f["severity"] == "critical"),
    )

    return findings


async def scan_skill_directory(directory: str | Path) -> dict[str, list[dict[str, Any]]]:
    """Scan all SKILL.md files in a directory tree.

    Returns a dict mapping skill path -> list of findings.
    """
    directory = Path(directory)
    results: dict[str, list[dict[str, Any]]] = {}

    for skill_file in directory.rglob("SKILL.md"):
        findings = await scan_skill_file(skill_file)
        if findings:
            results[str(skill_file)] = findings

    return results

"""SARIF (Static Analysis Results Interchange Format) output.

Generates SARIF v2.1.0 JSON reports compatible with:
- GitHub Code Scanning (Security tab)
- Azure DevOps
- VS Code SARIF Viewer
- Any SARIF-compliant CI/CD tool
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from mcpkernel.utils import get_logger

logger = get_logger(__name__)

_SARIF_VERSION = "2.1.0"
_SARIF_SCHEMA = "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json"


@dataclass
class SARIFResult:
    """A single SARIF result (finding)."""

    rule_id: str
    level: str  # "error" | "warning" | "note"
    message: str
    file_path: str = ""
    start_line: int = 1
    start_column: int = 1
    end_line: int | None = None
    end_column: int | None = None
    snippet: str = ""
    help_text: str = ""
    help_uri: str = ""


def _severity_to_sarif_level(severity: str) -> str:
    """Map MCPKernel severity to SARIF level."""
    mapping = {
        "critical": "error",
        "high": "error",
        "medium": "warning",
        "low": "note",
        "info": "note",
    }
    return mapping.get(severity.lower(), "warning")


def generate_sarif(
    results: list[SARIFResult],
    tool_name: str = "mcpkernel",
    tool_version: str = "0.1.3",
    *,
    rules: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Generate a complete SARIF v2.1.0 JSON document.

    Parameters
    ----------
    results:
        List of findings to include.
    tool_name:
        Name of the reporting tool.
    tool_version:
        Version of the reporting tool.
    rules:
        Optional pre-defined rule descriptors.
    """
    # Auto-generate rules from results if not provided
    rule_map: dict[str, dict[str, Any]] = {}
    if rules:
        for r in rules:
            rule_map[r["id"]] = r
    else:
        for res in results:
            if res.rule_id not in rule_map:
                rule_map[res.rule_id] = {
                    "id": res.rule_id,
                    "name": res.rule_id.replace("-", " ").title(),
                    "shortDescription": {"text": res.message[:200]},
                    "helpUri": res.help_uri or f"https://github.com/piyushptiwari1/mcpkernel/docs/rules/{res.rule_id}",
                    "defaultConfiguration": {"level": _severity_to_sarif_level(res.level)},
                }
                if res.help_text:
                    rule_map[res.rule_id]["fullDescription"] = {"text": res.help_text}

    sarif_results: list[dict[str, Any]] = []
    for res in results:
        result_obj: dict[str, Any] = {
            "ruleId": res.rule_id,
            "level": res.level if res.level in ("error", "warning", "note") else _severity_to_sarif_level(res.level),
            "message": {"text": res.message},
        }

        # Add location if file path is provided
        if res.file_path:
            region: dict[str, Any] = {
                "startLine": res.start_line,
                "startColumn": res.start_column,
            }
            if res.end_line:
                region["endLine"] = res.end_line
            if res.end_column:
                region["endColumn"] = res.end_column
            if res.snippet:
                region["snippet"] = {"text": res.snippet}

            result_obj["locations"] = [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": res.file_path},
                        "region": region,
                    }
                }
            ]

        sarif_results.append(result_obj)

    sarif_doc: dict[str, Any] = {
        "$schema": _SARIF_SCHEMA,
        "version": _SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": tool_name,
                        "version": tool_version,
                        "informationUri": "https://github.com/piyushptiwari1/mcpkernel",
                        "rules": list(rule_map.values()),
                    }
                },
                "results": sarif_results,
            }
        ],
    }

    return sarif_doc


def write_sarif(sarif: dict[str, Any], output_path: str) -> None:
    """Write SARIF document to a file."""
    with open(output_path, "w", encoding="utf-8") as fh:
        json.dump(sarif, fh, indent=2, ensure_ascii=False)
    logger.info("sarif_written", path=output_path, result_count=len(sarif.get("runs", [{}])[0].get("results", [])))


def poisoning_findings_to_sarif(
    findings: list[Any],
    config_path: str = "",
) -> list[SARIFResult]:
    """Convert poisoning scan findings to SARIF results."""
    results: list[SARIFResult] = []
    for f in findings:
        results.append(
            SARIFResult(
                rule_id=f.rule_id,
                level=_severity_to_sarif_level(f.severity.value if hasattr(f.severity, "value") else str(f.severity)),
                message=f"{f.title}: {f.description}",
                file_path=config_path,
                snippet=f.matched_text if hasattr(f, "matched_text") else "",
                help_text=f.remediation if hasattr(f, "remediation") else "",
            )
        )
    return results


def dlp_violations_to_sarif(violations: list[Any]) -> list[SARIFResult]:
    """Convert DLP chain violations to SARIF results."""
    results: list[SARIFResult] = []
    for v in violations:
        results.append(
            SARIFResult(
                rule_id=v.rule.rule_id,
                level=_severity_to_sarif_level(v.rule.severity.value),
                message=f"{v.rule.name}: {' → '.join(v.chain)}",
                help_text=v.rule.description,
            )
        )
    return results


def taint_findings_to_sarif(
    findings: list[Any],
    file_path: str = "",
) -> list[SARIFResult]:
    """Convert taint scan findings to SARIF results."""
    results: list[SARIFResult] = []
    for i, f in enumerate(findings):
        line = getattr(f, "line", 1)
        results.append(
            SARIFResult(
                rule_id=f"TAINT-{i + 1:03d}",
                level="warning",
                message=str(f),
                file_path=file_path,
                start_line=line if isinstance(line, int) else 1,
            )
        )
    return results

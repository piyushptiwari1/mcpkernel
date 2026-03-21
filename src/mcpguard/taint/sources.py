"""Taint source detection — identify sensitive data in tool call inputs."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from mcpguard.taint.tracker import TaintLabel
from mcpguard.utils import get_logger

logger = get_logger(__name__)


@dataclass
class SourcePattern:
    """A pattern that identifies tainted data at a source boundary."""

    name: str
    label: TaintLabel
    pattern: re.Pattern[str]
    description: str = ""


# Built-in source patterns
_BUILTIN_PATTERNS: list[SourcePattern] = [
    # Secrets
    SourcePattern(
        name="aws_key",
        label=TaintLabel.SECRET,
        pattern=re.compile(r"(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}", re.IGNORECASE),
        description="AWS Access Key ID",
    ),
    SourcePattern(
        name="generic_api_key",
        label=TaintLabel.SECRET,
        pattern=re.compile(r"(?:api[_-]?key|apikey|secret[_-]?key|access[_-]?token)\s*[:=]\s*['\"]?([a-zA-Z0-9_\-]{20,})", re.IGNORECASE),
        description="Generic API key assignment",
    ),
    SourcePattern(
        name="jwt_token",
        label=TaintLabel.SECRET,
        pattern=re.compile(r"eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}"),
        description="JWT token",
    ),
    SourcePattern(
        name="private_key",
        label=TaintLabel.SECRET,
        pattern=re.compile(r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----"),
        description="PEM private key header",
    ),
    SourcePattern(
        name="github_token",
        label=TaintLabel.SECRET,
        pattern=re.compile(r"gh[pousr]_[a-zA-Z0-9]{36,}"),
        description="GitHub personal access token",
    ),
    # PII
    SourcePattern(
        name="email",
        label=TaintLabel.PII,
        pattern=re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"),
        description="Email address",
    ),
    SourcePattern(
        name="ssn",
        label=TaintLabel.PII,
        pattern=re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
        description="US Social Security Number",
    ),
    SourcePattern(
        name="credit_card",
        label=TaintLabel.PII,
        pattern=re.compile(r"\b(?:4\d{3}|5[1-5]\d{2}|6011|3[47]\d{2})[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b"),
        description="Credit card number",
    ),
    SourcePattern(
        name="phone_us",
        label=TaintLabel.PII,
        pattern=re.compile(r"\b(?:\+1[- ]?)?\(?\d{3}\)?[- ]?\d{3}[- ]?\d{4}\b"),
        description="US phone number",
    ),
]


@dataclass
class SourceDetection:
    """A detected taint source in tool call data."""

    pattern_name: str
    label: TaintLabel
    matched_text: str
    field_path: str
    description: str


def detect_tainted_sources(
    data: dict[str, Any],
    *,
    custom_patterns: list[SourcePattern] | None = None,
    field_prefix: str = "",
) -> list[SourceDetection]:
    """Scan a dict (typically tool call arguments) for tainted sources.

    Returns a list of detections with matched text and location.
    """
    patterns = _BUILTIN_PATTERNS + (custom_patterns or [])
    detections: list[SourceDetection] = []

    def _scan(obj: Any, path: str) -> None:
        if isinstance(obj, str):
            for pat in patterns:
                match = pat.pattern.search(obj)
                if match:
                    detections.append(
                        SourceDetection(
                            pattern_name=pat.name,
                            label=pat.label,
                            matched_text=match.group(0)[:20] + "...",  # Truncate for safety
                            field_path=path,
                            description=pat.description,
                        )
                    )
        elif isinstance(obj, dict):
            for k, v in obj.items():
                _scan(v, f"{path}.{k}" if path else k)
        elif isinstance(obj, list):
            for i, item in enumerate(obj):
                _scan(item, f"{path}[{i}]")

    _scan(data, field_prefix)

    if detections:
        logger.info(
            "taint sources detected",
            count=len(detections),
            labels=[d.label.value for d in detections],
        )
    return detections

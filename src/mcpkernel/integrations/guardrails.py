"""Guardrails AI integration — enhanced PII/secret/toxicity validation.

Plugs into MCPKernel's taint detection pipeline to provide higher-accuracy
validation using Guardrails AI's community-maintained validators.

When ``guardrails`` is installed, this module augments the built-in regex
patterns with Guardrails validators for PII detection, toxic content
filtering, and secret scanning.

Usage::

    validator = GuardrailsValidator()
    if validator.available:
        detections = await validator.validate(text)
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Any

from mcpkernel.taint.tracker import TaintLabel
from mcpkernel.utils import get_logger

logger = get_logger(__name__)


@dataclass
class GuardrailsConfig:
    """Configuration for Guardrails AI integration."""

    enabled: bool = False
    pii_validator: bool = True
    toxic_content: bool = False
    secrets_validator: bool = True
    on_fail: str = "noop"  # noop = detect only, exception = block


@dataclass
class GuardrailsDetection:
    """A detection result from Guardrails AI validators."""

    validator_name: str
    label: TaintLabel
    entity_type: str
    matched_text: str
    confidence: float
    field_path: str


class GuardrailsValidator:
    """Wrapper for Guardrails AI validators with graceful fallback.

    If the ``guardrails-ai`` package is not installed, ``available`` returns
    ``False`` and validation calls return empty lists.
    """

    def __init__(self, config: GuardrailsConfig | None = None) -> None:
        self._config = config or GuardrailsConfig()
        self._guard: Any = None
        self._available = False
        self._init_attempted = False

    @property
    def available(self) -> bool:
        """Return True if guardrails-ai is installed and usable."""
        if not self._init_attempted:
            self._try_init()
        return self._available

    def _try_init(self) -> None:
        """Attempt to import guardrails and initialize validators."""
        self._init_attempted = True
        if not self._config.enabled:
            return

        try:
            import guardrails as gd  # noqa: F401

            self._available = True
            logger.info("guardrails-ai integration available")
        except ImportError:
            logger.debug("guardrails-ai not installed — using built-in patterns only")
            self._available = False

    async def validate_text(
        self,
        text: str,
        *,
        field_path: str = "",
    ) -> list[GuardrailsDetection]:
        """Run Guardrails validators on the given text.

        Returns a list of detections found by the validators.
        This is a fallback-safe operation — if guardrails is not
        installed, returns an empty list.
        """
        if not self.available:
            return []

        detections: list[GuardrailsDetection] = []

        if self._config.pii_validator:
            detections.extend(await self._detect_pii(text, field_path))

        if self._config.secrets_validator:
            detections.extend(await self._detect_secrets(text, field_path))

        if self._config.toxic_content:
            detections.extend(await self._detect_toxic(text, field_path))

        return detections

    async def validate_dict(
        self,
        data: dict[str, Any],
        *,
        field_prefix: str = "",
    ) -> list[GuardrailsDetection]:
        """Recursively validate all string fields in a dict."""
        detections: list[GuardrailsDetection] = []
        await self._scan_obj(data, field_prefix, detections)
        return detections

    async def _scan_obj(
        self,
        obj: Any,
        path: str,
        detections: list[GuardrailsDetection],
    ) -> None:
        """Recursive scanner for dict/list/string values."""
        if isinstance(obj, str) and len(obj) > 3:
            results = await self.validate_text(obj, field_path=path)
            detections.extend(results)
        elif isinstance(obj, dict):
            for k, v in obj.items():
                await self._scan_obj(v, f"{path}.{k}" if path else k, detections)
        elif isinstance(obj, list):
            for i, item in enumerate(obj):
                await self._scan_obj(item, f"{path}[{i}]", detections)

    # ------------------------------------------------------------------
    # Validator implementations
    # ------------------------------------------------------------------
    async def _detect_pii(
        self,
        text: str,
        field_path: str,
    ) -> list[GuardrailsDetection]:
        """Detect PII entities using Guardrails AI DetectPII validator."""
        detections: list[GuardrailsDetection] = []
        try:
            from guardrails.hub import DetectPII

            validator = DetectPII(
                pii_entities=[
                    "EMAIL_ADDRESS",
                    "PHONE_NUMBER",
                    "CREDIT_CARD",
                    "US_SSN",
                    "PERSON",
                    "LOCATION",
                    "IP_ADDRESS",
                    "IBAN_CODE",
                    "MEDICAL_LICENSE",
                ],
                on_fail=self._config.on_fail,
            )
            result = await asyncio.to_thread(validator.validate, text, {})

            if hasattr(result, "validation_passed") and not result.validation_passed:
                for entity in getattr(result, "detected_entities", []):
                    detections.append(
                        GuardrailsDetection(
                            validator_name="DetectPII",
                            label=TaintLabel.PII,
                            entity_type=entity.get("entity_type", "UNKNOWN"),
                            matched_text=str(entity.get("text", ""))[:20] + "...",
                            confidence=entity.get("score", 0.0),
                            field_path=field_path,
                        )
                    )

        except ImportError:
            logger.debug("DetectPII validator not installed — run: guardrails hub install hub://guardrails/detect_pii")
        except Exception as exc:
            logger.warning("guardrails PII detection failed", error=str(exc))

        return detections

    async def _detect_secrets(
        self,
        text: str,
        field_path: str,
    ) -> list[GuardrailsDetection]:
        """Detect secrets using Guardrails AI SecretsPresent validator."""
        detections: list[GuardrailsDetection] = []
        try:
            from guardrails.hub import SecretsPresent

            validator = SecretsPresent(on_fail=self._config.on_fail)
            result = await asyncio.to_thread(validator.validate, text, {})

            if hasattr(result, "validation_passed") and not result.validation_passed:
                detections.append(
                    GuardrailsDetection(
                        validator_name="SecretsPresent",
                        label=TaintLabel.SECRET,
                        entity_type="SECRET",
                        matched_text="[redacted]",
                        confidence=1.0,
                        field_path=field_path,
                    )
                )

        except ImportError:
            logger.debug(
                "SecretsPresent validator not installed — run: guardrails hub install hub://guardrails/secrets_present"
            )
        except Exception as exc:
            logger.warning("guardrails secrets detection failed", error=str(exc))

        return detections

    async def _detect_toxic(
        self,
        text: str,
        field_path: str,
    ) -> list[GuardrailsDetection]:
        """Detect toxic content using Guardrails AI ToxicLanguage validator."""
        detections: list[GuardrailsDetection] = []
        try:
            from guardrails.hub import ToxicLanguage

            validator = ToxicLanguage(on_fail=self._config.on_fail)
            result = await asyncio.to_thread(validator.validate, text, {})

            if hasattr(result, "validation_passed") and not result.validation_passed:
                detections.append(
                    GuardrailsDetection(
                        validator_name="ToxicLanguage",
                        label=TaintLabel.UNTRUSTED_EXTERNAL,
                        entity_type="TOXIC_CONTENT",
                        matched_text=text[:20] + "...",
                        confidence=0.9,
                        field_path=field_path,
                    )
                )

        except ImportError:
            logger.debug(
                "ToxicLanguage validator not installed — run: guardrails hub install hub://guardrails/toxic_language"
            )
        except Exception as exc:
            logger.warning("guardrails toxic content detection failed", error=str(exc))

        return detections

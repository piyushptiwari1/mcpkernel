"""Context reducer — TF-IDF-based semantic pruning of tool call context."""

from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass
from typing import Any

from mcpkernel.utils import get_logger

logger = get_logger(__name__)


@dataclass
class ReductionResult:
    """Result of context reduction."""

    original_tokens: int
    reduced_tokens: int
    reduction_ratio: float
    preserved_fields: list[str]
    pruned_fields: list[str]
    reduced_content: dict[str, Any]


class ContextReducer:
    """Reduce tool-call context to minimize tokens while keeping relevance.

    Uses TF-IDF scoring to rank fields by semantic importance relative
    to the tool name and recent conversation context.
    """

    def __init__(
        self,
        max_tokens: int = 4096,
        relevance_threshold: float = 0.1,
    ) -> None:
        self._max_tokens = max_tokens
        self._threshold = relevance_threshold
        self._idf_cache: dict[str, float] = {}
        self._document_count = 0

    def reduce(
        self,
        context: dict[str, Any],
        *,
        query_terms: list[str] | None = None,
    ) -> ReductionResult:
        """Reduce context dict to fit within token budget.

        Args:
            context: The full context dict to reduce.
            query_terms: Optional terms to bias relevance towards.
        """
        original_tokens = _estimate_tokens(context)
        if original_tokens <= self._max_tokens:
            return ReductionResult(
                original_tokens=original_tokens,
                reduced_tokens=original_tokens,
                reduction_ratio=0.0,
                preserved_fields=list(context.keys()),
                pruned_fields=[],
                reduced_content=context,
            )

        # Score each top-level field by relevance
        scored = []
        for key, value in context.items():
            text = _extract_text(value)
            score = _tfidf_score(text, query_terms or [])
            scored.append((key, value, score))

        scored.sort(key=lambda x: x[2], reverse=True)

        # Greedily include fields until budget is met
        reduced: dict[str, Any] = {}
        token_budget = self._max_tokens
        preserved = []
        pruned = []

        for key, value, score in scored:
            field_tokens = _estimate_tokens({key: value})
            if field_tokens <= token_budget and score >= self._threshold:
                reduced[key] = value
                token_budget -= field_tokens
                preserved.append(key)
            else:
                pruned.append(key)

        reduced_tokens = _estimate_tokens(reduced)
        logger.info(
            "context reduced",
            original_tokens=original_tokens,
            reduced_tokens=reduced_tokens,
            preserved=len(preserved),
            pruned=len(pruned),
        )
        return ReductionResult(
            original_tokens=original_tokens,
            reduced_tokens=reduced_tokens,
            reduction_ratio=1.0 - (reduced_tokens / max(original_tokens, 1)),
            preserved_fields=preserved,
            pruned_fields=pruned,
            reduced_content=reduced,
        )


def _estimate_tokens(obj: Any) -> int:
    """Rough token count — ~4 chars per token."""
    text = str(obj)
    return max(1, len(text) // 4)


def _extract_text(obj: Any) -> str:
    """Flatten an object to text for TF-IDF scoring."""
    if isinstance(obj, str):
        return obj
    return str(obj)


def _tfidf_score(text: str, query_terms: list[str]) -> float:
    """Simple TF-IDF relevance score against query terms."""
    if not query_terms or not text:
        return 0.5  # Neutral score when no query

    words = re.findall(r"\w+", text.lower())
    if not words:
        return 0.0

    tf = Counter(words)
    total = len(words)
    score = 0.0
    for term in query_terms:
        term_lower = term.lower()
        term_tf = tf.get(term_lower, 0) / total
        # Simple IDF approximation (assume 100 docs, term in 10)
        idf = math.log(10.0 / (1.0 + min(tf.get(term_lower, 0), 9)))
        score += term_tf * idf

    return score / len(query_terms)

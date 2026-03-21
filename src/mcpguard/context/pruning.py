"""Pruning strategies for context minimization."""

from __future__ import annotations

from enum import Enum
from typing import Any

from mcpguard.context.reducer import ContextReducer, ReductionResult
from mcpguard.utils import get_logger

logger = get_logger(__name__)


class PruningStrategy(str, Enum):
    """Aggressiveness level for context pruning."""

    AGGRESSIVE = "aggressive"
    MODERATE = "moderate"
    CONSERVATIVE = "conservative"


_STRATEGY_CONFIG: dict[PruningStrategy, dict[str, Any]] = {
    PruningStrategy.AGGRESSIVE: {"max_tokens": 1024, "relevance_threshold": 0.3},
    PruningStrategy.MODERATE: {"max_tokens": 4096, "relevance_threshold": 0.1},
    PruningStrategy.CONSERVATIVE: {"max_tokens": 16384, "relevance_threshold": 0.01},
}


def prune_context(
    context: dict[str, Any],
    *,
    strategy: PruningStrategy = PruningStrategy.MODERATE,
    query_terms: list[str] | None = None,
    max_tokens: int | None = None,
) -> ReductionResult:
    """Prune context using the specified strategy.

    Args:
        context: Full context to prune.
        strategy: Pruning aggressiveness level.
        query_terms: Terms to bias relevance scoring.
        max_tokens: Override the strategy's token budget.
    """
    config = _STRATEGY_CONFIG[strategy]
    budget = max_tokens or config["max_tokens"]
    threshold = config["relevance_threshold"]

    reducer = ContextReducer(max_tokens=budget, relevance_threshold=threshold)
    result = reducer.reduce(context, query_terms=query_terms)

    logger.info(
        "context pruned",
        strategy=strategy.value,
        ratio=f"{result.reduction_ratio:.1%}",
    )
    return result

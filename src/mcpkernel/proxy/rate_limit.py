"""Token-bucket rate limiter with in-memory and optional Redis backends."""

from __future__ import annotations

import time
from dataclasses import dataclass

from mcpkernel.utils import get_logger

logger = get_logger(__name__)


@dataclass
class RateLimitResult:
    """Outcome of a rate limit check."""

    allowed: bool
    remaining: int
    limit: int
    retry_after: float = 0.0


@dataclass
class _Bucket:
    tokens: float
    last_refill: float


class InMemoryRateLimiter:
    """Per-key token-bucket rate limiter backed by a dict.

    Thread-safety is not required — the proxy is async single-threaded per
    worker (uvicorn/asyncio).
    """

    MAX_BUCKETS = 100_000  # Cap to prevent unbounded memory growth

    def __init__(self, *, requests_per_minute: int = 60, burst_size: int = 10) -> None:
        self._rate = requests_per_minute / 60.0  # tokens per second
        self._burst = burst_size
        self._buckets: dict[str, _Bucket] = {}

    def _evict_oldest(self) -> None:
        """Evict the least-recently-used bucket when at capacity."""
        if len(self._buckets) < self.MAX_BUCKETS:
            return
        oldest_key = min(self._buckets, key=lambda k: self._buckets[k].last_refill)
        del self._buckets[oldest_key]
        logger.debug("rate_limiter evicted bucket", key=oldest_key)

    def _get_bucket(self, key: str) -> _Bucket:
        now = time.monotonic()
        bucket = self._buckets.get(key)
        if bucket is None:
            self._evict_oldest()
            bucket = _Bucket(tokens=float(self._burst), last_refill=now)
            self._buckets[key] = bucket
            return bucket
        # Refill tokens since last check
        elapsed = now - bucket.last_refill
        bucket.tokens = min(float(self._burst), bucket.tokens + elapsed * self._rate)
        bucket.last_refill = now
        return bucket

    def check(self, key: str) -> RateLimitResult:
        """Consume one token for *key*; return the verdict."""
        bucket = self._get_bucket(key)
        if bucket.tokens >= 1.0:
            bucket.tokens -= 1.0
            return RateLimitResult(
                allowed=True,
                remaining=int(bucket.tokens),
                limit=self._burst,
            )
        retry_after = (1.0 - bucket.tokens) / self._rate if self._rate > 0 else 60.0
        return RateLimitResult(
            allowed=False,
            remaining=0,
            limit=self._burst,
            retry_after=retry_after,
        )

    def reset(self, key: str) -> None:
        """Reset the bucket for *key*."""
        self._buckets.pop(key, None)

"""Micro-benchmark: taint-tracking overhead per tool call.

Run:

    python benchmarks/taint_overhead.py
    python benchmarks/taint_overhead.py --iterations 50000 --json

Compares three configurations against a no-op baseline:

  * baseline        — dict round-trip, no taint code at all
  * detect_only     — `detect_tainted_sources()` invoked on the args
  * full            — detect + `TaintTracker.mark()` for each finding

The script prints a small table (ops/sec, mean µs, p50/p95/p99) and exits
0. When invoked with ``--json`` it emits a single JSON object on stdout
for CI consumption.

The numbers reported by this benchmark are *not* a service-level
guarantee; they exist to detect regressions when changing taint
internals.  See ``docs/security/overview.md`` for production sizing.
"""

from __future__ import annotations

import argparse
import json
import logging
import statistics
import sys
import time
from typing import Any

import structlog

# Silence MCPKernel's structured logger so it never interleaves with
# stdout output (especially `--json`).
structlog.configure(
    wrapper_class=structlog.make_filtering_bound_logger(logging.CRITICAL),
    cache_logger_on_first_use=True,
)

from mcpkernel.taint.sources import detect_tainted_sources  # noqa: E402
from mcpkernel.taint.tracker import TaintTracker  # noqa: E402

# A representative MCP tool-call payload: medium nesting, mix of clean
# and tainted strings (one fake AWS key, one fake email, one JWT-ish).
_PAYLOAD: dict[str, Any] = {
    "tool": "fs.write",
    "arguments": {
        "path": "/tmp/out.log",  # noqa: S108 — benchmark fixture, never written
        "content": "user said: hello world; trace=AKIAIOSFODNN7EXAMPLE",
        "metadata": {
            "user": "alice@example.com",
            "session": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.abc",
            "tags": ["benign", "another benign string", "lorem ipsum"],
        },
    },
}


def _measure(fn, iterations: int) -> dict[str, float]:
    samples: list[float] = []
    # Warm-up
    for _ in range(min(1000, iterations // 10 or 1)):
        fn()
    start = time.perf_counter()
    for _ in range(iterations):
        t0 = time.perf_counter_ns()
        fn()
        samples.append(time.perf_counter_ns() - t0)
    elapsed = time.perf_counter() - start
    samples.sort()
    return {
        "iterations": iterations,
        "elapsed_s": elapsed,
        "ops_per_s": iterations / elapsed,
        "mean_us": statistics.fmean(samples) / 1000.0,
        "p50_us": samples[len(samples) // 2] / 1000.0,
        "p95_us": samples[int(len(samples) * 0.95)] / 1000.0,
        "p99_us": samples[int(len(samples) * 0.99)] / 1000.0,
    }


def _baseline() -> None:
    # Mimic the no-op of just passing args through.
    _ = dict(_PAYLOAD["arguments"])


def _detect_only() -> None:
    detect_tainted_sources(_PAYLOAD["arguments"])


def _full() -> None:
    tracker = TaintTracker()
    detections = detect_tainted_sources(_PAYLOAD["arguments"])
    for det in detections:
        tracker.mark(det.matched_text, det.label, source_id=det.field_path)


_SCENARIOS = {
    "baseline": _baseline,
    "detect_only": _detect_only,
    "full": _full,
}


def run(iterations: int) -> dict[str, dict[str, float]]:
    return {name: _measure(fn, iterations) for name, fn in _SCENARIOS.items()}


def _print_table(results: dict[str, dict[str, float]]) -> None:
    base = results["baseline"]["mean_us"]
    print(f"{'scenario':<14} {'ops/s':>10} {'mean us':>10} {'p50':>8} {'p95':>8} {'p99':>8} {'xbase':>7}")  # noqa: T201
    print("-" * 70)  # noqa: T201
    for name, r in results.items():
        overhead = r["mean_us"] / base if base > 0 else 0.0
        print(  # noqa: T201
            f"{name:<14} {r['ops_per_s']:>10.0f} {r['mean_us']:>10.2f} "
            f"{r['p50_us']:>8.2f} {r['p95_us']:>8.2f} {r['p99_us']:>8.2f} "
            f"{overhead:>7.2f}"
        )


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--iterations", type=int, default=20000)
    p.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    args = p.parse_args(argv)

    results = run(args.iterations)
    if args.json:
        json.dump(results, sys.stdout, indent=2)
        sys.stdout.write("\n")
    else:
        _print_table(results)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

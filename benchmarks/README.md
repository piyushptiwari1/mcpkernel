# Benchmarks

Micro-benchmarks that guard against performance regressions in
MCPKernel hot paths. These are **not** load tests.

## Available

| Script                  | What it measures                                  |
| ----------------------- | ------------------------------------------------- |
| `taint_overhead.py`     | Per-call cost of taint detection + marking        |

## Running

```bash
python benchmarks/taint_overhead.py
python benchmarks/taint_overhead.py --iterations 50000 --json
```

All benchmarks accept `--json` for CI consumption and print to stdout.
They are intentionally self-contained: no network, no sandbox, no disk
writes.

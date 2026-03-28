# Deterministic Execution Envelopes (DEE)

Every tool call through MCPKernel produces a **Deterministic Execution Envelope** — a cryptographically signed record that captures the exact input, output, and execution metadata. This makes every agent action provably replayable.

---

## What's in an Envelope?

| Field | Description |
|-------|-------------|
| `trace_id` | Unique identifier for this execution |
| `tool_name` | Which tool was called |
| `input_hash` | SHA-256 hash of the input arguments |
| `output_hash` | SHA-256 hash of the tool result |
| `duration_seconds` | How long execution took |
| `timestamp` | When the call happened |
| `signature` | Sigstore signature (optional) |

---

## Configuration

```yaml
dee:
  enabled: true
  store_path: .mcpkernel/traces.db     # SQLite database
  sign_traces: true                     # Sigstore signatures
  replay_on_drift: false                # Re-execute if hash mismatch
```

---

## Tutorial: View Execution Traces

After running tool calls through MCPKernel, inspect the trace log:

```bash
mcpkernel trace-list --db .mcpkernel/traces.db --limit 5
```

Output:

```
  a1b2c3d4e5f6… | read_file              | in=8f3a2b1c… out=d4e5f6a7… | 0.023s
  b2c3d4e5f6a7… | list_dir               | in=1c2d3e4f… out=a7b8c9d0… | 0.015s
  c3d4e5f6a7b8… | http_get               | in=3e4f5a6b… out=b8c9d0e1… | 0.342s
  d4e5f6a7b8c9… | execute_python         | in=5a6b7c8d… out=c9d0e1f2… | 1.204s
  e5f6a7b8c9d0… | write_file             | in=7c8d9e0f… out=d0e1f2a3… | 0.018s
```

### Export traces

```bash
# Export a specific trace as JSON
mcpkernel trace-export a1b2c3d4e5f6 --db .mcpkernel/traces.db
```

Output:

```json
{
  "trace_id": "a1b2c3d4e5f6",
  "tool_name": "read_file",
  "input_hash": "8f3a2b1c...",
  "output_hash": "d4e5f6a7...",
  "duration_seconds": 0.023,
  "timestamp": "2026-03-28T14:30:00Z"
}
```

!!! tip "Redirect to file"
    Use shell redirection to save: `mcpkernel trace-export <id> > trace.json`

---

## Tutorial: Replay Detection

DEE enables **drift detection** — if you replay the same input and get a different output, something changed.

```yaml
dee:
  replay_on_drift: true
```

When enabled, MCPKernel:

1. Stores the input hash → output hash mapping for every call
2. On subsequent calls with the same input, compares the output hash
3. If they differ, logs a drift warning
4. Optionally re-executes to verify

This catches:
- Non-deterministic tool implementations
- Tool servers that change behavior silently
- Compromised servers returning different results

---

## How DEE Fits the Pipeline

```
Tool Call → Pre-hooks → Execute → DEE captures trace → Audit log → Response
                                      ↓
                              Stores: trace_id, input_hash,
                              output_hash, duration, signature
```

The DEE hook runs after execution to capture the result. The trace is then available for:

- **Audit queries** — "What did this agent do?"
- **Replay verification** — "Would this call produce the same result?"
- **Compliance evidence** — Signed proof of every action taken

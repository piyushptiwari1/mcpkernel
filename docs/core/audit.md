# Audit & Logging

MCPKernel maintains a **tamper-proof, append-only audit log** of every tool call, policy decision, and security event. Each entry is hash-chained to the previous one — if any entry is modified, the chain breaks and tampering is detected.

---

## How It Works

```
Tool Call → Policy Decision → Execution → AuditEntry created
                                              ↓
                                    Hash-chained to previous entry
                                              ↓
                                    Stored in SQLite (WAL mode)
```

Every `AuditEntry` contains:

| Field | Description |
|-------|-------------|
| `entry_id` | Unique identifier |
| `timestamp` | Unix timestamp |
| `event_type` | What happened: `tool_call`, `policy_violation`, `taint_detected`, etc. |
| `tool_name` | Which tool was called |
| `agent_id` | Which agent made the call |
| `action` | Policy action taken: `allow`, `deny`, `audit`, `sandbox` |
| `outcome` | Result: `success`, `blocked`, `error` |
| `details` | JSON dict with extra context |
| `content_hash` | SHA-256 hash of this entry |
| `prev_hash` | Hash of previous entry (chain link) |

---

## Tutorial: Python API

### Create and log an entry

```python
import asyncio
from mcpkernel.audit.logger import AuditLogger, AuditEntry

async def main():
    logger = AuditLogger(db_path="my_audit.db")
    await logger.initialize()

    # Log a tool call
    entry = AuditEntry(
        event_type="tool_call",
        tool_name="read_file",
        agent_id="agent-001",
        action="allow",
        outcome="success",
        details={"path": "data.csv", "bytes_read": 1024},
    )
    entry_id = await logger.log(entry)
    print(f"Logged: {entry_id}")
    # Output: Logged: req_a1b2c3d4

    # Log a policy violation
    violation = AuditEntry(
        event_type="policy_violation",
        tool_name="shell_exec",
        agent_id="agent-002",
        action="deny",
        outcome="blocked",
        details={"rule_id": "ASI-01-001", "reason": "shell execution denied"},
    )
    await logger.log(violation)

    await logger.close()

asyncio.run(main())
```

### Query the audit log

```python
async def query_example():
    logger = AuditLogger(db_path="my_audit.db")
    await logger.initialize()

    # Get all policy violations
    violations = await logger.query(event_type="policy_violation", limit=10)
    for v in violations:
        print(f"[{v.event_type}] {v.tool_name}: {v.outcome}")
    # Output:
    # [policy_violation] shell_exec: blocked

    # Get recent entries for a specific tool
    reads = await logger.query(tool_name="read_file", limit=5)
    print(f"Found {len(reads)} read_file entries")
    # Output: Found 1 read_file entries

    await logger.close()
```

### Verify integrity (tamper detection)

```python
async def verify_example():
    logger = AuditLogger(db_path="my_audit.db")
    await logger.initialize()

    result = await logger.verify_integrity()
    print(result)
    # Output (clean):
    # {
    #     "total_entries": 2,
    #     "tampered_entries": 0,
    #     "chain_breaks": 0,
    #     "integrity": "ok"
    # }

    await logger.close()
```

!!! warning "Tampered log detection"
    If any entry has been modified:
    ```python
    # Output (tampered):
    # {
    #     "total_entries": 2,
    #     "tampered_entries": 1,
    #     "chain_breaks": 1,
    #     "integrity": "compromised"
    # }
    ```

---

## Tutorial: CLI Commands

### Query audit logs

```bash
# List recent entries
mcpkernel audit-query --limit 10
```

Output:

```
  req_a1b2c3d4 | 2026-03-28 14:30:00 | tool_call         | read_file  | allow | success
  req_b2c3d4e5 | 2026-03-28 14:30:01 | policy_violation  | shell_exec | deny  | blocked
```

```bash
# Filter by event type
mcpkernel audit-query --event-type policy_violation --limit 5

# Export in SIEM format
mcpkernel audit-query --format cef > siem_export.log
mcpkernel audit-query --format jsonl > structured.jsonl
mcpkernel audit-query --format csv > spreadsheet.csv
```

### Verify log integrity

```bash
mcpkernel audit-verify
```

Output (clean):

```
Audit Log Integrity Check
=========================
  Total entries:    247
  Tampered:         0
  Chain breaks:     0
  Status:           ✓ OK

All entries verified — no tampering detected.
```

---

## Export Formats

MCPKernel supports three SIEM-compatible export formats:

=== "JSONL"

    ```json
    {"entry_id":"req_a1b2","timestamp":1711641000.0,"event_type":"tool_call","tool_name":"read_file","agent_id":"agent-001","action":"allow","outcome":"success","content_hash":"8f3a2b..."}
    {"entry_id":"req_b2c3","timestamp":1711641001.0,"event_type":"policy_violation","tool_name":"shell_exec","agent_id":"agent-002","action":"deny","outcome":"blocked","content_hash":"d4e5f6..."}
    ```

=== "CEF"

    ```
    CEF:0|MCPKernel|AuditLog|1.0|tool_call|Tool Call|3|src=agent-001 act=allow outcome=success cs1=read_file cs1Label=tool_name
    CEF:0|MCPKernel|AuditLog|1.0|policy_violation|Policy Violation|8|src=agent-002 act=deny outcome=blocked cs1=shell_exec cs1Label=tool_name
    ```

=== "CSV"

    ```csv
    "entry_id","timestamp","event_type","tool_name","agent_id","action","outcome","content_hash"
    "req_a1b2","1711641000.0","tool_call","read_file","agent-001","allow","success","8f3a2b..."
    "req_b2c3","1711641001.0","policy_violation","shell_exec","agent-002","deny","blocked","d4e5f6..."
    ```

### Python export API

```python
from mcpkernel.audit.exporter import export_audit_logs, AuditExportFormat

# Export entries you've queried
entries = await logger.query(limit=100)

jsonl_output = export_audit_logs(entries, AuditExportFormat.JSON_LINES)
cef_output = export_audit_logs(entries, AuditExportFormat.SIEM_CEF)
csv_output = export_audit_logs(entries, AuditExportFormat.CSV)

# Write to file
with open("siem_export.jsonl", "w") as f:
    f.write(jsonl_output)
```

---

## Configuration

```yaml
# .mcpkernel/config.yaml
audit:
  enabled: true
  db_path: .mcpkernel/audit.db
  log_level: INFO
```

!!! tip "Production deployment"
    For high-throughput environments, the SQLite backend uses WAL mode and async writes via `aiosqlite` for minimal impact on tool call latency.

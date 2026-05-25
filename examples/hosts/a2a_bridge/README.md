# Agent-to-Agent (A2A) bridge with MCPKernel

This example shows two agents exchanging tool calls through MCPKernel
acting as a **bidirectional policy gateway**. Either side's outbound
calls — and the data they carry — are subject to the same taint,
policy, and audit pipeline.

```
┌──────────┐     MCP      ┌────────────┐     MCP     ┌──────────┐
│ Agent A  │ ───────────▶ │  MCPKernel │ ──────────▶ │ Agent B  │
│ (planner)│ ◀─────────── │  (gateway) │ ◀────────── │ (worker) │
└──────────┘              └────────────┘             └──────────┘
                                │
                                ▼
                          policy + taint + DEE + audit
```

## Why a gateway between agents

A2A traffic carries the same risks as agent-to-tool traffic:

| Risk (OWASP LLM Top 10 2025) | How MCPKernel addresses it |
|---|---|
| LLM01 Prompt injection from B → A | Taint label `prompt_injection` on B's output |
| LLM02 Sensitive info disclosure | Block PII-tainted payloads from crossing trust boundary |
| LLM05 Improper output handling | Structured-output schema enforcement |
| LLM06 Excessive agency | Per-rule allow/deny for cross-agent tool calls |
| LLM08 Vector & embedding weaknesses | DEE replay of full A2A transcripts for forensics |

## Run the example

### 1. Start two MCP servers (one per "agent")

The repo ships [`examples/simple_mcp_server/`](../../simple_mcp_server/)
which exposes a few demo tools. Start two instances on different ports:

```bash
# Terminal 1 — Agent B's tools
python examples/simple_mcp_server/server.py --port 3001

# Terminal 2 — Agent A's tools
python examples/simple_mcp_server/server.py --port 3002
```

### 2. Configure MCPKernel as the A2A bridge

Save as `a2a.yaml`:

```yaml
proxy:
  host: 127.0.0.1
  port: 8080

upstream:
  - name: agent_b
    transport: streamable_http
    url: http://127.0.0.1:3001/mcp
  - name: agent_a
    transport: streamable_http
    url: http://127.0.0.1:3002/mcp

taint:
  mode: full
  block_on_violation: true

policy:
  policy_paths: [a2a_policy.yaml]
  default_action: audit

audit:
  enabled: true
  db_path: ./a2a_audit.db
```

### 3. Write a cross-agent policy

Save as `a2a_policy.yaml`:

```yaml
rules:
  - id: A2A-001
    name: Block agent A from passing user secrets to agent B
    description: Any tainted secret coming from agent A must not reach B
    action: deny
    priority: 5
    server_patterns: ["agent_b"]
    taint_labels: [secret, api_key, pii]

  - id: A2A-002
    name: Cap agent B's privilege
    description: B is "worker" — never let it call destructive tools
    action: deny
    priority: 5
    server_patterns: ["agent_b"]
    tool_patterns: ["delete_.*", "drop_.*", "shell_exec"]

  - id: A2A-003
    name: Audit everything else
    action: audit
    priority: 100
    tool_patterns: [".*"]
```

### 4. Run the gateway

```bash
mcpkernel serve -c a2a.yaml
```

Both agents now connect to `http://127.0.0.1:8080/mcp` and reference
each other by upstream name (`agent_a`, `agent_b`). Every cross-agent
call traverses the same hooks pipeline that protects user-to-agent
traffic.

### 5. Inspect the bidirectional transcript

```bash
mcpkernel audit query --limit 20 --db ./a2a_audit.db
```

Each row shows `caller_server → tool_name → callee_server` plus the
policy decision and any taint labels. For a full replay:

```bash
mcpkernel trace-list --limit 5
mcpkernel replay <trace_id>
```

## Extending to real A2A protocols

When the Google A2A or Anthropic Computer-Use A2A specs land in
[`src/mcpkernel/proxy/`](../../../src/mcpkernel/proxy/), this same
config will work without modification — the upstream entry just
changes its `transport` field.

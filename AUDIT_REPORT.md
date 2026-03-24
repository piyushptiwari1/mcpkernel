# MCPKernel Comprehensive Architecture Audit

**Date**: 2025-01-XX  
**Version audited**: 0.1.1  
**Branch**: `development`  
**Tests**: 463 pass, 0 fail, 4 warnings  
**Lint**: ruff clean, mypy clean (53 files)

---

## Executive Summary

MCPKernel is **an end-to-end security service** but **NOT yet an infrastructure service**. The distinction:

| | End-to-end Service | Infrastructure Service |
|---|---|---|
| **Definition** | Works as a single proxy for tool calls | Provides platform-level capabilities (self-healing, hot-reload, multi-tenant, clustered) |
| **MCPKernel status** | ✅ Works for single-server proxy | ❌ Missing clustering, auto-scaling, tenant isolation, hot-reload |

The proxy pipeline (auth → rate-limit → policy → taint → DEE → audit → upstream) is **functional and tested**. But there are **19 critical gaps** preventing production readiness.

---

## Package-by-Package Audit

### 1. `proxy/` — The Core Gateway ✅ FUNCTIONAL (with gaps)

| File | Status | Issues |
|---|---|---|
| `server.py` | ✅ Working | Missing SSE/streamable-http streaming, only handles POST /mcp |
| `upstream.py` | ✅ Working | No reconnection logic, no health-check loop, no load balancing |
| `interceptor.py` | ✅ Working | Solid Kong-inspired pipeline, well-tested |
| `hooks.py` | ✅ Working | All 5 hooks wired (policy, taint, DEE, audit, eBPF) |
| `auth.py` | ⚠️ Partial | Only API key auth works. OAuth2/mTLS declared but returns NoAuth |
| `rate_limit.py` | ✅ Working | In-memory only. Redis backend declared in config but not implemented |
| `transform.py` | ✅ Working | REST→MCP normalization, covers all MCP methods |

**Critical gaps in proxy/:**

1. **No SSE/WebSocket streaming** — MCP SDK clients use `streamable_http_client` which expects Server-Sent Events for server→client streams. MCPKernel only serves `POST /mcp` returning JSON. Any client using the official MCP SDK will fail to connect because the protocol negotiation expects streaming support.

2. **Missing MCP methods** — `resources/list`, `resources/read`, `prompts/list`, `prompts/get`, `ping`, `logging/setLevel`, `completion/complete` all return `-32601 Method not found`. These are standard MCP protocol methods and must be forwarded to upstream.

3. **No upstream reconnection** — If an upstream server restarts, MCPKernel has no retry/reconnect logic. The connection dies permanently.

4. **No graceful shutdown** — The lifespan context disconnects upstreams but doesn't drain in-flight requests.

5. **OAuth2 and mTLS** — Config accepts `oauth2_jwks_url`, `oauth2_issuer`, `oauth2_audience`, `mtls_ca_cert` but `create_auth_backend()` ignores them and falls back to NoAuth.

---

### 2. `sandbox/` — The Execution Backends ❌ NOT WIRED INTO PIPELINE

| File | Status | Issues |
|---|---|---|
| `base.py` | ✅ Good interface | 8 abstract methods, clean design |
| `docker_backend.py` | ⚠️ Works standalone | Runs `python3 -c <code>` in container — but proxy sends JSON-RPC, not code |
| `firecracker_backend.py` | ❌ Stub | Needs firecracker binary + kernel + rootfs, runs subprocess |
| `wasm_backend.py` | ❌ Placeholder | Returns `"WASM execution placeholder"` string |
| `microsandbox_backend.py` | ⚠️ Works if external service exists | HTTP client to external API |

**Critical problem**: The sandbox is **completely disconnected from the proxy pipeline**. In `hooks.py`, the `PolicyAction.SANDBOX` is evaluated but there is no `SandboxHook` — when policy returns `sandbox`, it's treated as "allowed" (see `PolicyDecision.allowed` which returns True for SANDBOX). No code ever creates a sandbox, sends tool calls to it, or uses the sandbox execution path.

**What would need to happen**: A `SandboxHook` that, when policy decision is SANDBOX:
1. Routes the tool call to a sandbox backend instead of upstream
2. Executes in the sandbox with resource limits
3. Returns the sandbox result through the pipeline

---

### 3. `dee/` — Deterministic Execution Envelopes ✅ FUNCTIONAL

| File | Status | Issues |
|---|---|---|
| `envelope.py` | ✅ Working | wrap_execution, Sigstore signing, hash chain |
| `trace_store.py` | ✅ Working | SQLite WAL, append-only, indexed |
| `replay.py` | ⚠️ Working but fragile | `replay()` tries to reconstruct MCPToolCall from metadata but `metadata_json` may not contain arguments |
| `drift.py` | ✅ Working | Multi-replay comparison, heuristic classification |
| `snapshot.py` | ✅ Working | Environment hash from filesystem + env vars |

**Gaps**:
- `replay.py` reconstructs the tool call arguments from `metadata_json`, but `envelope.py` doesn't store arguments in the trace metadata. This means replay always replays with empty arguments `{}`.
- `_sign_trace` requires interactive Sigstore OIDC (browser popup). No CI/keyless mode.
- No trace retention/cleanup policy — database grows unbounded.

---

### 4. `taint/` — Taint Tracking ✅ FUNCTIONAL

| File | Status | Issues |
|---|---|---|
| `tracker.py` | ✅ Working | Labels, provenance chain, sanitizer registry |
| `sources.py` | ✅ Working | 9 built-in patterns (AWS keys, JWT, PII, etc.) |
| `sinks.py` | ✅ Working | 6 sink definitions, block/warn/log/allow |
| `propagation.py` | ✅ Working | Cross-tool flow tracking with Mermaid output |
| `static_analysis.py` | ✅ Working | AST-based dangerous pattern detection |
| `report.py` | ✅ Working | Mermaid flow graph generation |

**Gaps**:
- `TaintPropagator` is defined but **never instantiated in the pipeline**. The `TaintHook` uses `TaintTracker` + `detect_tainted_sources` only. Cross-tool propagation tracking is unreachable in the running system.
- `check_sink_operation` is never called in the pipeline. The `SinkDefinition` system is orphaned.
- No custom taint patterns from config (config has `custom_sources`/`custom_sinks` fields but these are never read by the hook).
- No taint redaction — tainted content passes through to the response unmodified.

---

### 5. `policy/` — Policy Engine ✅ FUNCTIONAL

| File | Status | Issues |
|---|---|---|
| `engine.py` | ✅ Working | Regex matching, precedence, taint-aware |
| `loader.py` | ✅ Working | YAML parsing, directory loading |

**Gaps**:
- No **hot-reload** — config says `hot_reload: true` but no file-watcher is implemented.
- No **conditions evaluation** beyond simple equality. The `conditions` field in rules only supports `key == value` matching. No operators (`>`, `<`, `contains`, `startswith`).
- `argument_patterns` uses `re.search()` but doesn't have regex timeout protection (could be ReDoS if user provides malicious patterns — note: there is `test_policy_regex_safety.py` which may address this).
- No rule versioning or audit trail for policy changes.

---

### 6. `context/` — Context Minimization ✅ FUNCTIONAL but DISCONNECTED

| File | Status | Issues |
|---|---|---|
| `reducer.py` | ✅ Working | TF-IDF scoring, token budget |
| `pruning.py` | ✅ Working | 3 strategy levels |
| `dependency_graph.py` | ✅ Working | AST-based Python dependency analysis |

**Critical problem**: Context minimization is **never called from the proxy pipeline**. The `ContextConfig` exists in settings but nothing reads it. No `ContextHook` exists. This entire package is unused at runtime.

---

### 7. `ebpf/` — Kernel Syscall Monitoring ⚠️ FUNCTIONAL (root-only)

| File | Status | Issues |
|---|---|---|
| `probe.py` | ✅ Working | BCC-based, graceful fallback |
| `redirector.py` | ✅ Working | Domain allowlist, CIDR, port blocking |

**Gaps**:
- Requires root + BCC. Gracefully degrades to no-op, which is correct.
- The `EBPFHook` only checks argument strings for URLs to do egress checking. It doesn't actually monitor kernel-level syscalls during tool execution (the probe runs but events are only logged, not used to block).
- `programs/` directory is empty — no shipped BPF bytecode.

---

### 8. `observability/` — Metrics & Tracing ⚠️ DEFINED but NOT WIRED

| File | Status | Issues |
|---|---|---|
| `metrics.py` | ✅ Defined | 8 Prometheus metrics defined, export works |
| `health.py` | ✅ Working | Component-level health aggregation |
| `tracing.py` | ⚠️ Partial | OTEL setup works if SDK installed |

**Critical problem**: `MetricsCollector` is **never called from the pipeline**. The proxy processes every tool call but never increments `tool_calls_total`, `policy_decisions`, `taint_detections`, etc. The `/metrics` endpoint is not exposed in `server.py`. The metrics infrastructure exists but produces all-zero values.

**Health check** is defined but `server.py`'s `/health` endpoint is hardcoded, not using the `HealthCheck` class.

---

### 9. `audit/` — Append-only Audit ✅ FUNCTIONAL

| File | Status | Issues |
|---|---|---|
| `logger.py` | ✅ Working | SQLite WAL, hash-based tamper detection |
| `exporter.py` | ✅ Working | JSONL, CSV, CEF export |

**Gaps**:
- No log rotation/retention policy
- No Sigstore signing of audit entries (only traces are signed)
- Chain integrity is hash-per-entry, not hash-chain (entry N doesn't include hash of entry N-1). A middle entry can be deleted without detection.

---

### 10. `agent_manifest/` — Agent Manifest Integration ✅ FUNCTIONAL but DISCONNECTED

| File | Status | Issues |
|---|---|---|
| `loader.py` | ✅ Working | Full agent.yaml parsing |
| `policy_bridge.py` | ✅ Working | Compliance→PolicyRule generation |
| `tool_validator.py` | ✅ Working | JSON Schema validation |
| `hooks.py` | ✅ Working | Tool allowlist + schema validation hook |

**Critical problem**: `AgentManifestHook` is **never registered in the pipeline**. The CLI commands `manifest-import` and `manifest-validate` work, but the hook is not wired into server startup. To use it, a user would need to manually register it — but there's no config field or CLI flag to do this.

---

### 11. `cli.py` — CLI Interface ✅ FUNCTIONAL

| Command | Status | Issues |
|---|---|---|
| `serve` | ✅ Working | Starts proxy |
| `validate-policy` | ✅ Working | |
| `trace-list` | ✅ Working | |
| `trace-export` | ✅ Working | |
| `replay` | ⚠️ Buggy | Arguments not stored in trace, replays with `{}` |
| `audit-query` | ✅ Working | |
| `audit-verify` | ✅ Working | |
| `scan` | ✅ Working | Static analysis |
| `init` | ✅ Working | |
| `add-server` | ✅ Working | |
| `test-connection` | ✅ Working | |
| `manifest-import` | ✅ Working | |
| `manifest-validate` | ✅ Working | |
| `version` | ✅ Working | |
| `config-show` | ✅ Working | |

---

## Cross-Cutting Issues

### Issue 1: No MCP Protocol Compliance (CRITICAL)

The MCP specification requires servers to support streaming via SSE (Server-Sent Events) or the new streamable-http protocol. MCPKernel only exposes `POST /mcp` returning a JSON response. This means:

- **MCP SDK clients cannot connect** — `streamable_http_client()` expects to negotiate SSE
- **No server-initiated notifications** — tools/list changes can't be pushed
- **No progress reporting** — long-running tool calls can't stream progress

**To fix**: MCPKernel should either:
1. Use `mcp.server.fastmcp.FastMCP` or `mcp.server.lowlevel.Server` to expose a proper MCP server that clients can connect to
2. Implement SSE endpoint at `/mcp` alongside the POST handler

### Issue 2: Resources/Prompts Not Forwarded (HIGH)

MCPKernel's `server.py` only handles `initialize`, `notifications/initialized`, `tools/list`, and `tools/call`. All other MCP methods return method-not-found. This breaks any upstream server that exposes resources or prompts.

### Issue 3: Disconnected Components (HIGH)

These components are built and tested but never called at runtime:
- `context/` (context minimization) — no hook, no call site
- `observability/metrics.py` — counters exist but never increment
- `observability/health.py` — HealthCheck class unused
- `taint/propagation.py` — TaintPropagator never instantiated
- `taint/sinks.py` — check_sink_operation never called
- `sandbox/` — no SandboxHook, SANDBOX policy action is a no-op
- `agent_manifest/hooks.py` — AgentManifestHook never registered

### Issue 4: No A2A Protocol Support (MEDIUM)

The project description says "MCP/A2A gateway" but there is zero A2A (Agent-to-Agent) protocol implementation anywhere in the codebase.

### Issue 5: Missing SDK Integration Examples (MEDIUM)

The four framework examples (`autogen/`, `crewai/`, `langchain/`, `copilot_guard/`) exist but none can work because MCPKernel doesn't expose a proper MCP server endpoint that these frameworks' MCP clients expect.

---

## What's Missing for End-to-End Infrastructure Service

### Must-Have (blocks production use)

| # | Gap | Package | Effort |
|---|---|---|---|
| 1 | MCP protocol streaming (SSE/streamable-http) | proxy/ | Large |
| 2 | Forward all MCP methods (resources, prompts, ping) | proxy/ | Medium |
| 3 | Wire MetricsCollector into pipeline + expose /metrics | observability/ + proxy/ | Small |
| 4 | Wire context minimization into pipeline | context/ + proxy/ | Small |
| 5 | Wire TaintPropagator + sink checking | taint/ + hooks.py | Medium |
| 6 | Wire AgentManifestHook from config | agent_manifest/ + server.py | Small |
| 7 | Create SandboxHook for SANDBOX policy action | sandbox/ + hooks.py | Medium |
| 8 | Implement OAuth2 JWKS auth backend | proxy/auth.py | Medium |
| 9 | Fix replay — store tool arguments in trace | dee/envelope.py + replay.py | Small |
| 10 | Upstream reconnection with backoff | proxy/upstream.py | Medium |

### Should-Have (production quality)

| # | Gap | Package | Effort |
|---|---|---|---|
| 11 | Redis rate limiter backend | proxy/rate_limit.py | Medium |
| 12 | Policy hot-reload (file watcher) | policy/ | Medium |
| 13 | Audit hash-chain (entry N links to N-1) | audit/logger.py | Small |
| 14 | Trace/audit retention + cleanup | dee/ + audit/ | Small |
| 15 | mTLS auth backend | proxy/auth.py | Medium |
| 16 | Custom taint patterns from config | taint/ + config.py | Small |
| 17 | Health check wiring (use HealthCheck class) | observability/ + server.py | Small |
| 18 | Graceful shutdown with request draining | proxy/server.py | Medium |
| 19 | Structured error responses (MCP error spec) | proxy/ | Small |

### Nice-to-Have (competitive advantage)

| # | Gap | Description | Effort |
|---|---|---|---|
| 20 | A2A protocol support | Agent-to-Agent gateway | Large |
| 21 | Multi-tenant isolation | Separate namespaces per client | Large |
| 22 | Dashboard UI | Real-time monitoring web panel | Large |
| 23 | Webhook notifications | Alert on policy violations | Medium |
| 24 | Plugin system for custom hooks | User-defined Python hooks | Medium |
| 25 | Load balancing across upstream servers | Round-robin / least-connections | Medium |

---

## Ease of Use Assessment

### Current UX (score: 5/10)

**Good**:
- `mcpkernel init` creates a ready-to-edit config
- `mcpkernel add-server` simplifies config editing
- `mcpkernel test-connection` validates setup
- `mcpkernel serve` is one command
- YAML config is readable

**Bad**:
- No `mcpkernel quickstart` that runs a demo end-to-end
- No interactive setup wizard
- Error messages when upstream fails are generic
- No dashboard or visual feedback
- CLI has no `--verbose` or `--dry-run` flags
- Config validation errors are unclear
- No `mcpkernel status` to check running state

### Integration Difficulty (score: 4/10)

For an MCP client to use MCPKernel, it currently needs to:
1. Send raw HTTP POST to `/mcp` with JSON-RPC body
2. Handle non-standard error codes
3. Cannot use official MCP SDK client because no SSE support

This is **the #1 blocker** — MCP clients can't connect natively.

---

## Why Internal Agents Are Not Working

Based on the agent definitions in `.github/agents/`, the agents are configured to use MCPKernel. The most likely reasons they fail:

1. **No MCP-compatible endpoint** — Agents using MCP SDK's `ClientSession` can't connect because MCPKernel doesn't serve the streaming protocol. The agents would need to use raw HTTP, which defeats the purpose.

2. **Missing method handlers** — If agents call `resources/list` or `prompts/get`, they get errors.

3. **AgentManifestHook not wired** — The `agent_manifest/hooks.py` has an `AgentManifestHook` that enforces `agent.yaml` tool allow-lists, but it's never registered. Agents' `agent.yaml` declarations are ignored at runtime.

4. **No multi-agent session support** — Each tool call is stateless. There's no concept of an agent session, so taint tracking across a multi-step agent workflow doesn't persist between calls.

---

## Required SDKs & Dependencies Audit

### Currently Used (correct)
- `mcp>=1.0` — MCP protocol client SDK (for upstream connections)
- `fastapi>=0.115` — HTTP server
- `uvicorn[standard]>=0.30` — ASGI server
- `pydantic>=2.7` / `pydantic-settings>=2.3` — Config
- `httpx>=0.27` — HTTP client
- `structlog>=24.1` — Logging
- `pyyaml>=6.0` — Config/policy parsing
- `sigstore>=3.0` — Trace signing
- `opentelemetry-*` — Tracing/metrics
- `prometheus-client>=0.20` — Metrics
- `aiosqlite>=0.20` — Trace/audit storage
- `cryptography>=42.0` — Crypto primitives

### Missing SDKs Needed
- `mcp.server` (from `mcp>=1.0`) — To expose MCPKernel AS an MCP server (not just a client). Already in deps, just not used for server-side.
- `watchfiles>=0.21` — For policy hot-reload file watching
- `redis[hiredis]>=5.0` — For Redis rate limiter (optional)
- `pyjwt[crypto]>=2.8` or `python-jose>=3.3` — For OAuth2 JWT validation
- No additional deps needed for A2A (custom implementation)

---

## Competitive Comparison

| Feature | MCPKernel | Envoy Proxy | Kong Gateway | OPA (Rego) |
|---|---|---|---|---|
| MCP-native | ✅ | ❌ | ❌ | ❌ |
| Policy engine | ✅ YAML | ❌ | ✅ Lua | ✅ Rego |
| Taint tracking | ✅ | ❌ | ❌ | ❌ |
| Deterministic replay | ✅ | ❌ | ❌ | ❌ |
| Sigstore audit | ✅ | ❌ | ❌ | ❌ |
| Streaming support | ❌ | ✅ | ✅ | N/A |
| Production ready | ❌ | ✅ | ✅ | ✅ |
| eBPF integration | ⚠️ | ✅ (Cilium) | ❌ | ❌ |
| Multi-tenant | ❌ | ✅ | ✅ | ✅ |

MCPKernel has **unique differentiators** (taint tracking + DEE + MCP-native) but **critical infrastructure gaps** compared to mature proxies.

---

## Recommended Implementation Priority

### Phase 1: MCP Protocol Compliance (URGENT)
Make MCPKernel a proper MCP server that any MCP client can connect to:
1. Use `mcp.server.lowlevel.Server` to serve the MCP protocol
2. Forward all MCP methods to upstream
3. Keep the security pipeline (hooks) in the forwarding path
4. Support SSE streaming for server→client notifications

### Phase 2: Wire Disconnected Components
1. Wire MetricsCollector (increment counters in hooks)
2. Wire TaintPropagator + sink checking
3. Wire AgentManifestHook from config
4. Wire context minimization as optional hook
5. Create SandboxHook for SANDBOX policy action

### Phase 3: Production Hardening
1. Upstream reconnection with backoff
2. OAuth2/mTLS auth
3. Redis rate limiter
4. Policy hot-reload
5. Audit hash-chain
6. Trace retention policy

### Phase 4: Infrastructure Features
1. A2A protocol support
2. Dashboard UI
3. Multi-tenant isolation
4. Plugin system
5. Load balancing

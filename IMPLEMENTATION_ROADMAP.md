# MCPKernel Implementation Roadmap

**Last updated**: March 2026 (v0.1.2 audit + replan)

---

## Vision

MCPKernel is a **pip-installable Python library + CLI** that secures any MCP tool call pipeline. Users should NOT need to clone any git repo. The two primary interfaces are:

1. **CLI** — `pip install mcpkernel && mcpkernel serve` (proxy gateway mode)
2. **Python API** — `from mcpkernel import MCPKernelProxy` (library/programmatic mode)

Everything is configurable: users enable only the features they need.

---

## Status Summary

| Category | Items Done | Items Remaining |
|----------|-----------|-----------------|
| MCP Protocol | 3/3 ✅ | — |
| Pipeline Hooks | 8/8 ✅ | — |
| Production Hardening | 4/6 | OAuth2, Redis rate-limiter |
| User Experience | 7/7 ✅ | — |
| Infrastructure | 1/5 | A2A, dashboard, multi-tenant, load balancing |

---

## Phase 1: MCP Protocol Compliance ✅ COMPLETE

| # | Item | Status |
|---|------|--------|
| 1.1 | MCP server via `lowlevel.Server` + `StreamableHTTPSessionManager` | ✅ Done |
| 1.2 | Forward all MCP methods (tools, resources, prompts, ping) to upstream | ✅ Done |
| 1.3 | stdio transport (`mcpkernel serve --transport stdio`) | ✅ Done |

---

## Phase 2: Pipeline Wiring ✅ COMPLETE

| # | Item | Status |
|---|------|--------|
| 2.1 | ObservabilityHook — Prometheus metrics in pipeline | ✅ Done |
| 2.2 | TaintHook — propagator + Guardrails AI + sink detection | ✅ Done |
| 2.3 | AgentManifestHook — wired from config into both lifespans | ✅ Done |
| 2.4 | ContextHook — prune large arguments with strategy control | ✅ Done |
| 2.5 | SandboxHook — execute in sandbox on "sandbox" policy decision | ✅ Done |
| 2.6 | Policy hot-reload watcher (watchfiles + polling fallback) | ✅ Done |
| 2.7 | Trace retention cleanup (`cleanup_old_traces`) | ✅ Done |
| 2.8 | Audit hash-chain with `verify_integrity()` | ✅ Done |

---

## Phase 3: User Experience & Production Readiness ✅ COMPLETE

**Goal**: Users `pip install mcpkernel` and get a production-ready security layer with zero git cloning, intuitive configuration, and a clean Python API.

### 3.1 Python API — `MCPKernelProxy` class
**Status**: ✅ Done (v0.1.2)

**Why**: Users need to use MCPKernel **as a library** from Python code — not just as a CLI. This is the single biggest usability gap.

```python
from mcpkernel import MCPKernelProxy

proxy = MCPKernelProxy(
    upstream=["http://localhost:3000/mcp"],
    policy="deny-unsafe",          # built-in preset or path to YAML
    taint=True,                    # enable taint detection
    audit=True,                    # enable audit logging
)
await proxy.start()

# Programmatic tool call through the security pipeline
result = await proxy.call_tool("read_file", {"path": "/etc/passwd"})
# → PolicyError: denied by rule OWASP-ASI-02
```

### 3.2 `mcpkernel quickstart` CLI command
**Status**: ✅ Done (v0.1.2)

One command that demonstrates the pipeline in action without needing any upstream server.

### 3.3 `mcpkernel status` CLI command
**Status**: ✅ Done (v0.1.2)

Check running state, loaded policies, hook count, upstream status.

### 3.4 Built-in policy presets
**Status**: ✅ Done (v0.1.2)

Named presets so users skip YAML authoring:
- `permissive` — audit everything, block nothing
- `standard` — block known-dangerous patterns, audit rest
- `strict` — deny-by-default, explicit allowlist
- `owasp-asi-2026` — full OWASP ASI compliance rules

### 3.5 `mcpkernel.protect()` decorator
**Status**: ✅ Done (v0.1.2)

One-line decorator for framework users:
```python
from mcpkernel import protect

@protect(policy="strict", taint=True)
async def my_tool(code: str) -> str:
    return eval(code)  # MCPKernel blocks dangerous calls
```

### 3.6 Improved `mcpkernel init` with presets
**Status**: ✅ Done (v0.1.2)

`mcpkernel init --preset strict` creates a ready-to-use config.

### 3.7 Consistent feature toggles
**Status**: ✅ Done (v0.1.2)

Every feature independently enabled/disabled via config YAML + env vars.

---

## Phase 4: Remaining Production Hardening

| # | Item | Status |
|---|------|--------|
| 4.1 | OAuth2 JWT Auth Backend | ⏳ Config exists; raises `NotImplementedError` if enabled |
| 4.2 | Redis Rate Limiter | ⏳ Config exists, code needed |

---

## Phase 5: Infrastructure Features (Future)

| # | Item | Status |
|---|------|--------|
| 5.1 | A2A Protocol Support | ❌ |
| 5.2 | Dashboard UI | ❌ |
| 5.3 | Multi-Tenant Isolation | ❌ |
| 5.4 | Plugin system (entry-point loading) | ⏳ Partial |
| 5.5 | Load Balancing | ❌ |

---

## Priority Order

1. **Phase 3.1** — Python API (`MCPKernelProxy`) — highest impact for library users
2. **Phase 3.5** — `protect()` decorator — one-line integration for framework users
3. **Phase 3.4** — Built-in presets — remove YAML barrier for beginners
4. **Phase 3.2/3.3** — Quickstart + status commands — first-run experience
5. **Phase 3.6** — Init presets — streamlined project setup
6. **Phase 4.1/4.2** — OAuth2 + Redis — enterprise needs

# MCPKernel Implementation Roadmap

## Overview

After auditing every file in every package, here is the concrete implementation plan to take MCPKernel from "working prototype" to "production-grade MCP infrastructure service."

---

## Phase 1: MCP Protocol Compliance (CRITICAL - blocks everything)

**Goal**: Any MCP client can connect to MCPKernel natively.

### 1.1 Serve MCP Protocol via `mcp.server.lowlevel.Server`

**File**: `src/mcpkernel/proxy/server.py` (rewrite)

Currently MCPKernel is a FastAPI HTTP server that accepts POST /mcp. It needs to become a proper MCP server.

**Implementation approach**:
```python
from mcp.server import Server as MCPServer
from mcp.server.sse import SseServerTransport

# Create an MCP server that wraps MCPKernel's security pipeline
mcp_server = MCPServer("mcpkernel")

@mcp_server.list_tools()
async def handle_list_tools():
    # Forward to upstream_manager.list_all_tools()
    # Return aggregated tool list
    
@mcp_server.call_tool()
async def handle_call_tool(name, arguments):
    # Run security pipeline (pre → forward → post → log)
    # Return result

@mcp_server.list_resources()
async def handle_list_resources():
    # Forward to all upstream servers
    
@mcp_server.read_resource()
async def handle_read_resource(uri):
    # Forward to correct upstream

@mcp_server.list_prompts()
async def handle_list_prompts():
    # Forward to all upstream servers

@mcp_server.get_prompt()
async def handle_get_prompt(name, arguments):
    # Forward to correct upstream
```

**Keep the existing FastAPI app** for:
- `GET /health` (REST health check)
- `GET /tools` (REST convenience)  
- `GET /metrics` (Prometheus)
- `POST /mcp` (backward compatibility)

**Mount the MCP server** using the SSE transport on Starlette/FastAPI:
```python
sse = SseServerTransport("/mcp/sse")
app.mount("/mcp/sse", sse.get_starlette_app())
```

### 1.2 Forward All MCP Methods to Upstream

**File**: `src/mcpkernel/proxy/upstream.py`

Add methods to UpstreamConnection:
- `list_resources()` → forward `resources/list`
- `read_resource(uri)` → forward `resources/read`
- `list_resource_templates()` → forward `resources/templates/list`
- `list_prompts()` → forward `prompts/list`
- `get_prompt(name, arguments)` → forward `prompts/get`
- `ping()` → forward `ping`

Add routing to UpstreamManager:
- Resources and prompts need routing (which upstream has which resource)
- Build a resource URI → server mapping on connect

### 1.3 Support stdio Transport for Downstream Clients

Allow MCPKernel itself to be started as a stdio MCP server:
```bash
mcpkernel serve --transport stdio --config config.yaml
```

This lets Claude Desktop, Cursor, etc. use MCPKernel directly in their MCP server config:
```json
{
  "mcpkernel": {
    "command": "mcpkernel",
    "args": ["serve", "--transport", "stdio", "-c", "config.yaml"]
  }
}
```

---

## Phase 2: Wire Disconnected Components

### 2.1 Wire MetricsCollector into Pipeline

**Files**: `proxy/hooks.py`, `proxy/server.py`, `observability/metrics.py`

Create an `ObservabilityHook`:
```python
class ObservabilityHook(PluginHook):
    PRIORITY = 50  # Runs last (low priority = runs after everything)
    NAME = "observability"
    
    def __init__(self, metrics: MetricsCollector):
        self._metrics = metrics
    
    async def post_execution(self, ctx):
        outcome = "blocked" if ctx.aborted else ("error" if ctx.result.is_error else "success")
        self._metrics.tool_calls_total.labels(tool_name=ctx.call.tool_name, outcome=outcome).inc()
        self._metrics.tool_call_duration.labels(tool_name=ctx.call.tool_name).observe(ctx.result.duration_seconds)
        
        if ctx.extra.get("policy_decision"):
            decision = ctx.extra["policy_decision"]
            for rule in decision.matched_rules:
                self._metrics.policy_decisions.labels(action=decision.action.value, rule_id=rule.id).inc()
```

Add `/metrics` endpoint to server.py:
```python
@app.get("/metrics")
async def metrics():
    from starlette.responses import Response
    return Response(content=get_metrics().export_prometheus(), media_type="text/plain")
```

### 2.2 Wire TaintPropagator + Sink Checking

**Files**: `proxy/hooks.py`

Enhance `TaintHook`:
```python
class TaintHook(PluginHook):
    def __init__(self, tracker, *, detect_fn=None, propagator=None):
        self._tracker = tracker
        self._detect_fn = detect_fn
        self._propagator = propagator or TaintPropagator(tracker)
    
    async def post_execution(self, ctx):
        if ctx.result and self._propagator:
            output_labels = self._propagator.propagate_through_call(
                ctx.call.tool_name, ctx.call.arguments, ctx.result.content
            )
            # Check sinks
            tainted_values = self._tracker.get_all_tainted()
            for content_item in ctx.result.content:
                if "url" in str(content_item).lower():
                    check_sink_operation(tainted_values, "http_post")
```

### 2.3 Wire AgentManifestHook from Config

**File**: `config.py`, `proxy/server.py`

Add to config:
```python
class AgentManifestConfig(BaseModel):
    enabled: bool = False
    manifest_path: Path | None = None
```

In server lifespan:
```python
if _settings.agent_manifest.enabled and _settings.agent_manifest.manifest_path:
    definition = load_agent_manifest(_settings.agent_manifest.manifest_path)
    _pipeline.register(AgentManifestHook(definition))
    # Also add bridge rules
    rules = manifest_to_policy_rules(definition)
    policy_engine.add_rules(rules)
```

### 2.4 Wire Context Minimization

Create a `ContextHook`:
```python
class ContextHook(PluginHook):
    PRIORITY = 850  # After taint, before execution
    NAME = "context"
    
    async def pre_execution(self, ctx):
        if len(str(ctx.call.arguments)) > self._max_tokens * 4:
            result = prune_context(ctx.call.arguments, strategy=self._strategy)
            ctx.call = MCPToolCall(..., arguments=result.reduced_content)
```

### 2.5 Create SandboxHook

**New file**: `proxy/hooks.py`

```python
class SandboxHook(PluginHook):
    PRIORITY = 750  # After taint checks, before execution
    NAME = "sandbox"
    
    async def pre_execution(self, ctx):
        if ctx.policy_decision == "sandbox":
            # Execute in sandbox instead of forwarding upstream
            result = await self._backend.execute_code(
                json.dumps(ctx.call.arguments),
                timeout=30,
            )
            ctx.result = result
            ctx.extra["sandboxed"] = True
```

---

## Phase 3: Production Hardening

### 3.1 Upstream Reconnection with Backoff

**File**: `proxy/upstream.py`

```python
class UpstreamConnection:
    async def call_tool(self, name, arguments):
        for attempt in range(3):
            try:
                return await self._session.call_tool(name, arguments)
            except (ConnectionError, RuntimeError):
                await self._reconnect(backoff=2 ** attempt)
        raise RuntimeError(f"Failed after 3 retries")
    
    async def _reconnect(self, backoff: float):
        await asyncio.sleep(backoff)
        await self.disconnect()
        await self.connect()
```

### 3.2 OAuth2 JWT Auth Backend

**File**: `proxy/auth.py`

```python
class OAuth2JWTAuth(AuthBackend):
    def __init__(self, jwks_url, issuer, audience):
        # Fetch JWKS from well-known endpoint
        # Validate JWT signature, issuer, audience, expiry
    
    async def authenticate(self, headers):
        token = headers.get("authorization", "").replace("Bearer ", "")
        claims = jwt.decode(token, key=self._jwks, ...)
        return AuthCredentials(identity=claims["sub"], scopes=set(claims.get("scope", "").split()))
```

### 3.3 Redis Rate Limiter

**File**: `proxy/rate_limit.py`

```python
class RedisRateLimiter:
    async def check(self, key):
        # Use Redis INCR + EXPIRE for distributed rate limiting
        # Lua script for atomic check-and-decrement
```

### 3.4 Policy Hot-Reload

**File**: `policy/watcher.py` (new)

```python
import watchfiles

async def watch_policy_files(engine, paths):
    async for changes in watchfiles.awatch(*paths):
        for change_type, path in changes:
            rules = load_policy_file(path)
            engine.reload_from_file(path, rules)
```

### 3.5 Audit Hash-Chain

**File**: `audit/logger.py`

Change to include previous entry's hash:
```python
async def log(self, entry):
    # Get last entry's hash
    last_hash = await self._get_last_hash()
    entry.prev_hash = last_hash
    entry.compute_hash()  # Now includes prev_hash
```

### 3.6 Trace/Audit Retention

```python
async def cleanup_old_traces(self, max_age_days: int = 90):
    cutoff = time.time() - (max_age_days * 86400)
    await self._db.execute("DELETE FROM traces WHERE timestamp < ?", (cutoff,))
```

---

## Phase 4: Infrastructure Features

### 4.1 A2A Protocol Support
- Implement Google A2A protocol (agent-to-agent)
- Agent Card endpoint, task management, streaming updates

### 4.2 Dashboard UI
- Optional web dashboard (Svelte/React)
- Real-time metrics, taint flow visualization, policy decisions
- Mermaid diagram rendering for taint graphs

### 4.3 Multi-Tenant Isolation
- Namespace per API key/tenant
- Separate policy sets, rate limits, audit logs
- Tenant-scoped trace stores

### 4.4 Plugin System
- User-defined hooks as Python modules
- `mcpkernel.plugins` entry point
- Hot-loadable plugins

### 4.5 Load Balancing
- Multiple instances of same upstream server
- Round-robin, least-connections, weighted routing
- Health-based routing (skip unhealthy upstreams)

---

## Timeline Suggestion

| Phase | Description | Prerequisite |
|---|---|---|
| 1.1-1.2 | MCP protocol compliance | None |
| 1.3 | Stdio transport | 1.1 |
| 2.1-2.5 | Wire all components | 1.1 |
| 3.1-3.6 | Production hardening | 2.x |
| 4.1-4.5 | Infrastructure features | 3.x |

---

## Documentation Plan

To match the reference (https://ai.pydantic.dev/mcp/fastmcp-client/#usage):

```
docs/
├── index.md              # Overview, quick start
├── getting-started/
│   ├── installation.md
│   ├── quickstart.md     # 5-minute tutorial
│   └── configuration.md
├── concepts/
│   ├── architecture.md   # How MCPKernel works
│   ├── proxy.md          # Proxy pipeline
│   ├── policy.md         # Policy engine
│   ├── taint.md          # Taint tracking
│   ├── dee.md            # Deterministic envelopes
│   ├── audit.md          # Audit logging
│   └── sandbox.md        # Sandbox backends
├── guides/
│   ├── claude-desktop.md # Integrate with Claude
│   ├── cursor.md         # Integrate with Cursor
│   ├── langchain.md      # LangChain integration
│   ├── autogen.md        # AutoGen integration
│   └── custom-hooks.md   # Write custom hooks
├── reference/
│   ├── cli.md            # CLI reference
│   ├── config.md         # Full config reference
│   ├── api.md            # HTTP API reference
│   └── policy-format.md  # Policy YAML format
└── changelog.md
```

Build with MkDocs Material (already in optional deps):
```bash
mkdocs serve  # Local dev server with hot-reload
mkdocs build  # Static site for GitHub Pages
```

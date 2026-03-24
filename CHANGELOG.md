# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.2] — 2026-03-25

### Fixed
- **17 mypy type errors** resolved across 5 files:
  - `agent_scan.py`: Explicit `str()` cast for dict value concatenation
  - `guardrails.py`: `type: ignore[import-not-found]` for optional `guardrails` imports
  - `registry.py`: Added `list[RegistryServer]` type annotation on cached value
  - `tracing.py`: `type: ignore[import-not-found]` for optional OTLP exporter import
  - `server.py`: `type: ignore[no-untyped-call, untyped-decorator]` for MCP SDK decorators; `type: ignore[arg-type]` for Starlette mount

### Added
- **64 new tests** in `tests/test_coverage_boost.py` covering:
  - DEE drift detection (all drift categories: NONE, ENVIRONMENT_CHANGE, RANDOM_SEED, CLOCK_DEPENDENCY, NETWORK_CALL, FILESYSTEM_CHANGE, UNKNOWN)
  - DEE envelope wrap_execution with/without Sigstore signing
  - Docker, Firecracker, WASM, and Microsandbox sandbox backend execution paths
  - eBPF probe lifecycle (start/stop/event registration)
  - Guardrails AI validators (PII, secrets, toxic content) with mock validators
  - Langfuse exporter lifecycle, flush, rate-limit retry, error handling
  - Agent scan report-to-policy-rules conversion
- Test coverage raised from **77.36% → 82.39%** (588 tests, all passing)

### Added
- **Third-party integrations package** (`src/mcpkernel/integrations/`)
  - `langfuse.py`: Async audit/trace export to Langfuse with batched ingestion, exponential backoff retry on 429, periodic flush, and graceful shutdown
  - `guardrails.py`: Enhanced PII/secret/toxicity validation via Guardrails AI hub validators (DetectPII, SecretsPresent, ToxicLanguage) with graceful fallback when not installed
  - `registry.py`: MCP Server Registry client for searching, listing, validating upstream MCP servers with response caching
  - `agent_scan.py`: Snyk agent-scan CLI bridge with JSON report parsing and automatic policy rule generation (critical/high → deny, medium → log)
- **Integration configuration models** in `config.py`: `LangfuseConfig`, `GuardrailsIntegrationConfig`, `RegistryConfig`, `AgentScanConfig` — all wired into `MCPKernelSettings`
- **4 new CLI commands**: `registry-search`, `registry-list`, `agent-scan`, `langfuse-export`
- **Enhanced TaintHook**: Optional `guardrails_validator` parameter runs Guardrails AI validators alongside built-in regex patterns
- **Enhanced ObservabilityHook**: Optional `langfuse_exporter` parameter auto-exports audit entries to Langfuse during proxy operation
- **Upstream proxy module** (`proxy/upstream.py`): Native MCP protocol forwarding with reconnection, exponential backoff retry, resource/prompt forwarding
- **Proxy server rewrite** (`proxy/server.py`): MCPLowLevelServer with StreamableHTTPSessionManager, REST endpoints, legacy JSON-RPC, native MCP protocol at `/mcp`
- **mcp-agent example** (`examples/mcp_agent/`): Integration example with config.yaml for mcp-agent framework
- **Simple MCP server example** (`examples/simple_mcp_server/`): FastMCP example server for testing
- 61 new integration tests + upstream tests (524 total, all passing)
- Agent manifest integration module (`src/mcpkernel/agent_manifest/`)
  - Renamed from gitagent to agent_manifest (inspired by open gitagent spec, MIT-licensed)
  - `loader.py`: Loads `agent.yaml`, SOUL.md, RULES.md, hooks.yaml, skills, sub-agents, a2a, vendor management
  - `policy_bridge.py`: Converts compliance config to MCPKernel PolicyRule objects with framework-specific checks (FINRA, SEC, Federal Reserve) and deep segregation-of-duties validation
  - `tool_validator.py`: Validates tool call arguments against declared JSON schemas with enum, type, and required-field checks
  - `hooks.py`: `AgentManifestHook` proxy hook blocks undeclared tools and enforces schema validation at runtime
  - 57 tests covering loader, policy bridge, tool validator, and proxy hook
- Initial project scaffolding with `src/` layout

- MCP/A2A proxy gateway with pluggable interceptor hooks
- Pluggable sandbox backends (Docker, Firecracker, WASM, Microsandbox)
- Deterministic Execution Envelope (DEE) with Sigstore signing
- eBPF-hybrid taint tracking (source/sink/propagation)
- Context minimization engine
- OWASP ASI 2026 policy engine
- Immutable audit trail with Sigstore-signed traces
- OpenTelemetry tracing + Prometheus metrics + structured JSON logging
- Typer CLI with full command set
- GitHub Actions CI/CD (lint, test, release, security scanning)
- Pre-built policies (OWASP strict, minimal, custom template)
- Framework examples (LangChain, CrewAI, AutoGen)

### Fixed
- `docker-compose.yml`: Merged duplicate `volumes:` keys — policy files were silently not mounted
- `ebpf/probe.py`: Replaced deprecated `asyncio.get_event_loop()` with `asyncio.get_running_loop()`
- CI now triggers on `development` branch in addition to `main`
- Format violations in `agent_manifest/hooks.py` and `tests/test_agent_manifest.py`

### Security
- **SSRF prevention** in `agent_scan.py`: URL scheme validation rejects non-HTTP/HTTPS URLs before passing to subprocess
- **Path traversal fix** in `registry.py`: Server name is URL-encoded via `urllib.parse.quote` before inclusion in API path
- **Langfuse host validation** in `config.py`: Warns on non-HTTPS hosts (except localhost) to prevent credential leakage
- **TOCTOU race fix**: Async Guardrails wrappers use `asyncio.to_thread` to avoid blocking the event loop and prevent time-of-check/time-of-use races

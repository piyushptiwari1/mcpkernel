# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
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

# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
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

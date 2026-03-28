# MCPKernel — Project Context for All Agents

## Project Overview
MCPKernel is an open-source **Execution Sovereignty Stack** — a mandatory, deterministic MCP/A2A gateway that makes every agent tool call provably replayable, taint-safe, and policy-enforced. Licensed under Apache 2.0.

**Repository**: `piyushptiwari1/mcpkernel`

## Architecture
- **11 packages** in `src/mcpkernel/`: proxy, sandbox, dee, taint, context, ebpf, policy, audit, observability, cli, agent_manifest
- **Proxy**: AsyncIO MCP/A2A transparent gateway with SSE/stdio transport
- **Policy**: YAML-based rules engine with OWASP ASI 2026 mappings
- **Taint**: Multi-mode taint tracking (FULL/LIGHT/OFF) for secrets, PII, user input
- **Sandbox**: Docker, Firecracker, WASM, Microsandbox backends
- **DEE**: Deterministic Execution Envelopes — hashed, Sigstore-signed, replayable
- **Audit**: Tamper-proof append-only logs with SIEM export (CEF, JSONL, CSV)
- **Context**: Environment snapshots and drift detection
- **Observability**: OpenTelemetry metrics and Prometheus export
- **eBPF**: Kernel-level syscall filtering
- **Agent Manifest**: agent.yaml loader, policy bridge, tool validator, proxy hook

## Code Standards
- Python >=3.12 (tested on 3.12 and 3.13, developed on 3.13.12)
- Async-first using `asyncio`
- Type hints on all public APIs
- Tests in `tests/` using `pytest` with async support
- All 695 tests must pass before merging to main
- Coverage must be ≥80% (`python -m pytest --cov=mcpkernel`)
- Lint clean: `ruff check src/ tests/` must show zero errors
- Format clean: `ruff format --check src/ tests/` must pass

## Build & Test
```bash
# Install (using uv)
uv venv --python 3.13
source .venv/bin/activate
uv pip install -e ".[dev]"

# Run all tests
python -m pytest tests/ -v --tb=short

# Run specific test module
python -m pytest tests/test_proxy.py -v

# Lint + Format
ruff check src/ tests/
ruff format --check src/ tests/

# Type check
mypy src/mcpkernel/
```

## Git Workflow
- `main` branch: stable, all tests passing
- `development` branch: active work, may have failing tests
- Feature branches: `feature/<description>` off development
- Bug fix branches: `fix/<description>` off development
- Always run tests before merging to main
- Use conventional commits: `feat:`, `fix:`, `docs:`, `test:`, `refactor:`, `chore:`

## Key Files
- `README.md` — Project overview and quick start
- `mkdocs.yml` — MkDocs Material documentation site config
- `docs/` — Tutorial-style documentation (25+ pages, deployed to GitHub Pages)
- `CHANGELOG.md` — Version history
- `CONTRIBUTING.md` — Contribution guidelines
- `pyproject.toml` — Project metadata and dependencies
- `policies/` — Example YAML policy files
- `src/mcpkernel/agent_manifest/` — Agent manifest loader, policy bridge, tool validator, hooks

## Documentation Site
- **Live**: https://piyushptiwari1.github.io/mcpkernel/
- **Source**: `docs/` + `mkdocs.yml`
- **Build**: `mkdocs build`
- **Auto-deploy**: `.github/workflows/docs.yml` on push to main

## Agent Team Guidelines
- When making changes, always run `python -m pytest tests/ -v --tb=short` to validate
- When fixing issues, create a test that reproduces the bug first
- When adding features, add corresponding tests
- Update `README.md` and `docs/` pages when public APIs change
- Track all work through GitHub Issues with appropriate labels

## Agent System Overview (17 agents — internal tooling only, not shipped)
- **Control**: team-lead (orchestrator), planner (spec writer)
- **Intelligence**: issue-hunter (external + internal structural scan), repo-scout, researcher, use-case-scout, contributor-booster
- **Execution**: code-improver, test-writer, test-runner
- **Quality**: code-quality-agent (lint, type check, format, coverage, compatibility — NEW Sprint 2)
- **Validation**: security-agent (hard gate), reviewer (hard gate)
- **Support**: docs-updater, docs-guardian (verifies docs against code), branch-manager (PR-only, never merges to main)
- **Meta**: agent-architect (proposal-only, read-only — now detects quality blind spots)
- Execution chain: `code-improver → test-writer → test-runner → code-quality-agent → security-agent → reviewer → docs-updater → docs-guardian → branch-manager`
- Destructive operations (file/function deletion) emit `⚠️ DESTRUCTIVE` tag and halt pipeline for human review
- `pyproject.toml` auto-grant exception: if test-runner fails with `ModuleNotFoundError`, code-improver may add the missing dependency without human gate
- Sequence lock: docs-updater always finishes before contributor-booster touches README.md
- Agent definitions live in `.github/agents/` (gitignored)
- Project board at `.agent-workspace/board.json` (gitignored)
- Monthly pipeline: `.github/workflows/monthly-agents.yml` runs all agents on 1st of each month
  - Phase 1: code-quality-agent + test-runner + issue-hunter (quality + structural scan)
  - Phase 2: docs-guardian (dynamic discovery + audit + build verify)
  - Phase 3: security-agent (deps + patterns + OWASP)
  - Phase 4: Auto-generated GitHub Issue with monthly report
  - Can also be triggered manually via `workflow_dispatch`

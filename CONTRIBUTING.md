# Contributing to mcpkernel

We welcome contributions! This document covers the development workflow.

## Development Setup

```bash
# Clone the repo
git clone https://github.com/piyushptiwari1/mcpkernel.git
cd mcpkernel

# Create virtual environment
python -m venv .venv
source .venv/bin/activate

# Install in editable mode with dev dependencies
pip install -e ".[dev,all]"

# Install pre-commit hooks
pre-commit install
```

## Running Tests

```bash
# All tests
pytest

# Unit tests only (fast)
pytest tests/unit/ -v

# With coverage
pytest --cov=mcpkernel --cov-report=term-missing

# Skip tests requiring Docker/eBPF
pytest -m "not docker and not ebpf"
```

## Code Quality

```bash
# Lint
ruff check src/ tests/

# Format
ruff format src/ tests/

# Type check
mypy src/mcpkernel/
```

## Pull Request Process

1. Fork the repo and create a feature branch from `main`.
2. Write tests for any new functionality.
3. Ensure all checks pass: `ruff check`, `mypy`, `pytest`.
4. Update documentation if applicable.
5. Open a PR with a clear description of the change.

## Commit Messages

We use [Conventional Commits](https://www.conventionalcommits.org/):

- `feat:` new feature
- `fix:` bug fix
- `docs:` documentation only
- `test:` adding/updating tests
- `refactor:` code change that neither fixes a bug nor adds a feature
- `ci:` CI/CD changes
- `chore:` maintenance

## Architecture Decision Records

For significant design decisions, add an ADR in `docs/adr/`. Use the template:

```markdown
# ADR-NNN: Title

## Status
Proposed | Accepted | Deprecated

## Context
Why is this decision needed?

## Decision
What was decided?

## Consequences
What are the trade-offs?
```

## Code of Conduct

Be respectful, constructive, and inclusive. We follow the [Contributor Covenant](https://www.contributor-covenant.org/version/2/1/code_of_conduct/).

## Documentation

MCPKernel uses [MkDocs Material](https://squidfunk.github.io/mkdocs-material/) for documentation, hosted on GitHub Pages.

- **Live site**: [https://piyushptiwari1.github.io/mcpkernel/](https://piyushptiwari1.github.io/mcpkernel/)
- **Source**: `docs/` directory + `mkdocs.yml`
- **Local preview**: `mkdocs serve` (opens at http://127.0.0.1:8000)
- **Auto-deploy**: Pushes to `main` that change `docs/**` or `mkdocs.yml` trigger automatic deployment

When changing public APIs, update the corresponding docs page in `docs/`.

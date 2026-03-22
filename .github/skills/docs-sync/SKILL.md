---
name: docs-sync
description: 'Multi-step workflow to audit MCPKernel documentation against the codebase and update README.md, docs/USAGE.md, CHANGELOG.md. Use when synchronizing documentation with code changes, auditing doc accuracy, or before releases.'
---

# Documentation Sync Workflow

## When to Use
- After a batch of code changes to sync docs
- Before preparing a release
- When public APIs have changed
- Regular documentation audits

## Procedure

### Step 1: Audit README.md
1. Read `README.md`
2. Verify:
   - Python version badge matches `pyproject.toml`
   - Quick start commands work
   - Feature list matches actual packages in `src/mcpkernel/`
   - Architecture diagram is accurate
   - All links are valid

### Step 2: Audit docs/USAGE.md
1. Read `docs/USAGE.md`
2. Cross-reference with:
   - `src/mcpkernel/config.py` for configuration options
   - `src/mcpkernel/cli.py` for CLI commands
   - `src/mcpkernel/policy/` for policy syntax
   - `policies/` for example policies
3. Verify all code examples match current API

### Step 3: Update CHANGELOG.md
1. Check git log for unreleased changes:
   ```bash
   git log --oneline --since="last tag" 
   ```
2. Categorize changes: Added, Changed, Fixed, Security
3. Add entries under `[Unreleased]` section

### Step 4: Update CONTRIBUTING.md
1. Verify build/test commands are current
2. Check that development workflow matches actual practice

### Step 5: Apply Updates
- Edit files with accurate, verified information
- Keep style consistent with existing docs
- Don't add fictional features

## References
- `README.md` — Project overview
- `docs/USAGE.md` — Usage guide
- `CHANGELOG.md` — Version history
- `CONTRIBUTING.md` — Contributor guide
- `src/mcpkernel/config.py` — Configuration reference
- `src/mcpkernel/cli.py` — CLI reference

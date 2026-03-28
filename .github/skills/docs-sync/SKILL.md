---
name: docs-sync
description: 'Multi-step workflow to audit MCPKernel documentation against the codebase and update README.md, docs/ MkDocs site, CHANGELOG.md. Use when synchronizing documentation with code changes, auditing doc accuracy, or before releases.'
---

# Documentation Sync Workflow

## When to Use
- After a batch of code changes to sync docs
- Before preparing a release
- When public APIs have changed
- Regular documentation audits
- After adding new features or CLI commands

## Documentation Site

MCPKernel uses **MkDocs Material** for documentation, hosted at:
- **Live**: https://piyushptiwari1.github.io/mcpkernel/
- **Source**: `docs/` directory + `mkdocs.yml`
- **Build**: `mkdocs build` (output in `site/`)
- **Preview**: `mkdocs serve` (http://127.0.0.1:8000)
- **Auto-deploy**: `.github/workflows/docs.yml` on push to main

## Procedure

### Step 1: Audit README.md
1. Read `README.md`
2. Verify:
   - Docs badge and link to https://piyushptiwari1.github.io/mcpkernel/
   - Python version badge matches `pyproject.toml`
   - Quick start commands work
   - Feature list matches actual packages in `src/mcpkernel/`
   - Architecture diagram is accurate
   - All links are valid
   - Test count and coverage percentage are current

### Step 2: Audit MkDocs Site (docs/)
1. Read `mkdocs.yml` for nav structure
2. For each page in `docs/`:
   - Cross-reference code examples against source files
   - Verify method signatures, parameter names, return types
   - Check CLI commands match `mcpkernel <cmd> --help` output
   - Verify import paths are correct
   - Ensure expected output examples are structurally plausible
3. Key cross-references:
   - `docs/trust/` ↔ `src/mcpkernel/trust/`
   - `docs/security/` ↔ `src/mcpkernel/security.py`
   - `docs/compliance/` ↔ `src/mcpkernel/compliance.py`
   - `docs/core/` ↔ `src/mcpkernel/policy/`, `taint/`, `sandbox/`, `dee/`, `audit/`
   - `docs/cli/` ↔ `src/mcpkernel/cli.py`
   - `docs/api/` ↔ `src/mcpkernel/api.py`

### Step 3: Update CHANGELOG.md
1. Check git log for unreleased changes:
   ```bash
   git log --oneline --since="last tag"
   ```
2. Categorize changes: Added, Changed, Fixed, Security
3. Add entries under `[Unreleased]` section

### Step 4: Update CONTRIBUTING.md
1. Verify build/test commands are current
2. Check docs section references MkDocs Material and the live site URL

### Step 5: Build and Verify
```bash
mkdocs build 2>&1  # Should have no errors
```

### Step 6: Apply Updates
- Edit files with accurate, verified information
- Keep style consistent with existing docs
- Don't add fictional features
- Always include code examples with expected output

## References
- `README.md` — Project overview
- `mkdocs.yml` — Documentation site configuration
- `docs/` — MkDocs Material pages (25+ pages)
- `CHANGELOG.md` — Version history
- `CONTRIBUTING.md` — Contributor guide
- `src/mcpkernel/config.py` — Configuration reference
- `src/mcpkernel/cli.py` — CLI reference
- `.github/workflows/docs.yml` — Auto-deploy workflow
- `.github/agents/docs-guardian.agent.md` — Documentation verification agent

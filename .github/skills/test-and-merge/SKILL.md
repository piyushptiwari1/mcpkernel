---
name: test-and-merge
description: 'Multi-step workflow to run the full MCPKernel test suite, validate code quality, and merge development branch to main when all checks pass. Use when validating changes, preparing for merge, or checking if development is ready for main.'
---

# Test and Merge Workflow

## When to Use
- Validating that all tests pass before merging
- Preparing the development branch for merge to main
- Running comprehensive quality checks

## Procedure

### Step 1: Verify Branch State
```bash
git branch
git status
git log --oneline development..HEAD  # or HEAD..development
```

### Step 2: Run Full Test Suite
```bash
python -m pytest tests/ -v --tb=short
```
- All 106+ tests must pass
- Zero failures, zero errors

### Step 3: Run Lint Check
```bash
ruff check src/ tests/
```
- No lint errors allowed

### Step 4: Verify Documentation
1. Check `CHANGELOG.md` has entries for recent changes
2. Check `README.md` is current
3. Check `docs/USAGE.md` matches current APIs

### Step 5: Merge Decision
If ALL checks pass:
```bash
git checkout main
git merge --no-ff development -m "chore: merge development to main — all tests passing"
git checkout development
```

If ANY check fails:
- Report failures with details
- Do NOT merge
- List what needs to be fixed

### Step 6: Report
```
## Merge Report
- Tests: PASS/FAIL (count)
- Lint: PASS/FAIL
- Docs: UP TO DATE / NEEDS UPDATE
- Merge: COMPLETED / BLOCKED (reason)
```

## References
- Test suite: `tests/`
- CI config: `.github/workflows/ci.yml`

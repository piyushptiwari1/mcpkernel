# Reproducible Builds

MCPKernel ships a fully pinned dependency graph so anyone — auditors,
downstream packagers, supply-chain scanners — can rebuild the exact
artifact distributed on PyPI from source.

This page documents the three primitives that make that possible:

1. **`uv.lock`** — universal lock-file pinning every transitive dependency
   to an exact version + hash.
2. **CycloneDX SBOM** — produced on every tagged release and attached to
   the GitHub Release as `mcpkernel-sbom.cdx.json` /
   `mcpkernel-sbom.cdx.xml`.
3. **Sigstore-signed DEE traces** — runtime attestations covered separately
   in `docs/trust/`.

## Prerequisites

- Python 3.12 or 3.13 (CI runs both)
- [`uv`](https://docs.astral.sh/uv/) >= 0.4

## Reproducing a development environment

```bash
# 1. Check out the exact tag you want to audit
git clone https://github.com/piyushptiwari1/mcpkernel.git
cd mcpkernel
git checkout v0.3.0

# 2. Materialise the locked environment
#    --frozen ensures uv refuses to update uv.lock — fail-closed.
uv sync --frozen --all-extras

# 3. Verify the lock-file matches pyproject.toml
uv lock --check
```

`uv sync --frozen` will reject any drift between `pyproject.toml` and
`uv.lock`. If it succeeds, the resulting `.venv/` is byte-identical (modulo
platform wheels) to the one used by CI and by maintainers.

## Reproducing the wheel

```bash
# Build the same artifact PyPI serves
python -m build --wheel --sdist

# Compare hashes against the SBOM and the PyPI release page
sha256sum dist/*
```

The `release.yml` workflow runs `python -m build` inside a clean
GitHub-hosted runner; no maintainer machine ever touches a published
artifact.

## Verifying the SBOM

Every tagged release attaches a CycloneDX 1.6 SBOM to the GitHub Release.
Download it and run any CycloneDX-compatible scanner:

```bash
gh release download v0.3.0 -p "mcpkernel-sbom.cdx.json"

# Example: feed it to Grype for CVE matching
grype sbom:mcpkernel-sbom.cdx.json

# Or to cyclonedx-cli to validate the schema
cyclonedx validate --input-file mcpkernel-sbom.cdx.json
```

The SBOM is generated from the **installed** environment used to build the
wheel, so it captures the exact transitive closure pinned by `uv.lock`.

## Updating dependencies

When you legitimately need to bump a dependency:

```bash
# 1. Edit pyproject.toml
# 2. Regenerate the lockfile
uv lock

# 3. Verify the resolved environment still works
uv sync --frozen --all-extras
pytest tests/

# 4. Commit BOTH pyproject.toml and uv.lock in the same commit
git add pyproject.toml uv.lock
git commit -m "chore: bump <package> to <version>"
```

Never commit `pyproject.toml` changes without the matching `uv.lock`
update — CI will reject the PR.

## eBPF note

The `ebpf` extra is intentionally empty on PyPI. The underlying `bcc`
Python binding is distributed only as an OS package
(`apt install python3-bpfcc` on Debian/Ubuntu, equivalent elsewhere) and
is not resolvable by `uv lock`. eBPF features become available at runtime
if the system package is present; otherwise MCPKernel degrades gracefully.

## Related

- [`CHANGELOG.md`](../../CHANGELOG.md) — per-release dependency deltas
- [Release workflow](../../.github/workflows/release.yml) — SBOM generation
- [`docs/trust/`](../trust/) — runtime attestation chain

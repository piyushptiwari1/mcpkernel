# Installation

## Requirements

- Python 3.12 or newer
- pip or uv package manager

## Install from PyPI

=== "pip"

    ```bash
    pip install mcpkernel
    ```

=== "pip (all extras)"

    ```bash
    pip install "mcpkernel[all]"
    ```

=== "uv"

    ```bash
    uv pip install mcpkernel
    ```

## Install from Source

```bash
git clone https://github.com/piyushptiwari1/mcpkernel.git
cd mcpkernel
pip install -e ".[dev]"
```

## Verify Installation

```bash
mcpkernel version
```

Expected output:

```
mcpkernel 0.1.3
```

## Initialize a Project

Run `mcpkernel init` to set up configuration files in your project:

```bash
cd your-project/
mcpkernel init --preset standard
```

Expected output:

```
✓ Initialized MCPKernel in .mcpkernel (preset: standard)
  Config: .mcpkernel/config.yaml
  Policies: .mcpkernel/policies
  Preset: standard — Block known-dangerous patterns, audit the rest.

Next steps:
  1. Add an upstream MCP server:
     mcpkernel add-server myserver http://localhost:3000/mcp
  2. Start the proxy:
     mcpkernel serve -c .mcpkernel/config.yaml
```

This creates:

```
.mcpkernel/
├── config.yaml          # Main configuration
└── policies/
    └── default.yaml     # Policy rules from your preset
```

## What the Presets Do

| Preset | Default Action | Description |
|--------|---------------|-------------|
| `permissive` | `allow` | Audit everything, block nothing. Good for development. |
| `standard` | `audit` | Block known-dangerous patterns, audit the rest. |
| `strict` | `deny` | Deny-by-default. Only explicitly allowed tools pass. |

```bash
# See all presets and their rules
mcpkernel presets
```

Expected output:

```
Available policy presets:
==================================================

  permissive
  Audit everything, block nothing. Good for development.
    [  audit] Audit all tool calls

  standard
  Block known-dangerous patterns, audit the rest.
    [   deny] Block shell execution
    [   deny] Block path traversal
    [  audit] Audit external API calls

  strict
  Deny-by-default. Only explicitly allowed tools pass.
    [   deny] Block all uncategorized tools
    [   deny] Block shell execution
    [   deny] Block path traversal
    [   deny] Block external network
```

## Next Steps

Once installed, follow the [Quick Start](quickstart.md) guide to run your first secured tool call.

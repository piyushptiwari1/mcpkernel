# MCPKernel VS Code Extension

Security gateway management for AI agent tool calls — right from your editor.

## Features

- **Policy Validation** — Real-time YAML validation for policy files with JSON Schema
- **Gateway Management** — Start/stop the MCPKernel proxy from the command palette
- **Taint Scanning** — Right-click any Python file to scan for secrets, PII, and API keys
- **Audit Viewer** — Query audit logs in CEF, JSON, CSV, or table format
- **Trace Explorer** — List and inspect deterministic execution envelopes
- **Status Bar** — See gateway status at a glance
- **Auto-Validation** — Policy files are validated on save
- **YAML Autocomplete** — Full schema support for `config.yaml` and policy files

## Commands

| Command | Description |
|---------|-------------|
| `MCPKernel: Initialize Project` | Create `.mcpkernel/` with config and policies |
| `MCPKernel: Start Gateway` | Start the security proxy server |
| `MCPKernel: Stop Gateway` | Stop the running gateway |
| `MCPKernel: Show Status` | Display current configuration |
| `MCPKernel: Validate Policy File` | Validate the active YAML policy |
| `MCPKernel: Taint Scan Current File` | Run static taint analysis |
| `MCPKernel: Query Audit Logs` | View audit entries |
| `MCPKernel: List Execution Traces` | Browse DEE traces |
| `MCPKernel: Add Upstream Server` | Add an MCP server to proxy |

## Requirements

- [MCPKernel](https://pypi.org/project/mcpkernel/) installed: `pip install mcpkernel`
- [YAML extension](https://marketplace.visualstudio.com/items?itemName=redhat.vscode-yaml) (auto-installed as dependency)

## Setup

```bash
pip install mcpkernel
```

Then open any project and run `MCPKernel: Initialize Project` from the command palette (Ctrl+Shift+P).

## Building from Source

```bash
cd vscode-extension
npm install
npm run compile
```

To package as VSIX:
```bash
npx @vscode/vsce package
```

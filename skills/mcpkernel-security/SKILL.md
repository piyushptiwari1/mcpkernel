---
name: mcpkernel-security
description: AI agent security gateway — policy enforcement, taint tracking, tool poisoning detection, DLP chain analysis, and SARIF output for CI/CD.
version: 0.1.3
author: piyushptiwari1
repository: https://github.com/piyushptiwari1/mcpkernel
license: Apache-2.0
tags:
  - security
  - mcp
  - taint-tracking
  - policy-engine
  - owasp
  - dlp
  - tool-poisoning
  - sarif
metadata:
  openclaw:
    requires:
      bins:
        - mcpkernel
      env: []
    primaryEnv: ""
    mcp:
      servers:
        mcpkernel:
          command: mcpkernel
          args:
            - mcp-serve
---

# MCPKernel Security Skill

The security kernel for AI agents. MCPKernel provides deterministic, policy-enforced security for every MCP tool call.

## What it does

When installed, MCPKernel gives you these security tools:

### `mcpkernel_scan_tool`
Scan any MCP tool's description for prompt injection, poisoning, shadowing, and Unicode obfuscation attacks.

**Example:**
> "Scan the filesystem tool for poisoning attacks"

### `mcpkernel_validate_policy`
Validate MCPKernel YAML policy files for syntax and rule correctness.

**Example:**
> "Validate my policy at policies/strict.yaml"

### `mcpkernel_discover_configs`
Auto-discover MCP server configurations across all installed IDE clients (Claude Desktop, Cursor, VS Code, Windsurf, OpenClaw, Zed, etc.) and flag security issues like exposed secrets.

**Example:**
> "Discover all my MCP server configs and check for security issues"

### `mcpkernel_check_taint`
Analyze text for sensitive data — PII, secrets, API keys, user input.

**Example:**
> "Check this text for sensitive data: my email is john@example.com and my key is sk-abc123"

### `mcpkernel_scan_skill`
Scan OpenClaw SKILL.md files for dangerous shell commands, exfiltration patterns, hidden instructions, and metadata mismatches.

**Example:**
> "Scan the skills/my-skill/SKILL.md for security issues"

### `mcpkernel_doctor`
Run full MCPKernel health diagnostics — check config, dependencies, exposed secrets, file permissions, and available tools.

**Example:**
> "Run MCPKernel doctor to check my setup"

## Installation

```bash
# Install MCPKernel
pip install mcpkernel

# Install in OpenClaw
mcpkernel install --target openclaw
```

Or add directly to your OpenClaw config:

```json
{
  "mcp": {
    "servers": {
      "mcpkernel": {
        "command": "mcpkernel",
        "args": ["mcp-serve"]
      }
    }
  }
}
```

## Key Features

- **OWASP ASI 2026 compliant** policy engine with YAML rules
- **Multi-mode taint tracking** (PII, secrets, user input, external data)
- **Tool poisoning detection** with 10+ injection pattern rules
- **DLP chain detection** (e.g., read_file(.env) → http_post = blocked)
- **SARIF v2.1.0 output** for GitHub Code Scanning / Azure DevOps
- **Multi-backend sandboxing** (Docker, Firecracker, WASM, Microsandbox)
- **Deterministic Execution Envelopes** (Sigstore-signed, replayable)
- **Tamper-proof audit logs** with SIEM export (CEF, JSONL, CSV)
- **eBPF syscall monitoring** at kernel level

## Links

- [GitHub](https://github.com/piyushptiwari1/mcpkernel)
- [PyPI](https://pypi.org/project/mcpkernel/)
- [Documentation](https://github.com/piyushptiwari1/mcpkernel/blob/main/docs/USAGE.md)

# Host integrations

MCPKernel works with every MCP-compatible host. The pattern is always
the same:

1. Run MCPKernel as a local proxy (`mcpkernel serve`).
2. Configure the host to point its MCP transport at
   `http://127.0.0.1:8080/mcp`.
3. List the real upstream MCP servers in `.mcpkernel/config.yaml`.

The host never talks to the real servers directly. Every call goes
through MCPKernel's pipeline:

```
host  →  mcpkernel  →  policy  →  taint  →  sandbox  →  upstream
                                            ↓
                                  DEE + audit + observability
```

## Walk-throughs

| Host                              | Transport          | Example                                                          |
| --------------------------------- | ------------------ | ---------------------------------------------------------------- |
| Claude Desktop                    | `mcp-remote` shim  | [`examples/hosts/claude_desktop/`](../../examples/hosts/claude_desktop/) |
| Claude Code (CLI)                 | http               | [`examples/hosts/claude_code/`](../../examples/hosts/claude_code/) |
| VS Code GitHub Copilot Chat       | http               | [`examples/hosts/vscode_copilot/`](../../examples/hosts/vscode_copilot/) |
| Cursor                            | http               | [`examples/hosts/cursor/`](../../examples/hosts/cursor/) |
| Agent-to-Agent (A2A)              | http (bidirectional) | [`examples/hosts/a2a_bridge/`](../../examples/hosts/a2a_bridge/) |

For the other hosts MCPKernel supports out-of-the-box (Windsurf, Zed,
Goose, OpenClaw), use the one-line installer:

```bash
mcpkernel install <host>      # writes the host's MCP config for you
mcpkernel install --help      # full list of supported targets
```

## Recommended hardening for any host

Every walk-through ends with the same checklist. Once you have a host
talking to MCPKernel:

- [ ] `MCPKERNEL_AUTH__METHOD=oauth2` and `MCPKERNEL_AUTH__REQUIRE_RESOURCE=true`
      — enforce RFC 8707 resource-bound tokens.
- [ ] `MCPKERNEL_SANDBOX__BACKEND=docker` (or `firecracker`/`wasm`) —
      never run tool code on the host.
- [ ] `MCPKERNEL_TAINT__MODE=full` — flow analysis on every argument and
      return value.
- [ ] `MCPKERNEL_DEE__ENABLED=true` plus `MCPKERNEL_DEE__SIGN=true` in
      CI — Sigstore-signed, replayable transcripts.
- [ ] `MCPKERNEL_HEALTH_TOKEN=$(mcpkernel gen-token)` — only authenticated
      monitoring may scrape `/health/secret`.
- [ ] Promote from `policies/minimal.yaml` to
      [`policies/owasp_asi_2026_strict.yaml`](../../policies/owasp_asi_2026_strict.yaml)
      or
      [`policies/owasp_llm_top10_2025.yaml`](../../policies/owasp_llm_top10_2025.yaml).

## Troubleshooting

| Symptom                              | Likely cause                                  |
| ------------------------------------ | --------------------------------------------- |
| Host shows "Connection refused"      | `mcpkernel serve` not running, or wrong port  |
| Host lists zero tools                | `upstream:` in config.yaml is empty or wrong  |
| `policy_denied` on a tool you expect | Check `mcpkernel audit query --limit 5`       |
| OAuth fails with `aud` claim error   | `MCPKERNEL_AUTH__RESOURCE` doesn't match IdP  |

Run `mcpkernel doctor` for a comprehensive diagnostic.

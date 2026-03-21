# Security Policy

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| 0.1.x   | :white_check_mark: |

## Reporting a Vulnerability

MCPGuard is a security-focused project, and we take vulnerability reports seriously.

**DO NOT open a public GitHub issue for security vulnerabilities.**

Instead, please report vulnerabilities through one of these channels:

### GitHub Security Advisories (Preferred)

1. Go to [Security Advisories](https://github.com/piyushptiwari1/mcpguard/security/advisories/new)
2. Click "Report a vulnerability"
3. Fill in the details

### Email

Send details to the maintainers via GitHub's private contact mechanism on the repository.

## What to Include

- Description of the vulnerability
- Steps to reproduce
- Affected component(s): proxy, policy, taint, sandbox, dee, audit, context, ebpf, observability, cli
- Impact assessment (what an attacker could do)
- Suggested fix (if you have one)

## Response Timeline

- **Acknowledgment**: Within 48 hours
- **Assessment**: Within 1 week
- **Fix**: Depends on severity
  - Critical: Within 72 hours
  - High: Within 1 week
  - Medium: Within 2 weeks
  - Low: Next release cycle

## Disclosure Policy

- We follow coordinated disclosure
- We will credit reporters in the CHANGELOG (unless anonymity is requested)
- We will publish a security advisory once a fix is available
- We ask reporters to allow us reasonable time to fix before public disclosure

## Scope

The following are in scope for security reports:

- Policy bypass (tool calls evading policy checks)
- Taint tracking evasion (secrets/PII leaking through untracked paths)
- Sandbox escape (code execution outside sandbox boundaries)
- Audit log tampering or bypass
- DEE signature forgery or replay attacks
- Proxy authentication/authorization bypass
- Injection attacks through MCP messages
- Denial of service against the proxy gateway

## Out of Scope

- Vulnerabilities in upstream dependencies (report to the respective project)
- Issues requiring physical access to the host machine
- Social engineering attacks

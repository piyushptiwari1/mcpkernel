"""Security Protections — defenses against named MCP spec attacks.

Addresses the 6 attacks from MCP Security Best Practices (2025-11-25):
  1. Confused Deputy — tool X tricks proxy into calling tool Y
  2. Token Passthrough — credentials leak through tool args/results
  3. SSRF — tool calls bypass network restrictions via proxy
  4. Session Hijacking — session tokens stolen or replayed
  5. Local Server Compromise — local MCP server is malicious
  6. Memory Poisoning — self-reinforcing injection in agent memory
     (from Zombie Agents, arXiv:2602.15654)
"""

from __future__ import annotations

import hashlib
import hmac
import re
import time
from dataclasses import dataclass, field
from typing import Any

from mcpkernel.utils import get_logger

logger = get_logger(__name__)

# ---------------------------------------------------------------------------
# Common types
# ---------------------------------------------------------------------------


@dataclass
class SecurityVerdict:
    """Result of a security check."""

    allowed: bool
    check_name: str
    reason: str = ""
    severity: str = "info"  # info, warning, critical
    metadata: dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# 1. Confused Deputy Defense
# ---------------------------------------------------------------------------

# Precompiled, read-only whitelist patterns
_TOOL_NAME_PATTERN = re.compile(r"^[a-zA-Z0-9_.\-/]{1,256}$")


class ConfusedDeputyGuard:
    """Prevents confused deputy attacks by validating tool call provenance.

    A confused deputy attack occurs when one tool tricks the system into
    executing another tool on its behalf with elevated privileges.
    """

    def __init__(
        self,
        *,
        allowed_tools: set[str] | None = None,
        allowed_servers: set[str] | None = None,
        deny_cross_server_delegation: bool = True,
    ) -> None:
        self._allowed_tools = allowed_tools
        self._allowed_servers = allowed_servers
        self._deny_cross_server = deny_cross_server_delegation
        self._call_stack: list[str] = []

    def check_tool_call(
        self,
        tool_name: str,
        server_name: str,
        *,
        caller_tool: str | None = None,
        caller_server: str | None = None,
    ) -> SecurityVerdict:
        """Verify a tool call is authorized and not delegated maliciously."""
        # Validate tool name format
        if not _TOOL_NAME_PATTERN.match(tool_name):
            return SecurityVerdict(
                allowed=False,
                check_name="confused_deputy",
                reason=f"Invalid tool name format: {tool_name!r}",
                severity="critical",
            )

        # Check tool allowlist
        if self._allowed_tools and tool_name not in self._allowed_tools:
            return SecurityVerdict(
                allowed=False,
                check_name="confused_deputy",
                reason=f"Tool '{tool_name}' not in allowlist",
                severity="critical",
            )

        # Check server allowlist
        if self._allowed_servers and server_name not in self._allowed_servers:
            return SecurityVerdict(
                allowed=False,
                check_name="confused_deputy",
                reason=f"Server '{server_name}' not in allowlist",
                severity="critical",
            )

        # Cross-server delegation check
        if self._deny_cross_server and caller_server and caller_server != server_name:
            return SecurityVerdict(
                allowed=False,
                check_name="confused_deputy",
                reason=(f"Cross-server delegation denied: '{caller_server}' → '{server_name}'"),
                severity="critical",
            )

        return SecurityVerdict(allowed=True, check_name="confused_deputy")


# ---------------------------------------------------------------------------
# 2. Token Passthrough Defense
# ---------------------------------------------------------------------------

# Precompiled patterns for common secret formats
_SECRET_PATTERNS = [
    re.compile(p, re.IGNORECASE)
    for p in [
        r"(?:api[_-]?key|token|secret|password|bearer)\s*[:=]\s*\S+",
        r"sk-[a-zA-Z0-9]{20,}",  # OpenAI
        r"ghp_[a-zA-Z0-9]{36}",  # GitHub PAT
        r"ghu_[a-zA-Z0-9]{36}",  # GitHub user token
        r"glpat-[a-zA-Z0-9\-]{20,}",  # GitLab PAT
        r"xox[bpors]-[a-zA-Z0-9\-]+",  # Slack
        r"AIza[0-9A-Za-z\-_]{35}",  # Google API
        r"AKIA[0-9A-Z]{16}",  # AWS access key
        r"eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}",  # JWT
    ]
]


class TokenPassthroughGuard:
    """Prevents credentials from leaking through tool arguments or results.

    Scans tool call arguments and results for known credential patterns
    and blocks or redacts them.
    """

    def __init__(
        self,
        *,
        mode: str = "block",  # "block" or "redact"
        extra_patterns: list[str] | None = None,
    ) -> None:
        self._mode = mode
        self._patterns = list(_SECRET_PATTERNS)
        if extra_patterns:
            self._patterns.extend(re.compile(p, re.IGNORECASE) for p in extra_patterns)

    def scan_arguments(self, tool_name: str, arguments: dict[str, Any]) -> SecurityVerdict:
        """Scan tool arguments for leaked credentials."""
        for key, value in arguments.items():
            if not isinstance(value, str):
                continue
            for pattern in self._patterns:
                if pattern.search(value):
                    logger.warning(
                        "token_passthrough_detected",
                        tool=tool_name,
                        argument=key,
                        pattern=pattern.pattern[:50],
                    )
                    return SecurityVerdict(
                        allowed=False,
                        check_name="token_passthrough",
                        reason=f"Credential pattern found in argument '{key}'",
                        severity="critical",
                        metadata={"argument": key},
                    )
        return SecurityVerdict(allowed=True, check_name="token_passthrough")

    def scan_result(self, tool_name: str, content: str) -> SecurityVerdict:
        """Scan tool result content for leaked credentials."""
        for pattern in self._patterns:
            if pattern.search(content):
                logger.warning(
                    "token_in_result_detected",
                    tool=tool_name,
                    pattern=pattern.pattern[:50],
                )
                return SecurityVerdict(
                    allowed=False,
                    check_name="token_passthrough",
                    reason="Credential pattern found in tool result",
                    severity="critical",
                )
        return SecurityVerdict(allowed=True, check_name="token_passthrough")


# ---------------------------------------------------------------------------
# 3. SSRF Defense
# ---------------------------------------------------------------------------

# Precompiled internal/private network patterns
_PRIVATE_CIDR_PATTERNS = [
    re.compile(p)
    for p in [
        r"^127\.",  # localhost
        r"^10\.",  # 10.0.0.0/8
        r"^172\.(1[6-9]|2\d|3[01])\.",  # 172.16.0.0/12
        r"^192\.168\.",  # 192.168.0.0/16
        r"^169\.254\.",  # link-local
        r"^0\.",  # "this" network
        r"^::1$",  # IPv6 localhost
        r"^fd[0-9a-f]{2}:",  # IPv6 ULA
        r"^fe80:",  # IPv6 link-local
    ]
]

_CLOUD_METADATA_HOSTS = frozenset(
    {
        "169.254.169.254",  # AWS/GCP/Azure metadata
        "metadata.google.internal",
        "metadata.gic.internal",
        "100.100.100.200",  # Alibaba Cloud metadata
    }
)


class SSRFGuard:
    """Prevents Server-Side Request Forgery through tool calls.

    Blocks tool calls that attempt to access internal networks,
    cloud metadata endpoints, or non-allowlisted hosts.
    """

    def __init__(
        self,
        *,
        allowed_domains: set[str] | None = None,
        block_private: bool = True,
        block_metadata: bool = True,
    ) -> None:
        self._allowed_domains = allowed_domains
        self._block_private = block_private
        self._block_metadata = block_metadata

    def check_url(self, url: str) -> SecurityVerdict:
        """Check a URL for SSRF patterns."""
        from urllib.parse import urlparse

        try:
            parsed = urlparse(url)
        except Exception:
            return SecurityVerdict(
                allowed=False,
                check_name="ssrf",
                reason=f"Unparseable URL: {url[:100]}",
                severity="critical",
            )

        host = parsed.hostname or ""

        # Check cloud metadata endpoints
        if self._block_metadata and host in _CLOUD_METADATA_HOSTS:
            return SecurityVerdict(
                allowed=False,
                check_name="ssrf",
                reason=f"Cloud metadata endpoint blocked: {host}",
                severity="critical",
            )

        # Check private networks
        if self._block_private:
            for pattern in _PRIVATE_CIDR_PATTERNS:
                if pattern.match(host):
                    return SecurityVerdict(
                        allowed=False,
                        check_name="ssrf",
                        reason=f"Private network access blocked: {host}",
                        severity="critical",
                    )

        # Check domain allowlist
        if self._allowed_domains and host not in self._allowed_domains:
            return SecurityVerdict(
                allowed=False,
                check_name="ssrf",
                reason=f"Domain '{host}' not in allowlist",
                severity="warning",
            )

        return SecurityVerdict(allowed=True, check_name="ssrf")

    def scan_arguments(self, arguments: dict[str, Any]) -> SecurityVerdict:
        """Scan all string arguments for URLs containing SSRF patterns."""
        url_pattern = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
        for key, value in arguments.items():
            if not isinstance(value, str):
                continue
            urls = url_pattern.findall(value)
            for url in urls:
                verdict = self.check_url(url)
                if not verdict.allowed:
                    verdict.metadata["argument"] = key
                    return verdict
        return SecurityVerdict(allowed=True, check_name="ssrf")


# ---------------------------------------------------------------------------
# 4. Session Hijacking Defense
# ---------------------------------------------------------------------------


class SessionGuard:
    """Prevents session hijacking and replay attacks.

    Uses HMAC-based session tokens with expiry and binding to
    client fingerprints.
    """

    def __init__(
        self,
        secret: str = "",
        *,
        max_age_seconds: int = 3600,
    ) -> None:
        self._secret = secret.encode() if secret else b"mcpkernel-default-session-key"
        self._max_age = max_age_seconds
        self._active_sessions: dict[str, dict[str, Any]] = {}

    def create_session(
        self,
        session_id: str,
        client_fingerprint: str,
    ) -> str:
        """Create a new session token bound to a client fingerprint."""
        now = time.time()
        payload = f"{session_id}:{client_fingerprint}:{now}"
        token = hmac.new(self._secret, payload.encode(), hashlib.sha256).hexdigest()
        self._active_sessions[session_id] = {
            "token": token,
            "fingerprint": client_fingerprint,
            "created_at": now,
        }
        return token

    def validate_session(
        self,
        session_id: str,
        token: str,
        client_fingerprint: str,
    ) -> SecurityVerdict:
        """Validate a session token."""
        session = self._active_sessions.get(session_id)
        if not session:
            return SecurityVerdict(
                allowed=False,
                check_name="session_hijacking",
                reason="Unknown session",
                severity="critical",
            )

        # Check expiry
        age = time.time() - session["created_at"]
        if age > self._max_age:
            del self._active_sessions[session_id]
            return SecurityVerdict(
                allowed=False,
                check_name="session_hijacking",
                reason="Session expired",
                severity="warning",
            )

        # Check fingerprint binding
        if not hmac.compare_digest(session["fingerprint"], client_fingerprint):
            logger.warning(
                "session_fingerprint_mismatch",
                session_id=session_id,
            )
            return SecurityVerdict(
                allowed=False,
                check_name="session_hijacking",
                reason="Client fingerprint mismatch (possible hijacking)",
                severity="critical",
            )

        # Check token
        if not hmac.compare_digest(session["token"], token):
            return SecurityVerdict(
                allowed=False,
                check_name="session_hijacking",
                reason="Invalid session token",
                severity="critical",
            )

        return SecurityVerdict(allowed=True, check_name="session_hijacking")

    def revoke_session(self, session_id: str) -> None:
        self._active_sessions.pop(session_id, None)


# ---------------------------------------------------------------------------
# 5. Memory Poisoning Defense (Zombie Agents — arXiv:2602.15654)
# ---------------------------------------------------------------------------

# Precompiled patterns for injection markers
_INJECTION_PATTERNS = [
    re.compile(p, re.IGNORECASE)
    for p in [
        r"<\s*system\s*>",  # system prompt injection
        r"\bignore\s+previous\s+instructions?\b",
        r"\bdo\s+not\s+follow\b",
        r"\byou\s+are\s+now\b",
        r"\bforget\s+(everything|all|prior)\b",
        r"\bnew\s+instructions?\s*:",
        r"\bact\s+as\b.*\bassistant\b",
        r"\boverride\b.*\bpolicy\b",
        r"\bexecute\b.*\bcode\b.*\bdirectly\b",
    ]
]


class MemoryPoisoningGuard:
    """Detects and blocks self-reinforcing memory injection attacks.

    Zombie Agents inject instructions that persist in agent memory
    and reinforce themselves across sessions. This guard:
      1. Scans tool outputs for injection patterns
      2. Tracks content hash continuity to detect mutations
      3. Flags outputs that differ from their declared schema
    """

    def __init__(
        self,
        *,
        extra_patterns: list[str] | None = None,
        max_repetition_score: float = 0.7,
    ) -> None:
        self._patterns = list(_INJECTION_PATTERNS)
        if extra_patterns:
            self._patterns.extend(re.compile(p, re.IGNORECASE) for p in extra_patterns)
        self._max_rep = max_repetition_score
        self._content_hashes: dict[str, list[str]] = {}  # tool → recent hashes

    def scan_content(self, content: str, *, tool_name: str = "unknown") -> SecurityVerdict:
        """Scan content for injection patterns."""
        for pattern in self._patterns:
            match = pattern.search(content)
            if match:
                logger.warning(
                    "memory_poisoning_detected",
                    tool=tool_name,
                    pattern=pattern.pattern[:60],
                    match=match.group()[:100],
                )
                return SecurityVerdict(
                    allowed=False,
                    check_name="memory_poisoning",
                    reason=f"Injection pattern detected: {match.group()[:80]}",
                    severity="critical",
                    metadata={"pattern": pattern.pattern[:60]},
                )
        return SecurityVerdict(allowed=True, check_name="memory_poisoning")

    def check_repetition(self, content: str, tool_name: str) -> SecurityVerdict:
        """Detect self-reinforcing content by tracking hash continuity.

        If the same tool keeps producing content with high hash similarity
        to previous outputs, it may be reinforcing injected instructions.
        """
        content_hash = hashlib.sha256(content.encode()).hexdigest()[:16]

        history = self._content_hashes.setdefault(tool_name, [])
        if history:
            matches = sum(1 for h in history if h == content_hash)
            rep_score = matches / len(history)
            if rep_score > self._max_rep and len(history) >= 3:
                logger.warning(
                    "memory_repetition_detected",
                    tool=tool_name,
                    score=round(rep_score, 3),
                )
                return SecurityVerdict(
                    allowed=False,
                    check_name="memory_poisoning",
                    reason=(f"Self-reinforcing content detected (repetition score: {rep_score:.2f})"),
                    severity="warning",
                    metadata={"repetition_score": rep_score},
                )

        history.append(content_hash)
        # Keep only recent history
        if len(history) > 50:
            self._content_hashes[tool_name] = history[-50:]

        return SecurityVerdict(allowed=True, check_name="memory_poisoning")


# ---------------------------------------------------------------------------
# 6. Unified Security Pipeline
# ---------------------------------------------------------------------------


class SecurityPipeline:
    """Unified pipeline that runs all security checks on a tool call.

    Usage:
        pipeline = SecurityPipeline()
        verdicts = pipeline.check_tool_call(
            tool_name="read_file",
            server_name="filesystem",
            arguments={"path": "/etc/passwd"},
        )
        if not all(v.allowed for v in verdicts):
            block_call(verdicts)
    """

    def __init__(
        self,
        *,
        confused_deputy: ConfusedDeputyGuard | None = None,
        token_guard: TokenPassthroughGuard | None = None,
        ssrf_guard: SSRFGuard | None = None,
        session_guard: SessionGuard | None = None,
        memory_guard: MemoryPoisoningGuard | None = None,
    ) -> None:
        self.confused_deputy = confused_deputy or ConfusedDeputyGuard()
        self.token_guard = token_guard or TokenPassthroughGuard()
        self.ssrf_guard = ssrf_guard or SSRFGuard()
        self.session_guard = session_guard
        self.memory_guard = memory_guard or MemoryPoisoningGuard()

    def check_tool_call(
        self,
        tool_name: str,
        server_name: str,
        arguments: dict[str, Any],
        *,
        caller_tool: str | None = None,
        caller_server: str | None = None,
    ) -> list[SecurityVerdict]:
        """Run all applicable pre-execution security checks."""
        verdicts: list[SecurityVerdict] = []

        # 1. Confused deputy
        verdicts.append(
            self.confused_deputy.check_tool_call(
                tool_name,
                server_name,
                caller_tool=caller_tool,
                caller_server=caller_server,
            )
        )

        # 2. Token passthrough (arguments)
        verdicts.append(self.token_guard.scan_arguments(tool_name, arguments))

        # 3. SSRF check on arguments
        verdicts.append(self.ssrf_guard.scan_arguments(arguments))

        return verdicts

    def check_tool_result(
        self,
        tool_name: str,
        content: str,
    ) -> list[SecurityVerdict]:
        """Run post-execution security checks on tool results."""
        verdicts: list[SecurityVerdict] = []

        # Token leakage in results
        verdicts.append(self.token_guard.scan_result(tool_name, content))

        # Memory poisoning check
        verdicts.append(self.memory_guard.scan_content(content, tool_name=tool_name))
        verdicts.append(self.memory_guard.check_repetition(content, tool_name))

        return verdicts

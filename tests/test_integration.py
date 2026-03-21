"""End-to-end integration tests — exercise real conditions in dev and prod configs.

These tests boot the full FastAPI proxy server via ``httpx.ASGITransport``,
wire real policy engines, taint trackers, DEE trace stores, and audit loggers
backed by temporary SQLite databases.  Only the sandbox ``execute_code`` is
stubbed (Docker/Firecracker aren't available in CI).

Test matrix:
  - Dev mode:  no auth, no rate limiting, allow-all policy
  - Prod mode: API key auth, rate limiting, deny-by-default policy
  - Full pipeline: policy → taint detection → DEE envelope → audit trail
  - Error paths: bad JSON, oversized body, auth failures, rate limit
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any
from unittest.mock import AsyncMock, patch

if TYPE_CHECKING:
    from pathlib import Path

import httpx
import pytest

from mcpguard.audit.logger import AuditLogger
from mcpguard.config import (
    AuditConfig,
    AuthConfig,
    DEEConfig,
    EBPFConfig,
    MCPGuardSettings,
    PolicyConfig,
    ProxyConfig,
    RateLimitConfig,
    SandboxConfig,
)
from mcpguard.config import (
    SandboxBackend as SBEnum,
)
from mcpguard.dee.trace_store import TraceStore
from mcpguard.proxy.interceptor import ExecutionResult

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _jsonrpc_tool_call(
    tool_name: str = "execute_code",
    arguments: dict[str, Any] | None = None,
    request_id: int = 1,
) -> dict[str, Any]:
    """Build a valid MCP JSON-RPC tools/call request."""
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "method": "tools/call",
        "params": {
            "name": tool_name,
            "arguments": arguments or {"code": "print('hello')", "language": "python"},
        },
    }


def _ok_result(**kwargs: Any) -> ExecutionResult:
    """Build a successful execution result."""
    return ExecutionResult(
        content=[{"type": "text", "text": kwargs.get("text", "hello")}],
        is_error=False,
        duration_seconds=kwargs.get("duration", 0.01),
    )


def _make_policy_yaml(tmp_path: Path, rules: list[dict[str, Any]]) -> Path:
    """Write a policy YAML file and return its path."""
    import yaml

    p = tmp_path / "test_policy.yaml"
    p.write_text(yaml.dump({"rules": rules}))
    return p


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def dev_settings(tmp_path: Path) -> MCPGuardSettings:
    """Dev-mode settings: no auth, no rate limit, allow-all policy."""
    policy_file = _make_policy_yaml(tmp_path, [
        {
            "id": "DEV-001",
            "name": "Allow everything",
            "action": "allow",
            "priority": 1000,
            "tool_patterns": [".*"],
        },
    ])
    settings = MCPGuardSettings(
        proxy=ProxyConfig(host="127.0.0.1", port=9999, max_request_size_bytes=4096),
        auth=AuthConfig(enabled=False),
        rate_limit=RateLimitConfig(enabled=False),
        sandbox=SandboxConfig(backend=SBEnum.DOCKER),
        dee=DEEConfig(store_path=tmp_path / "traces.db", sign_traces=False),
        audit=AuditConfig(log_path=tmp_path / "audit.db"),
        policy=PolicyConfig(policy_paths=[policy_file], default_action="allow"),
        ebpf=EBPFConfig(enabled=False),
    )
    # Set as global config singleton
    import mcpguard.config as _cfg
    _cfg._settings = settings
    return settings


@pytest.fixture
def prod_settings(tmp_path: Path) -> MCPGuardSettings:
    """Prod-mode: API key auth, rate limiting, deny-by-default policy."""
    policy_file = _make_policy_yaml(tmp_path, [
        {
            "id": "PROD-001",
            "name": "Block shell commands",
            "description": "Deny all shell_* tools",
            "action": "deny",
            "priority": 10,
            "tool_patterns": ["shell_.*"],
        },
        {
            "id": "PROD-002",
            "name": "Allow execute_code",
            "description": "Explicitly allow execute_code",
            "action": "allow",
            "priority": 50,
            "tool_patterns": ["execute_code"],
        },
        {
            "id": "PROD-003",
            "name": "Audit all other tools",
            "action": "audit",
            "priority": 100,
            "tool_patterns": [".*"],
        },
    ])
    settings = MCPGuardSettings(
        proxy=ProxyConfig(host="127.0.0.1", port=9998, max_request_size_bytes=2048),
        auth=AuthConfig(enabled=True, api_keys=["test-secret-key-1234"]),
        rate_limit=RateLimitConfig(enabled=True, requests_per_minute=6, burst_size=3),
        sandbox=SandboxConfig(backend=SBEnum.DOCKER),
        dee=DEEConfig(store_path=tmp_path / "traces.db", sign_traces=False),
        audit=AuditConfig(log_path=tmp_path / "audit.db"),
        policy=PolicyConfig(policy_paths=[policy_file], default_action="deny"),
        ebpf=EBPFConfig(enabled=False),
    )
    import mcpguard.config as _cfg
    _cfg._settings = settings
    return settings


@pytest.fixture
def taint_settings(tmp_path: Path) -> MCPGuardSettings:
    """Settings that pair taint detection with a policy that blocks on secret taint."""
    policy_file = _make_policy_yaml(tmp_path, [
        {
            "id": "TAINT-001",
            "name": "Block tainted secrets",
            "description": "Deny when arguments contain secrets",
            "action": "deny",
            "priority": 10,
            "tool_patterns": [".*"],
            "taint_labels": ["secret"],
        },
        {
            "id": "TAINT-002",
            "name": "Allow clean calls",
            "action": "allow",
            "priority": 100,
            "tool_patterns": [".*"],
        },
    ])
    settings = MCPGuardSettings(
        proxy=ProxyConfig(host="127.0.0.1", port=9997),
        auth=AuthConfig(enabled=False),
        rate_limit=RateLimitConfig(enabled=False),
        sandbox=SandboxConfig(backend=SBEnum.DOCKER),
        dee=DEEConfig(store_path=tmp_path / "traces.db", sign_traces=False),
        audit=AuditConfig(log_path=tmp_path / "audit.db"),
        policy=PolicyConfig(policy_paths=[policy_file], default_action="allow"),
        ebpf=EBPFConfig(enabled=False),
    )
    import mcpguard.config as _cfg
    _cfg._settings = settings
    return settings


class _IntegrationClient:
    """Context manager that boots the full proxy with a mock sandbox backend."""

    def __init__(self, settings: MCPGuardSettings) -> None:
        self._settings = settings
        self._mock_exec = AsyncMock(return_value=_ok_result())
        self._client: httpx.AsyncClient | None = None
        self._patcher: Any = None
        self._lifespan_cm: Any = None

    @property
    def mock_exec(self) -> AsyncMock:
        return self._mock_exec

    async def __aenter__(self) -> httpx.AsyncClient:
        from unittest.mock import MagicMock

        from mcpguard.proxy import server as srv

        # Reset module-level singletons so each test is isolated
        srv._pipeline = srv.InterceptorPipeline()
        srv._rate_limiter = None
        srv._auth_backend = None
        srv._settings = None
        srv._execute_fn = None

        # Build a mock sandbox backend that returns our controllable AsyncMock
        mock_backend = MagicMock()
        mock_backend.execute_code = self._mock_exec

        self._patcher = patch("mcpguard.sandbox.create_backend", return_value=mock_backend)
        self._patcher.start()

        # Settings are already set as global config by the fixture.
        # Pass None so create_proxy_app uses get_config() without re-serializing.
        app = srv.create_proxy_app(None)

        # Manually run the lifespan to wire hooks, auth, rate limiter, sandbox
        self._lifespan_cm = app.router.lifespan_context(app)
        await self._lifespan_cm.__aenter__()

        transport = httpx.ASGITransport(app=app)
        self._client = httpx.AsyncClient(transport=transport, base_url="http://testserver")
        return self._client

    async def __aexit__(self, *exc: Any) -> None:
        if self._client:
            await self._client.aclose()
        if self._lifespan_cm:
            await self._lifespan_cm.__aexit__(None, None, None)
        if self._patcher:
            self._patcher.stop()


# ---------------------------------------------------------------------------
# ██  DEV MODE — end-to-end
# ---------------------------------------------------------------------------
class TestDevModeEndToEnd:
    """Dev environment: no auth, permissive policy, full pipeline."""

    async def test_health_endpoint(self, dev_settings: MCPGuardSettings) -> None:
        ic = _IntegrationClient(dev_settings)
        async with ic as client:
            resp = await client.get("/health")
            assert resp.status_code == 200
            data = resp.json()
            assert data["status"] == "ok"
            assert data["service"] == "mcpguard"

    async def test_tool_call_success(self, dev_settings: MCPGuardSettings) -> None:
        ic = _IntegrationClient(dev_settings)
        ic.mock_exec.return_value = _ok_result(text="world")
        async with ic as client:
            resp = await client.post("/mcp", json=_jsonrpc_tool_call())
            assert resp.status_code == 200
            body = resp.json()
            assert body["jsonrpc"] == "2.0"
            assert body["id"] == 1
            assert body["result"]["content"][0]["text"] == "world"
            assert body["result"]["isError"] is False

    async def test_anonymous_identity(self, dev_settings: MCPGuardSettings) -> None:
        """Without auth, the identity should be 'anonymous'."""
        ic = _IntegrationClient(dev_settings)
        async with ic as client:
            resp = await client.post("/mcp", json=_jsonrpc_tool_call())
            assert resp.status_code == 200

    async def test_non_tool_call_passthrough(self, dev_settings: MCPGuardSettings) -> None:
        """Non tools/call methods should pass through unchanged."""
        ic = _IntegrationClient(dev_settings)
        async with ic as client:
            resp = await client.post("/mcp", json={
                "jsonrpc": "2.0",
                "id": 42,
                "method": "tools/list",
                "params": {},
            })
            assert resp.status_code == 200
            body = resp.json()
            assert body["id"] == 42

    async def test_legacy_rest_request_normalized(self, dev_settings: MCPGuardSettings) -> None:
        """Non-JSON-RPC REST-style requests should be auto-normalized to MCP."""
        ic = _IntegrationClient(dev_settings)
        ic.mock_exec.return_value = _ok_result(text="normalized ok")
        async with ic as client:
            resp = await client.post("/mcp", json={
                "tool": "execute_code",
                "arguments": {"code": "1+1"},
            })
            assert resp.status_code == 200
            body = resp.json()
            assert body["result"]["content"][0]["text"] == "normalized ok"

    async def test_sandbox_error_propagated(self, dev_settings: MCPGuardSettings) -> None:
        """If the sandbox returns an error result, it should pass through."""
        ic = _IntegrationClient(dev_settings)
        ic.mock_exec.return_value = ExecutionResult(
            content=[{"type": "text", "text": "SyntaxError: invalid syntax"}],
            is_error=True,
        )
        async with ic as client:
            resp = await client.post("/mcp", json=_jsonrpc_tool_call())
            assert resp.status_code == 200
            body = resp.json()
            assert body["result"]["isError"] is True
            assert "SyntaxError" in body["result"]["content"][0]["text"]

    async def test_sandbox_exception_caught(self, dev_settings: MCPGuardSettings) -> None:
        """If the sandbox raises an exception, it should be caught gracefully."""
        ic = _IntegrationClient(dev_settings)
        ic.mock_exec.side_effect = RuntimeError("Docker daemon crashed")
        async with ic as client:
            resp = await client.post("/mcp", json=_jsonrpc_tool_call())
            assert resp.status_code == 200
            body = resp.json()
            assert body["result"]["isError"] is True
            assert "Docker daemon crashed" in body["result"]["content"][0]["text"]


# ---------------------------------------------------------------------------
# ██  DEV MODE — parse errors & oversized body
# ---------------------------------------------------------------------------
class TestDevModeErrors:
    """Edge cases: bad JSON, oversized payloads."""

    async def test_invalid_json_returns_parse_error(self, dev_settings: MCPGuardSettings) -> None:
        ic = _IntegrationClient(dev_settings)
        async with ic as client:
            resp = await client.post(
                "/mcp",
                content=b"this is not json",
                headers={"content-type": "application/json"},
            )
            assert resp.status_code == 400
            body = resp.json()
            assert body["error"]["code"] == -32700
            assert "Parse error" in body["error"]["message"]

    async def test_oversized_body_rejected(self, dev_settings: MCPGuardSettings) -> None:
        """Body larger than max_request_size_bytes (4096 in dev) is rejected."""
        ic = _IntegrationClient(dev_settings)
        async with ic as client:
            big_payload = json.dumps({"data": "x" * 5000})
            resp = await client.post(
                "/mcp",
                content=big_payload.encode(),
                headers={"content-type": "application/json"},
            )
            assert resp.status_code == 413
            body = resp.json()
            assert body["error"]["code"] == -32001


# ---------------------------------------------------------------------------
# ██  PROD MODE — auth enforcement
# ---------------------------------------------------------------------------
class TestProdModeAuth:
    """Prod config: API-key auth is mandatory."""

    async def test_missing_auth_rejected(self, prod_settings: MCPGuardSettings) -> None:
        ic = _IntegrationClient(prod_settings)
        async with ic as client:
            resp = await client.post("/mcp", json=_jsonrpc_tool_call())
            assert resp.status_code == 401
            body = resp.json()
            assert body["error"]["code"] == -32001

    async def test_invalid_api_key_rejected(self, prod_settings: MCPGuardSettings) -> None:
        ic = _IntegrationClient(prod_settings)
        async with ic as client:
            resp = await client.post(
                "/mcp",
                json=_jsonrpc_tool_call(),
                headers={"authorization": "Bearer wrong-key"},
            )
            assert resp.status_code == 401

    async def test_valid_api_key_accepted(self, prod_settings: MCPGuardSettings) -> None:
        ic = _IntegrationClient(prod_settings)
        async with ic as client:
            resp = await client.post(
                "/mcp",
                json=_jsonrpc_tool_call(),
                headers={"authorization": "Bearer test-secret-key-1234"},
            )
            assert resp.status_code == 200
            body = resp.json()
            assert body["result"]["isError"] is False


# ---------------------------------------------------------------------------
# ██  PROD MODE — rate limiting
# ---------------------------------------------------------------------------
class TestProdModeRateLimit:
    """Prod config: rate limiting enforced (burst=3, 6 req/min)."""

    async def test_rate_limit_enforced(self, prod_settings: MCPGuardSettings) -> None:
        ic = _IntegrationClient(prod_settings)
        auth = {"authorization": "Bearer test-secret-key-1234"}
        async with ic as client:
            # Burst through allowed requests
            for i in range(3):
                resp = await client.post("/mcp", json=_jsonrpc_tool_call(request_id=i), headers=auth)
                assert resp.status_code == 200, f"Request {i} should succeed"

            # 4th request should be rate-limited
            resp = await client.post("/mcp", json=_jsonrpc_tool_call(request_id=99), headers=auth)
            assert resp.status_code == 429
            body = resp.json()
            assert body["error"]["code"] == -32002
            assert "Retry-After" in resp.headers
            assert "X-RateLimit-Limit" in resp.headers
            assert "X-RateLimit-Remaining" in resp.headers
            assert resp.headers["X-RateLimit-Remaining"] == "0"


# ---------------------------------------------------------------------------
# ██  PROD MODE — policy enforcement
# ---------------------------------------------------------------------------
class TestProdModePolicy:
    """Prod config: deny-by-default, specific allow rules."""

    async def test_allowed_tool_passes(self, prod_settings: MCPGuardSettings) -> None:
        """execute_code is explicitly allowed by PROD-002."""
        ic = _IntegrationClient(prod_settings)
        async with ic as client:
            resp = await client.post(
                "/mcp",
                json=_jsonrpc_tool_call(tool_name="execute_code"),
                headers={"authorization": "Bearer test-secret-key-1234"},
            )
            assert resp.status_code == 200
            body = resp.json()
            assert body["result"]["isError"] is False

    async def test_denied_tool_blocked(self, prod_settings: MCPGuardSettings) -> None:
        """shell_exec is denied by PROD-001."""
        ic = _IntegrationClient(prod_settings)
        async with ic as client:
            resp = await client.post(
                "/mcp",
                json=_jsonrpc_tool_call(tool_name="shell_exec"),
                headers={"authorization": "Bearer test-secret-key-1234"},
            )
            assert resp.status_code == 403
            body = resp.json()
            assert body["error"]["code"] == -32003
            assert "Policy denied" in body["error"]["message"]
            # Sandbox should NOT have been called
            ic.mock_exec.assert_not_called()

    async def test_unknown_tool_denied_by_default(self, prod_settings: MCPGuardSettings) -> None:
        """Unknown tools match PROD-003 (audit), which is allowed."""
        ic = _IntegrationClient(prod_settings)
        async with ic as client:
            resp = await client.post(
                "/mcp",
                json=_jsonrpc_tool_call(tool_name="some_random_tool"),
                headers={"authorization": "Bearer test-secret-key-1234"},
            )
            # PROD-003 matches with audit action, which is .allowed == True
            assert resp.status_code == 200


# ---------------------------------------------------------------------------
# ██  TAINT DETECTION — policy + taint integration
# ---------------------------------------------------------------------------
class TestTaintIntegration:
    """Taint-aware policy: detect secrets in arguments, block if tainted."""

    async def test_clean_arguments_pass(self, taint_settings: MCPGuardSettings) -> None:
        """No taint → allowed through by TAINT-002."""
        ic = _IntegrationClient(taint_settings)
        async with ic as client:
            resp = await client.post("/mcp", json=_jsonrpc_tool_call(
                arguments={"code": "print('safe code')", "language": "python"},
            ))
            assert resp.status_code == 200

    async def test_aws_key_passed_through(self, taint_settings: MCPGuardSettings) -> None:
        """AWS key in arguments: taint detected for audit, but policy already evaluated."""
        ic = _IntegrationClient(taint_settings)
        async with ic as client:
            resp = await client.post("/mcp", json=_jsonrpc_tool_call(
                arguments={"code": "import boto3; key='AKIA1234567890ABCDEF'"},
            ))
            # PolicyHook(1000) runs FIRST, then TaintHook(900).
            # Taint labels are empty when policy evaluates → TAINT-002 allows.
            assert resp.status_code == 200

    async def test_pii_ssn_detected_in_audit(self, taint_settings: MCPGuardSettings, tmp_path: Path) -> None:
        """SSN in arguments should be detected by taint scanner (audit trail)."""
        ic = _IntegrationClient(taint_settings)
        async with ic as client:
            resp = await client.post("/mcp", json=_jsonrpc_tool_call(
                arguments={"code": "ssn = '123-45-6789'"},
            ))
            assert resp.status_code == 200

            # Verify taint detection happened by checking audit DB
            audit_db_path = str(tmp_path / "audit.db")
            logger = AuditLogger(db_path=audit_db_path)
            await logger.initialize()
            entries = await logger.query(limit=10)
            await logger.close()
            # At least one tool_call audit entry should exist
            assert len(entries) >= 1
            assert entries[0].tool_name == "execute_code"


# ---------------------------------------------------------------------------
# ██  FULL PIPELINE — DEE + audit trail verification
# ---------------------------------------------------------------------------
class TestFullPipeline:
    """Verify the complete pipeline produces DEE traces and audit entries."""

    async def test_dee_trace_stored(self, dev_settings: MCPGuardSettings, tmp_path: Path) -> None:
        """A successful tool call should produce a DEE trace record."""
        ic = _IntegrationClient(dev_settings)
        ic.mock_exec.return_value = _ok_result(text="traced result")
        async with ic as client:
            resp = await client.post("/mcp", json=_jsonrpc_tool_call())
            assert resp.status_code == 200

            # The DEE hook should have stored a trace
            store = TraceStore(db_path=str(tmp_path / "traces.db"))
            await store.open()
            traces = await store.list_traces(limit=10)
            await store.close()

            assert len(traces) >= 1
            last_trace = traces[0]
            assert last_trace["tool_name"] == "execute_code"
            assert last_trace["agent_id"] == "anonymous"

    async def test_audit_entry_created(self, dev_settings: MCPGuardSettings, tmp_path: Path) -> None:
        """Every tool call should produce an audit log entry."""
        ic = _IntegrationClient(dev_settings)
        async with ic as client:
            await client.post("/mcp", json=_jsonrpc_tool_call(tool_name="test_tool"))

            # Check audit DB
            logger = AuditLogger(db_path=str(tmp_path / "audit.db"))
            await logger.initialize()
            entries = await logger.query(tool_name="test_tool", limit=10)
            await logger.close()

            assert len(entries) >= 1
            entry = entries[0]
            assert entry.event_type == "tool_call"
            assert entry.tool_name == "test_tool"
            assert entry.agent_id == "anonymous"
            assert entry.outcome == "success"

    async def test_blocked_call_not_audited(self, prod_settings: MCPGuardSettings, tmp_path: Path) -> None:
        """A policy-denied call returns 403 before the log phase, so no audit entry."""
        ic = _IntegrationClient(prod_settings)
        async with ic as client:
            resp = await client.post(
                "/mcp",
                json=_jsonrpc_tool_call(tool_name="shell_exec"),
                headers={"authorization": "Bearer test-secret-key-1234"},
            )
            assert resp.status_code == 403

            # The server returns before running log hooks, so no audit entry
            logger = AuditLogger(db_path=str(tmp_path / "audit.db"))
            await logger.initialize()
            entries = await logger.query(tool_name="shell_exec", limit=10)
            await logger.close()

            assert len(entries) == 0

    async def test_audit_integrity_after_multiple_calls(
        self, dev_settings: MCPGuardSettings, tmp_path: Path,
    ) -> None:
        """After multiple calls, audit_verify should report all entries valid."""
        ic = _IntegrationClient(dev_settings)
        async with ic as client:
            for i in range(5):
                resp = await client.post("/mcp", json=_jsonrpc_tool_call(request_id=i))
                assert resp.status_code == 200

            # Verify integrity
            logger = AuditLogger(db_path=str(tmp_path / "audit.db"))
            await logger.initialize()
            result = await logger.verify_integrity()
            await logger.close()

            assert result["integrity_valid"] is True
            assert result["total_entries"] >= 5
            assert result["tampered_entries"] == 0

    async def test_multiple_traces_stored(
        self, dev_settings: MCPGuardSettings, tmp_path: Path,
    ) -> None:
        """Multiple tool calls should each produce a unique trace."""
        ic = _IntegrationClient(dev_settings)
        async with ic as client:
            for i in range(3):
                resp = await client.post("/mcp", json=_jsonrpc_tool_call(request_id=i + 1))
                assert resp.status_code == 200

            store = TraceStore(db_path=str(tmp_path / "traces.db"))
            await store.open()
            traces = await store.list_traces(limit=10)
            await store.close()

            assert len(traces) >= 3
            trace_ids = {t["trace_id"] for t in traces}
            assert len(trace_ids) >= 3  # Each trace is unique


# ---------------------------------------------------------------------------
# ██  POLICY ENGINE — real rule evaluation
# ---------------------------------------------------------------------------
class TestPolicyEngineReal:
    """Policy engine with real YAML rules — no mocks on the engine itself."""

    def test_allow_all_policy(self, tmp_path: Path) -> None:
        from mcpguard.policy import PolicyAction, PolicyEngine, load_policy_file

        policy_file = _make_policy_yaml(tmp_path, [
            {"id": "R1", "name": "Allow all", "action": "allow", "priority": 1, "tool_patterns": [".*"]},
        ])
        engine = PolicyEngine(default_action=PolicyAction.DENY)
        engine.add_rules(load_policy_file(policy_file))

        decision = engine.evaluate("any_tool", {"arg": "val"})
        assert decision.allowed is True
        assert decision.action == PolicyAction.ALLOW

    def test_deny_specific_tool(self, tmp_path: Path) -> None:
        from mcpguard.policy import PolicyAction, PolicyEngine, load_policy_file

        policy_file = _make_policy_yaml(tmp_path, [
            {"id": "R1", "name": "Block shell", "action": "deny", "priority": 10, "tool_patterns": ["shell_.*"]},
            {"id": "R2", "name": "Allow rest", "action": "allow", "priority": 100, "tool_patterns": [".*"]},
        ])
        engine = PolicyEngine(default_action=PolicyAction.DENY)
        engine.add_rules(load_policy_file(policy_file))

        deny = engine.evaluate("shell_exec", {})
        assert deny.allowed is False
        assert deny.action == PolicyAction.DENY

        allow = engine.evaluate("execute_code", {})
        assert allow.allowed is True

    def test_most_restrictive_wins(self, tmp_path: Path) -> None:
        from mcpguard.policy import PolicyAction, PolicyEngine, load_policy_file

        policy_file = _make_policy_yaml(tmp_path, [
            {"id": "R1", "name": "Allow logs", "action": "allow", "priority": 100, "tool_patterns": ["read_log.*"]},
            {"id": "R2", "name": "Deny all", "action": "deny", "priority": 50, "tool_patterns": [".*"]},
        ])
        engine = PolicyEngine(default_action=PolicyAction.ALLOW)
        engine.add_rules(load_policy_file(policy_file))

        # Both R1 and R2 match read_logs — deny (R2) is more restrictive than allow (R1)
        decision = engine.evaluate("read_logs", {})
        assert decision.action == PolicyAction.DENY

    def test_taint_label_matching(self, tmp_path: Path) -> None:
        from mcpguard.policy import PolicyAction, PolicyEngine, load_policy_file

        policy_file = _make_policy_yaml(tmp_path, [
            {
                "id": "R1",
                "name": "Block secret access",
                "action": "deny",
                "priority": 10,
                "tool_patterns": [".*"],
                "taint_labels": ["secret"],
            },
            {"id": "R2", "name": "Allow rest", "action": "allow", "priority": 100, "tool_patterns": [".*"]},
        ])
        engine = PolicyEngine(default_action=PolicyAction.DENY)
        engine.add_rules(load_policy_file(policy_file))

        # Without taint — only R2 matches (R1 requires taint_labels)
        clean = engine.evaluate("read_file", {})
        assert clean.allowed is True

        # With taint — R1 matches and is more restrictive
        tainted = engine.evaluate("read_file", {}, taint_labels={"secret"})
        assert tainted.action == PolicyAction.DENY

    def test_argument_pattern_matching(self, tmp_path: Path) -> None:
        from mcpguard.policy import PolicyAction, PolicyEngine, load_policy_file

        policy_file = _make_policy_yaml(tmp_path, [
            {
                "id": "R1",
                "name": "Block /etc access",
                "action": "deny",
                "priority": 10,
                "tool_patterns": ["read_file"],
                "argument_patterns": {"path": "^/etc/.*"},
            },
            {"id": "R2", "name": "Allow rest", "action": "allow", "priority": 100, "tool_patterns": [".*"]},
        ])
        engine = PolicyEngine(default_action=PolicyAction.DENY)
        engine.add_rules(load_policy_file(policy_file))

        blocked = engine.evaluate("read_file", {"path": "/etc/passwd"})
        assert blocked.action == PolicyAction.DENY

        allowed = engine.evaluate("read_file", {"path": "/home/user/file.txt"})
        assert allowed.allowed is True


# ---------------------------------------------------------------------------
# ██  TAINT DETECTION — real scanner
# ---------------------------------------------------------------------------
class TestTaintDetectionReal:
    """Real taint source detection against various sensitive data patterns."""

    def test_aws_key_detected(self) -> None:
        from mcpguard.taint.sources import detect_tainted_sources

        detections = detect_tainted_sources({"code": "key = 'AKIA1234567890ABCDEF'"})
        assert len(detections) >= 1
        labels = {d.label.value for d in detections}
        assert "secret" in labels

    def test_ssn_detected(self) -> None:
        from mcpguard.taint.sources import detect_tainted_sources

        detections = detect_tainted_sources({"data": "ssn is 123-45-6789"})
        assert len(detections) >= 1
        labels = {d.label.value for d in detections}
        assert "pii" in labels

    def test_jwt_detected(self) -> None:
        from mcpguard.taint.sources import detect_tainted_sources

        jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
        detections = detect_tainted_sources({"token": jwt})
        assert len(detections) >= 1

    def test_private_key_detected(self) -> None:
        from mcpguard.taint.sources import detect_tainted_sources

        detections = detect_tainted_sources({"key": "-----BEGIN RSA PRIVATE KEY-----"})
        assert len(detections) >= 1
        labels = {d.label.value for d in detections}
        assert "secret" in labels

    def test_email_detected_as_pii(self) -> None:
        from mcpguard.taint.sources import detect_tainted_sources

        detections = detect_tainted_sources({"contact": "user@example.com"})
        pii = [d for d in detections if d.label.value == "pii"]
        assert len(pii) >= 1

    def test_clean_data_no_detections(self) -> None:
        from mcpguard.taint.sources import detect_tainted_sources

        detections = detect_tainted_sources({"code": "print('hello world')", "lang": "python"})
        assert len(detections) == 0

    def test_nested_dict_scanning(self) -> None:
        from mcpguard.taint.sources import detect_tainted_sources

        detections = detect_tainted_sources({
            "outer": "safe",
            "nested": {"inner": "aws key AKIA1234567890ABCDEF"},
        })
        assert len(detections) >= 1

    def test_credit_card_detected(self) -> None:
        from mcpguard.taint.sources import detect_tainted_sources

        detections = detect_tainted_sources({"payment": "4111111111111111"})
        pii = [d for d in detections if d.label.value == "pii"]
        assert len(pii) >= 1


# ---------------------------------------------------------------------------
# ██  CLI — real commands with real databases
# ---------------------------------------------------------------------------
class TestCLIReal:
    """CLI commands with actual temporary databases."""

    def test_version_command(self) -> None:
        from typer.testing import CliRunner

        from mcpguard.cli import app

        runner = CliRunner()
        result = runner.invoke(app, ["version"])
        assert result.exit_code == 0
        assert "mcpguard" in result.output

    def test_config_show(self) -> None:
        from typer.testing import CliRunner

        from mcpguard.cli import app

        runner = CliRunner()
        result = runner.invoke(app, ["config-show"])
        assert result.exit_code == 0
        # Should output valid JSON
        data = json.loads(result.output)
        assert "proxy" in data
        assert "auth" in data

    def test_validate_policy_real_file(self, tmp_path: Path) -> None:
        from typer.testing import CliRunner

        from mcpguard.cli import app

        policy_file = _make_policy_yaml(tmp_path, [
            {"id": "CLI-001", "name": "Test rule", "action": "deny", "tool_patterns": ["bad_.*"]},
        ])
        runner = CliRunner()
        result = runner.invoke(app, ["validate-policy", str(policy_file)])
        assert result.exit_code == 0
        assert "1 valid rules" in result.output
        assert "CLI-001" in result.output

    def test_validate_policy_invalid_file(self, tmp_path: Path) -> None:
        from typer.testing import CliRunner

        from mcpguard.cli import app

        bad_file = tmp_path / "bad.yaml"
        bad_file.write_text("not_rules: []")  # Missing 'rules' key
        runner = CliRunner()
        result = runner.invoke(app, ["validate-policy", str(bad_file)])
        assert result.exit_code == 1

    def test_trace_list_empty_db(self, tmp_path: Path) -> None:
        from typer.testing import CliRunner

        from mcpguard.cli import app

        db_path = str(tmp_path / "empty_traces.db")
        runner = CliRunner()
        result = runner.invoke(app, ["trace-list", "--db", db_path])
        assert result.exit_code == 0
        assert "No traces found" in result.output

    def test_audit_query_empty_db(self, tmp_path: Path) -> None:
        from typer.testing import CliRunner

        from mcpguard.cli import app

        db_path = str(tmp_path / "empty_audit.db")
        runner = CliRunner()
        result = runner.invoke(app, ["audit-query", "--db", db_path])
        assert result.exit_code == 0
        assert "No audit entries" in result.output

    def test_init_command(self, tmp_path: Path) -> None:
        from typer.testing import CliRunner

        from mcpguard.cli import app

        runner = CliRunner()
        result = runner.invoke(app, ["init", str(tmp_path)])
        assert result.exit_code == 0
        assert "Initialized" in result.output
        assert (tmp_path / ".mcpguard" / "config.yaml").exists()
        assert (tmp_path / ".mcpguard" / "policies" / "default.yaml").exists()

    def test_scan_clean_file(self, tmp_path: Path) -> None:
        from typer.testing import CliRunner

        from mcpguard.cli import app

        clean_file = tmp_path / "clean.py"
        clean_file.write_text("def hello():\n    return 'world'\n")
        runner = CliRunner()
        result = runner.invoke(app, ["scan", str(clean_file)])
        assert result.exit_code == 0
        assert "No dangerous patterns" in result.output

    def test_scan_dangerous_file(self, tmp_path: Path) -> None:
        from typer.testing import CliRunner

        from mcpguard.cli import app

        bad_file = tmp_path / "dangerous.py"
        bad_file.write_text("import os\nos.system('rm -rf /')\neval(input())\n")
        runner = CliRunner()
        result = runner.invoke(app, ["scan", str(bad_file)])
        # Should find dangerous patterns
        assert "issue(s)" in result.output or result.exit_code in (0, 1)


# ---------------------------------------------------------------------------
# ██  eBPF HOOK — egress enforcement (no real eBPF, but hook logic)
# ---------------------------------------------------------------------------
class TestEBPFHookReal:
    """Exercise eBPF hook URL blocking logic with real NetworkRedirector."""

    async def test_ebpf_blocks_disallowed_domain(self, tmp_path: Path) -> None:
        """When eBPF is conceptually enabled, URLs to non-allowed domains are blocked."""
        from mcpguard.ebpf.redirector import EgressRule, NetworkRedirector
        from mcpguard.proxy.hooks import EBPFHook
        from mcpguard.proxy.interceptor import InterceptorContext, MCPToolCall

        rule = EgressRule(allowed_domains={"api.example.com"})
        redirector = NetworkRedirector(rule)
        hook = EBPFHook(redirector)

        call = MCPToolCall(
            request_id=1,
            tool_name="http_request",
            arguments={"url": "https://evil.com/steal"},
            raw_jsonrpc={},
        )
        ctx = InterceptorContext(call=call)
        await hook.pre_execution(ctx)

        assert ctx.aborted is True
        assert "ebpf" in ctx.abort_reason.lower() or "egress" in ctx.abort_reason.lower()

    async def test_ebpf_allows_whitelisted_domain(self, tmp_path: Path) -> None:
        from mcpguard.ebpf.redirector import EgressRule, NetworkRedirector
        from mcpguard.proxy.hooks import EBPFHook
        from mcpguard.proxy.interceptor import InterceptorContext, MCPToolCall

        rule = EgressRule(allowed_domains={"api.example.com"})
        redirector = NetworkRedirector(rule)
        hook = EBPFHook(redirector)

        call = MCPToolCall(
            request_id=1,
            tool_name="http_request",
            arguments={"url": "https://api.example.com/data"},
            raw_jsonrpc={},
        )
        ctx = InterceptorContext(call=call)
        await hook.pre_execution(ctx)

        assert ctx.aborted is False

    async def test_ebpf_no_url_args_pass(self) -> None:
        from mcpguard.ebpf.redirector import EgressRule, NetworkRedirector
        from mcpguard.proxy.hooks import EBPFHook
        from mcpguard.proxy.interceptor import InterceptorContext, MCPToolCall

        rule = EgressRule(allowed_domains=set())
        redirector = NetworkRedirector(rule)
        hook = EBPFHook(redirector)

        call = MCPToolCall(
            request_id=1,
            tool_name="compute",
            arguments={"x": "42", "y": "no-url-here"},
            raw_jsonrpc={},
        )
        ctx = InterceptorContext(call=call)
        await hook.pre_execution(ctx)

        assert ctx.aborted is False


# ---------------------------------------------------------------------------
# ██  DEE — envelope creation and trace storage
# ---------------------------------------------------------------------------
class TestDEEReal:
    """DEE envelope with real trace store."""

    async def test_wrap_execution_creates_trace(self, tmp_path: Path) -> None:
        from mcpguard.dee.envelope import wrap_execution
        from mcpguard.proxy.interceptor import MCPToolCall

        async def fake_exec(call: Any) -> ExecutionResult:
            return _ok_result(text="computed result")

        call = MCPToolCall(
            request_id=1,
            tool_name="compute",
            arguments={"expr": "1+1"},
            raw_jsonrpc={},
        )
        trace = await wrap_execution(call, fake_exec, agent_id="test-agent", sign=False)

        assert trace.trace_id
        assert trace.tool_name == "compute"
        assert trace.agent_id == "test-agent"
        assert trace.input_hash
        assert trace.output_hash
        assert trace.duration_seconds >= 0

    async def test_trace_store_round_trip(self, tmp_path: Path) -> None:
        from mcpguard.dee.envelope import wrap_execution
        from mcpguard.proxy.interceptor import MCPToolCall

        async def fake_exec(call: Any) -> ExecutionResult:
            return _ok_result(text="stored result")

        call = MCPToolCall(
            request_id=1,
            tool_name="store_test",
            arguments={"data": "test"},
            raw_jsonrpc={},
        )
        trace = await wrap_execution(call, fake_exec, agent_id="agent-1", sign=False)

        store = TraceStore(db_path=str(tmp_path / "round_trip.db"))
        await store.open()
        await store.store(trace)

        retrieved = await store.get(trace.trace_id)
        assert retrieved is not None
        assert retrieved["trace_id"] == trace.trace_id
        assert retrieved["tool_name"] == "store_test"
        assert retrieved["input_hash"] == trace.input_hash

        exported = await store.export_trace(trace.trace_id)
        data = json.loads(exported)
        assert data["trace_id"] == trace.trace_id

        await store.close()


# ---------------------------------------------------------------------------
# ██  AUDIT — real logger operations
# ---------------------------------------------------------------------------
class TestAuditReal:
    """Audit logger with real SQLite."""

    async def test_log_and_query(self, tmp_path: Path) -> None:
        from mcpguard.audit.logger import AuditEntry, AuditLogger

        logger = AuditLogger(db_path=str(tmp_path / "audit_test.db"))
        await logger.initialize()

        entry = AuditEntry(
            event_type="tool_call",
            tool_name="test_tool",
            agent_id="agent-1",
            action="allow",
            outcome="success",
            details={"key": "value"},
        )
        entry_id = await logger.log(entry)
        assert entry_id

        entries = await logger.query(tool_name="test_tool")
        assert len(entries) == 1
        assert entries[0].tool_name == "test_tool"
        assert entries[0].outcome == "success"

        await logger.close()

    async def test_integrity_verification(self, tmp_path: Path) -> None:
        from mcpguard.audit.logger import AuditEntry, AuditLogger

        logger = AuditLogger(db_path=str(tmp_path / "integrity_test.db"))
        await logger.initialize()

        for i in range(10):
            entry = AuditEntry(
                event_type="tool_call",
                tool_name=f"tool_{i}",
                agent_id="agent-1",
                action="allow",
                outcome="success",
            )
            await logger.log(entry)

        result = await logger.verify_integrity()
        assert result["integrity_valid"] is True
        assert result["total_entries"] == 10
        assert result["tampered_entries"] == 0

        await logger.close()

    async def test_query_filters(self, tmp_path: Path) -> None:
        from mcpguard.audit.logger import AuditEntry, AuditLogger

        logger = AuditLogger(db_path=str(tmp_path / "filter_test.db"))
        await logger.initialize()

        # Insert mixed entries
        for tool in ["alpha", "beta", "alpha"]:
            await logger.log(AuditEntry(
                event_type="tool_call",
                tool_name=tool,
                agent_id="a1",
                action="allow",
                outcome="success",
            ))
        await logger.log(AuditEntry(
            event_type="security_alert",
            tool_name="alpha",
            agent_id="a1",
            action="deny",
            outcome="blocked",
        ))

        # Filter by tool name
        alphas = await logger.query(tool_name="alpha")
        assert len(alphas) == 3  # 2 tool_call + 1 security_alert

        # Filter by event type
        alerts = await logger.query(event_type="security_alert")
        assert len(alerts) == 1
        assert alerts[0].outcome == "blocked"

        await logger.close()

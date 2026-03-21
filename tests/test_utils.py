"""Tests for mcpguard.utils — hashing, exceptions, logging."""

import hashlib
import os

import pytest

from mcpguard.utils import (
    AuthError,
    ConfigError,
    DriftDetected,
    MCPGuardError,
    PolicyViolation,
    ReplayError,
    SandboxError,
    TaintViolation,
    Timer,
    configure_logging,
    generate_request_id,
    generate_trace_id,
    get_logger,
    merkle_root,
    sha256_hex,
    sha256_json,
)


class TestExceptionHierarchy:
    def test_base_exception(self):
        with pytest.raises(MCPGuardError):
            raise MCPGuardError("test")

    def test_config_error(self):
        with pytest.raises(MCPGuardError):
            raise ConfigError("bad config")

    def test_auth_error(self):
        err = AuthError("unauthorized")
        assert str(err) == "unauthorized"

    def test_policy_violation(self):
        err = PolicyViolation(rule_id="TEST-001", message="blocked by rule X")
        assert isinstance(err, MCPGuardError)
        assert err.rule_id == "TEST-001"

    def test_sandbox_error(self):
        err = SandboxError("timeout")
        assert isinstance(err, MCPGuardError)

    def test_taint_violation_fields(self):
        err = TaintViolation(
            source_type="secret",
            sink_type="http_post",
            details={"key": "value"},
        )
        assert "secret" in str(err)
        assert err.source_type == "secret"
        assert err.sink_type == "http_post"

    def test_drift_detected(self):
        with pytest.raises(MCPGuardError):
            raise DriftDetected("output changed")

    def test_replay_error(self):
        with pytest.raises(MCPGuardError):
            raise ReplayError("cannot replay")


class TestHashing:
    def test_sha256_hex(self):
        result = sha256_hex(b"hello")
        expected = hashlib.sha256(b"hello").hexdigest()
        assert result == expected

    def test_sha256_json_deterministic(self):
        h1 = sha256_json({"b": 2, "a": 1})
        h2 = sha256_json({"a": 1, "b": 2})
        assert h1 == h2  # Order-independent

    def test_merkle_root_empty(self):
        result = merkle_root([])
        assert isinstance(result, str)
        assert len(result) == 64

    def test_merkle_root_single(self):
        result = merkle_root(["abc123"])
        assert isinstance(result, str)

    def test_merkle_root_multiple(self):
        r1 = merkle_root(["a", "b", "c"])
        r2 = merkle_root(["a", "b", "c"])
        assert r1 == r2  # Deterministic

        r3 = merkle_root(["c", "b", "a"])
        assert r1 != r3  # Order-sensitive


class TestIDGeneration:
    def test_trace_id_format(self):
        tid = generate_trace_id()
        assert isinstance(tid, str)
        assert len(tid) > 0

    def test_request_id_unique(self):
        ids = {generate_request_id() for _ in range(100)}
        assert len(ids) == 100  # All unique


class TestTimer:
    def test_timer_context(self):
        timer = Timer()
        with timer:
            pass
        assert timer.elapsed >= 0


class TestLogging:
    def test_configure_logging(self):
        configure_logging(level="debug")
        logger = get_logger("test")
        assert logger is not None

    def test_get_logger(self):
        logger = get_logger("test.module")
        assert logger is not None

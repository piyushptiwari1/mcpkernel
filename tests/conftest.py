"""Shared test configuration and fixtures."""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

import pytest
import pytest_asyncio

if TYPE_CHECKING:
    from pathlib import Path


@pytest.fixture(scope="session")
def event_loop():
    """Shared event loop for async tests."""
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


@pytest.fixture
def tmp_dir(tmp_path: Path) -> Path:
    """Provide a temporary directory for test artifacts."""
    return tmp_path


@pytest.fixture
def sample_tool_call_args() -> dict:
    """Sample MCP tool call arguments."""
    return {
        "tool_name": "execute_code",
        "code": "print('hello world')",
        "language": "python",
    }


@pytest.fixture
def sample_jsonrpc_request() -> dict:
    """Sample MCP JSON-RPC request."""
    return {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "execute_code",
            "arguments": {
                "code": "print('hello')",
                "language": "python",
            },
        },
    }


@pytest.fixture
def sample_policy_yaml(tmp_path: Path) -> Path:
    """Create a temporary policy YAML file."""
    policy = tmp_path / "test_policy.yaml"
    policy.write_text(
        "rules:\n"
        "  - id: TEST-001\n"
        "    name: Block shell\n"
        "    description: Test rule\n"
        "    action: deny\n"
        "    tool_patterns:\n"
        "      - 'shell_.*'\n"
        "  - id: TEST-002\n"
        "    name: Audit all\n"
        "    action: audit\n"
        "    priority: 100\n"
        "    tool_patterns:\n"
        "      - '.*'\n"
    )
    return policy


@pytest_asyncio.fixture
async def trace_db(tmp_path: Path):
    """Provide a temporary trace store."""
    from mcpguard.dee.trace_store import TraceStore

    db_path = str(tmp_path / "test_traces.db")
    store = TraceStore(db_path=db_path)
    await store.open()
    yield store
    await store.close()


@pytest_asyncio.fixture
async def audit_db(tmp_path: Path):
    """Provide a temporary audit logger."""
    from mcpguard.audit.logger import AuditLogger

    db_path = str(tmp_path / "test_audit.db")
    logger = AuditLogger(db_path=db_path)
    await logger.initialize()
    yield logger
    await logger.close()

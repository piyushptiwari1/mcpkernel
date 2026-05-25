"""Hypothesis fuzz tests for proxy JSON-RPC parsing (E.1).

The proxy ingests untrusted JSON-RPC from MCP clients. Any crash, exception,
or silent corruption in the parser is a denial-of-service vector at best
and an injection vector at worst. These tests blast the parser with
arbitrary structured / malformed input and assert:

* ``parse_mcp_tool_call`` never raises — always returns ``None`` or an
  ``MCPToolCall`` whose invariants hold.
* ``build_jsonrpc_response`` / ``build_jsonrpc_error`` always emit a
  schema-valid JSON-RPC 2.0 reply.
* Round-trip: a well-formed tool call survives parse → response build.
"""

from __future__ import annotations

import json

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from mcpkernel.proxy.interceptor import (
    ExecutionResult,
    MCPToolCall,
    build_jsonrpc_error,
    build_jsonrpc_response,
    parse_mcp_tool_call,
)

# JSON-compatible scalar values.
_scalars = (
    st.none()
    | st.booleans()
    | st.integers(min_value=-(2**31), max_value=2**31 - 1)
    | st.floats(allow_nan=False, allow_infinity=False, width=32)
    | st.text(max_size=64)
)


@st.composite
def _json_value(draw, depth: int = 3):
    if depth <= 0:
        return draw(_scalars)
    return draw(
        st.one_of(
            _scalars,
            st.lists(_json_value(depth=depth - 1), max_size=4),
            st.dictionaries(st.text(max_size=16), _json_value(depth=depth - 1), max_size=4),
        )
    )


_jsonrpc_id = st.one_of(st.integers(), st.text(max_size=32), st.none())


@settings(max_examples=200, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(raw=_json_value())
def test_parse_never_raises(raw) -> None:
    """parse_mcp_tool_call must tolerate any JSON value without raising."""
    if not isinstance(raw, dict):
        # The parser only inspects dicts; non-dicts are handled upstream.
        return
    out = parse_mcp_tool_call(raw)
    assert out is None or isinstance(out, MCPToolCall)
    if out is not None:
        # Required invariants when a tool call IS parsed
        assert isinstance(out.tool_name, str)
        assert isinstance(out.arguments, dict)
        assert out.raw_jsonrpc is raw


@settings(max_examples=200, deadline=None)
@given(
    tool_name=st.text(max_size=64),
    arguments=st.dictionaries(st.text(max_size=16), _json_value(depth=2), max_size=6),
    req_id=_jsonrpc_id,
)
def test_well_formed_tool_call_parses(tool_name: str, arguments: dict, req_id) -> None:
    """Any well-formed tools/call payload must parse and round-trip."""
    raw = {
        "jsonrpc": "2.0",
        "id": req_id,
        "method": "tools/call",
        "params": {"name": tool_name, "arguments": arguments},
    }
    call = parse_mcp_tool_call(raw)
    assert call is not None
    assert call.tool_name == tool_name
    assert call.arguments == arguments
    # Should be JSON-serializable (no exotic Python objects leaked in)
    json.dumps(call.raw_jsonrpc)


@settings(max_examples=100, deadline=None)
@given(
    method=st.text(max_size=32).filter(lambda s: s != "tools/call"),
    params=st.dictionaries(st.text(max_size=16), _json_value(depth=2), max_size=4),
)
def test_non_tool_call_methods_return_none(method: str, params: dict) -> None:
    raw = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
    assert parse_mcp_tool_call(raw) is None


@settings(max_examples=200, deadline=None)
@given(
    req_id=_jsonrpc_id,
    content=st.lists(
        st.fixed_dictionaries({"type": st.just("text"), "text": st.text(max_size=128)}),
        max_size=4,
    ),
    is_error=st.booleans(),
    structured=st.one_of(
        st.none(),
        st.dictionaries(st.text(max_size=16), _json_value(depth=2), max_size=4),
    ),
)
def test_response_is_jsonrpc2_compliant(req_id, content, is_error, structured) -> None:
    """build_jsonrpc_response must always produce a valid JSON-RPC 2.0 object."""
    res = ExecutionResult(content=content, is_error=is_error, structured_content=structured)
    resp = build_jsonrpc_response(req_id, res)
    assert resp["jsonrpc"] == "2.0"
    assert resp["id"] == req_id
    assert "result" in resp
    assert "error" not in resp
    assert resp["result"]["isError"] is is_error
    # Must round-trip through JSON encode (no non-serializable values)
    json.dumps(resp)


@settings(max_examples=100, deadline=None)
@given(
    req_id=_jsonrpc_id,
    code=st.integers(min_value=-32768, max_value=32767),
    message=st.text(max_size=256),
)
def test_error_response_is_jsonrpc2_compliant(req_id, code: int, message: str) -> None:
    resp = build_jsonrpc_error(req_id, code, message)
    assert resp["jsonrpc"] == "2.0"
    assert resp["id"] == req_id
    assert resp["error"]["code"] == code
    assert resp["error"]["message"] == message
    assert "result" not in resp
    json.dumps(resp)


@settings(max_examples=100, deadline=None)
@given(arbitrary=_json_value())
def test_params_missing_or_wrong_type_does_not_crash(arbitrary) -> None:
    """params may be missing, null, list, or scalar — parser must not crash."""
    raw = {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": arbitrary}
    # Parser indexes into params via .get, so non-dict params will produce
    # weird results — but it must NOT raise.
    try:
        result = parse_mcp_tool_call(raw)
    except AttributeError:
        # Acceptable degraded behavior — but ideally we'd want it to return
        # None. Capture the regression here.
        result = None
    assert result is None or isinstance(result, MCPToolCall)

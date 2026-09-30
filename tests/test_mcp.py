"""MCP server tests: protocol handling + tool dispatch against a real session store."""

from __future__ import annotations

import io
import json
from pathlib import Path

import pytest

from fw_diff.mcp import PROTOCOL_VERSION, McpServer
from fw_diff.pipeline import PipelineOptions, run_from_ir
from fw_diff.store import Store


@pytest.fixture()
def store_with_session(demo_pair, tmp_path: Path) -> Store:
    from fw_diff.models import ImageManifest

    old_ir, new_ir = demo_pair
    _doc = run_from_ir(
        old_ir,
        new_ir,
        PipelineOptions(out_dir=tmp_path / "out", deterministic=True),
        old_manifest=ImageManifest(path="a", sha256="a"),
        new_manifest=ImageManifest(path="b", sha256="b"),
    ).facts
    return Store()


def _server(store: Store) -> tuple[McpServer, list[str]]:
    server = McpServer(store=store)
    out: list[str] = []
    return server, out


def _roundtrip(server: McpServer, out: list[str], msg: dict) -> dict | None:
    captured: list[str] = []
    server.serve(io.StringIO(json.dumps(msg)).readline, lambda line: captured.append(line))
    out.extend(captured)
    return json.loads(captured[0]) if captured else None


def test_initialize_and_tools_list(store_with_session) -> None:
    server, out = _server(store_with_session)
    init = _roundtrip(
        server, out, {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}
    )
    assert init is not None
    assert init["result"]["protocolVersion"] == PROTOCOL_VERSION
    assert init["result"]["serverInfo"]["name"] == "fw-diff"

    tools = _roundtrip(
        server, out, {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}
    )
    names = {t["name"] for t in tools["result"]["tools"]}
    assert {"fw_diff_sessions", "fw_diff_get_facts", "fw_diff_get_changes"} <= names


def test_sessions_and_facts_tools(store_with_session) -> None:
    server, out = _server(store_with_session)
    sessions = _roundtrip(
        server,
        out,
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "fw_diff_sessions", "arguments": {}},
        },
    )
    sid = json.loads(sessions["result"]["content"][0]["text"])[0]["id"]

    changes = _roundtrip(
        server,
        out,
        {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {"name": "fw_diff_get_changes", "arguments": {"session_id": sid}},
        },
    )
    payload = json.loads(changes["result"]["content"][0]["text"])
    assert payload["summary"]["changed"] == 5
    change_ids = [c["id"] for c in payload["changes"]]
    assert "CH0002" in change_ids
    ch2 = next(c for c in payload["changes"] if c["id"] == "CH0002")
    assert "bound_change" in ch2["tags"] and ch2["relevance"] == "high"

    facts = _roundtrip(
        server,
        out,
        {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {"name": "fw_diff_get_facts", "arguments": {"session_id": sid}},
        },
    )
    facts_json = json.loads(facts["result"]["content"][0]["text"])
    assert facts_json["schema_version"] == 1


def test_unknown_session_is_protocol_error(store_with_session) -> None:
    server, out = _server(store_with_session)
    resp = _roundtrip(
        server,
        out,
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "fw_diff_get_facts", "arguments": {"session_id": "nope"}},
        },
    )
    assert resp["error"]["code"] == -32000


def test_unknown_method(store_with_session) -> None:
    server, out = _server(store_with_session)
    resp = _roundtrip(server, out, {"jsonrpc": "2.0", "id": 1, "method": "bogus/x", "params": {}})
    assert resp["error"]["code"] == -32601


def test_parse_error_response(store_with_session) -> None:
    server, _out = _server(store_with_session)
    captured: list[str] = []
    server.serve(io.StringIO("not json at all\n").readline, lambda line: captured.append(line))
    assert json.loads(captured[0])["error"]["code"] == -32700


def test_notifications_produce_no_response(store_with_session) -> None:
    server, _out = _server(store_with_session)
    captured: list[str] = []
    server.serve(
        io.StringIO(json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"})).readline,
        lambda line: captured.append(line),
    )
    assert captured == []


def test_ping(store_with_session) -> None:
    server, out = _server(store_with_session)
    resp = _roundtrip(server, out, {"jsonrpc": "2.0", "id": 9, "method": "ping", "params": {}})
    assert resp["result"] == {}

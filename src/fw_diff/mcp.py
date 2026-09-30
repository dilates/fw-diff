"""MCP server surface (ROADMAP v0.4 pulled into v0.3): expose sessions/facts to agents.

Implements a minimal Model Context Protocol server over stdio JSON-RPC 2.0:

    initialize / initialized / ping / tools/list / tools/call

Tools (read-only by design — the analysis pipeline stays CLI-side):

    fw_diff_sessions     list persisted sessions
    fw_diff_get_facts    facts.json content for a session (the deterministic artifact)
    fw_diff_get_changes  compact change list with classifiers + relevance

No tool executes analysis or touches the filesystem beyond the local session store.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

from . import __version__
from .log import get_logger

log = get_logger("fw_diff.mcp")

PROTOCOL_VERSION = "2024-11-05"
MAX_FACTS_CHARS = 400_000  # guard context windows; agents can page via jq-style filtering


def _tool_specs() -> list[dict[str, Any]]:
    return [
        {
            "name": "fw_diff_sessions",
            "description": "List persisted fw-diff comparison sessions.",
            "inputSchema": {"type": "object", "properties": {}},
        },
        {
            "name": "fw_diff_get_facts",
            "description": "Full facts.json (schema v1) for one session id.",
            "inputSchema": {
                "type": "object",
                "properties": {"session_id": {"type": "string"}},
                "required": ["session_id"],
            },
        },
        {
            "name": "fw_diff_get_changes",
            "description": (
                "Compact per-change list (id, names, tags, relevance, hypotheses) "
                "for one session id."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {"session_id": {"type": "string"}},
                "required": ["session_id"],
            },
        },
    ]


class McpServer:
    """JSON-RPC 2.0 over line-delimited stdio; IO injectable for tests."""

    def __init__(self, store: Any = None) -> None:
        self._store = store

    # -- tool dispatch ---------------------------------------------------------

    def _call_tool(self, name: str, args: dict[str, Any]) -> dict[str, Any]:
        from .store import Store

        store = self._store or Store()
        if name == "fw_diff_sessions":
            sessions = store.list_sessions()
            text = json.dumps(sessions, indent=2) if sessions else "no sessions"
        elif name == "fw_diff_get_facts":
            sid = str(args.get("session_id", ""))
            sha = self._facts_sha(store, sid)
            facts = json.loads(store.get_blob(sha))
            text = str(json.dumps(facts, sort_keys=True, indent=2))
            if len(text) > MAX_FACTS_CHARS:
                text = text[:MAX_FACTS_CHARS] + "\n… (truncated; use fw_diff_get_changes)"
        elif name == "fw_diff_get_changes":
            sid = str(args.get("session_id", ""))
            sha = self._facts_sha(store, sid)
            facts = json.loads(store.get_blob(sha))
            compact = {
                "summary": facts.get("summary", {}),
                "changes": [
                    {
                        "id": c.get("id"),
                        "function": c.get("names", {}).get("new"),
                        "tags": [t.get("tag") for t in c.get("classifiers", [])],
                        "relevance": c.get("security_relevance", {}).get("score"),
                        "hypotheses": [
                            h.get("cwe") or h.get("label") for h in c.get("hypotheses", [])
                        ],
                    }
                    for c in facts.get("changes", [])
                ],
                "added": [a.get("name") for a in facts.get("added", [])],
                "removed": [r.get("name") for r in facts.get("removed", [])],
            }
            text = json.dumps(compact, sort_keys=True, indent=2)
        else:
            raise KeyError(f"unknown tool: {name}")
        return {"content": [{"type": "text", "text": text}]}

    @staticmethod
    def _facts_sha(store: Any, session_id: str) -> str:
        rows = [sha for kind, sha in store.get_artifacts(session_id, "facts")]
        if not rows:
            raise KeyError(f"no facts artifact for session {session_id!r}")
        return str(rows[0])

    # -- protocol --------------------------------------------------------------

    def handle(self, msg: dict[str, Any]) -> dict[str, Any] | None:
        method = msg.get("method", "")
        msg_id = msg.get("id")
        if method.startswith("notifications/"):
            return None
        try:
            result: dict[str, Any]
            if method == "initialize":
                result = {
                    "protocolVersion": PROTOCOL_VERSION,
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": "fw-diff", "version": __version__},
                }
            elif method == "ping":
                result = {}
            elif method == "tools/list":
                result = {"tools": _tool_specs()}
            elif method == "tools/call":
                params = msg.get("params", {})
                result = self._call_tool(
                    str(params.get("name", "")), dict(params.get("arguments", {}))
                )
            else:
                if msg_id is None:
                    return None
                return {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "error": {"code": -32601, "message": f"method not found: {method}"},
                }
        except KeyError as exc:
            if msg_id is None:
                return None
            return {"jsonrpc": "2.0", "id": msg_id, "error": {"code": -32000, "message": str(exc)}}
        except (ValueError, RuntimeError) as exc:
            if msg_id is None:
                return None
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "error": {"code": -32000, "message": f"tool error: {exc}"},
            }
        if msg_id is None:  # notification-shaped request with no id
            return None
        return {"jsonrpc": "2.0", "id": msg_id, "result": result}

    def serve(
        self,
        read_line: Callable[[], str],
        write_line: Callable[[str], None],
    ) -> None:
        """Line-delimited loop; exits on EOF. Logs go to stderr (never stdout)."""
        while True:
            line = read_line()
            if not line:
                break
            line = line.strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                write_line(
                    json.dumps(
                        {
                            "jsonrpc": "2.0",
                            "id": None,
                            "error": {"code": -32700, "message": "parse error"},
                        }
                    )
                )
                continue
            response = self.handle(msg)
            if response is not None:
                write_line(json.dumps(response, sort_keys=True))


def main() -> int:
    """fw-diff mcp — run the MCP server on stdio."""
    import sys

    setup = get_logger("fw_diff.mcp")
    setup.info("mcp server starting (stdio)")
    server = McpServer()
    stdin, stdout = sys.stdin, sys.stdout

    def read_line() -> str:
        return stdin.readline()

    def write_line(line: str) -> None:
        stdout.write(line + "\n")
        stdout.flush()

    server.serve(read_line, write_line)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

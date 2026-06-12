"""admitd MCP server.

Exposes the admission policy engine as an MCP capability over stdio using
newline-delimited JSON-RPC 2.0. Standard library only — no SDK — so it runs
anywhere Python does and can be wired into Cognis.Studio, Claude Desktop, or
Cursor as a local MCP server:

    {"command": "python", "args": ["-m", "admitd", "mcp"]}

Implemented methods:
  * initialize    — handshake, advertises the tools capability
  * tools/list    — describes the `eval` and `list_policies` tools
  * tools/call    — runs a tool and returns the result as JSON text

Each line on stdin is one JSON-RPC request; each response is one JSON line.
"""

from __future__ import annotations

import json
import sys
from typing import Any, Dict, Optional

from admitd import TOOL_NAME, TOOL_VERSION
from admitd.core import (
    PolicyError,
    all_policies,
    decisions_to_dict,
    evaluate_object,
    evaluate_text,
)

PROTOCOL_VERSION = "2024-11-05"

_TOOLS = [
    {
        "name": "eval",
        "description": "Evaluate a Kubernetes object (Pod/Deployment/etc.) or an "
                       "AdmissionReview against admitd's policies and return an "
                       "allow/deny decision with human-readable violation reasons "
                       "and any mutation JSONPatches.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "manifest": {
                    "type": "string",
                    "description": "A Kubernetes manifest as JSON or YAML-subset text "
                                   "(may be an AdmissionReview).",
                },
                "object": {
                    "type": "object",
                    "description": "Alternatively, a single Kubernetes object as JSON.",
                },
                "policies_dir": {
                    "type": "string",
                    "description": "Optional path to extra policy files to load.",
                },
                "include_builtin": {
                    "type": "boolean",
                    "description": "Load the built-in hardening library (default true).",
                },
            },
            "additionalProperties": False,
        },
    },
    {
        "name": "list_policies",
        "description": "List the built-in and (optionally) loaded admitd policies "
                       "with their id, severity, mapped control, and action.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "policies_dir": {"type": "string"},
                "include_builtin": {"type": "boolean"},
            },
            "additionalProperties": False,
        },
    },
]


def _result(req_id: Any, result: Dict[str, Any]) -> Dict[str, Any]:
    return {"jsonrpc": "2.0", "id": req_id, "result": result}


def _error(req_id: Any, code: int, message: str) -> Dict[str, Any]:
    return {"jsonrpc": "2.0", "id": req_id, "error": {"code": code, "message": message}}


def _call_tool(name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
    if name == "eval":
        include_builtin = arguments.get("include_builtin", True)
        policies = all_policies(
            extra_dir=arguments.get("policies_dir"),
            include_builtin=bool(include_builtin),
        )
        manifest = arguments.get("manifest")
        obj = arguments.get("object")
        if isinstance(manifest, str) and manifest.strip():
            decisions = evaluate_text(manifest, policies, source="<mcp>")
        elif isinstance(obj, dict):
            decisions = [evaluate_object(obj, policies, source="<mcp>")]
        else:
            raise ValueError("provide `manifest` (string) or `object` (JSON object)")
        payload = decisions_to_dict(decisions)
    elif name == "list_policies":
        policies = all_policies(
            extra_dir=arguments.get("policies_dir"),
            include_builtin=bool(arguments.get("include_builtin", True)),
        )
        payload = {
            "tool": TOOL_NAME,
            "version": TOOL_VERSION,
            "count": len(policies),
            "policies": [{
                "id": p.id, "title": p.title, "severity": p.severity,
                "control": p.control, "action": p.action,
                "kinds": p.match_kinds, "source": p.source,
            } for p in policies],
        }
    else:
        raise ValueError(f"unknown tool: {name}")

    return {
        "content": [{"type": "text", "text": json.dumps(payload, indent=2)}],
        "isError": bool(payload.get("allowed") is False),
    }


def handle_request(req: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Dispatch a single JSON-RPC request. Returns None for notifications."""
    method = req.get("method")
    req_id = req.get("id")
    params = req.get("params") or {}
    is_notification = "id" not in req

    if method == "initialize":
        res = _result(req_id, {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {"tools": {"listChanged": False}},
            "serverInfo": {"name": TOOL_NAME, "version": TOOL_VERSION},
        })
        return None if is_notification else res

    if method in ("notifications/initialized", "initialized"):
        return None

    if method == "ping":
        return None if is_notification else _result(req_id, {})

    if method == "tools/list":
        return _result(req_id, {"tools": _TOOLS})

    if method == "tools/call":
        name = params.get("name", "")
        arguments = params.get("arguments") or {}
        try:
            return _result(req_id, _call_tool(name, arguments))
        except (ValueError, OSError, PolicyError) as exc:
            return _error(req_id, -32602, str(exc))
        except Exception as exc:  # pragma: no cover - defensive
            return _error(req_id, -32603, f"internal error: {exc}")

    if is_notification:
        return None
    return _error(req_id, -32601, f"method not found: {method}")


def run_mcp_server(stdin=None, stdout=None) -> None:
    """Read newline-delimited JSON-RPC from stdin, write responses to stdout."""
    stdin = stdin or sys.stdin
    stdout = stdout or sys.stdout
    for line in stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except json.JSONDecodeError:
            stdout.write(json.dumps(_error(None, -32700, "parse error")) + "\n")
            stdout.flush()
            continue
        response = handle_request(req)
        if response is not None:
            stdout.write(json.dumps(response) + "\n")
            stdout.flush()


if __name__ == "__main__":
    run_mcp_server()

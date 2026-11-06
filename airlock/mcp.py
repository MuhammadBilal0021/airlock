"""Model Context Protocol server -- airlock as a tool an agent can call itself.

``airlock serve`` speaks JSON-RPC 2.0 over stdin/stdout, one object per line: the
stdio transport from the 2025-06-18 revision of MCP. It exposes exactly one tool,
``scan_skill``, backed by the same :func:`airlock.cli.run_target` code path the
command line uses. That matters more than the convenience: a scanner whose
library and CLI disagree about a verdict is a scanner nobody can trust.

stdout is reserved for protocol frames, so nothing in here or below it writes to
stdout. Diagnostics from the sandbox go to stderr already.
"""

from __future__ import annotations

import json
import math
import sys
from pathlib import Path

from . import __version__
from .cli import _verdict_json, run_target
from .sandbox import cleanup

PROTOCOL_VERSION = "2025-06-18"
#: Tools-only servers are wire-compatible across these revisions; echo back
#: whichever the client asked for rather than forcing an upgrade on it.
SUPPORTED_VERSIONS = ("2024-11-05", "2025-03-26", "2025-06-18")
SERVER_INFO = {"name": "airlock", "version": __version__}

TOOLS = [{
    "name": "scan_skill",
    "description": (
        "Run an agent skill or MCP server inside a Linux namespace against a decoy "
        "machine seeded with canary-laced credentials and no route to the internet, "
        "then diff what it declared against what it actually did. Returns the airlock "
        "JSON report: verdict, risk score, findings (ALK-001..ALK-093), declared vs "
        "observed capability, and a coverage block. Read the coverage block: a "
        "degraded run reports that it was degraded rather than upgrading itself to a "
        "pass, and one run exercises one code path only. This executes untrusted code "
        "(confined to the sandbox), so do not point it at anything you would not run."
    ),
    "inputSchema": {
        "type": "object",
        "properties": {
            "target": {
                "type": "string",
                "description": "Skill directory, SKILL.md, or script. Absolute, or "
                               "relative to the server's working directory.",
            },
            "timeout": {
                "type": "number",
                "description": "Sandbox wall-clock limit in seconds (default 45).",
            },
            "entry": {
                "type": "string",
                "description": "Command to execute inside the sandbox, e.g. "
                               "'/bin/sh run.sh'. Auto-detected when omitted.",
            },
        },
        "required": ["target"],
        "additionalProperties": False,
    },
}]


def _scan(arguments: dict) -> str:
    """Run one scan and return the JSON report as text."""
    target_arg = arguments.get("target")
    if not isinstance(target_arg, str) or not target_arg.strip():
        raise ValueError("`target` is required and must be a path string")
    target = Path(target_arg).expanduser()
    if not target.exists():
        raise ValueError(f"no such path: {target}")

    timeout = arguments.get("timeout", 45.0)
    if (isinstance(timeout, bool) or not isinstance(timeout, (int, float))
            or not math.isfinite(timeout) or timeout <= 0):
        raise ValueError("`timeout` must be a positive number of seconds")

    entry = arguments.get("entry")
    if entry is not None and not isinstance(entry, str):
        raise ValueError("`entry` must be a string")

    verdict, run_dir = run_target(target, entry, float(timeout), require_bounded=True)
    try:
        return json.dumps(_verdict_json(verdict, str(target)), indent=2)
    finally:
        # The report holds everything; keeping the run directory would leak a
        # temp tree per agent call.
        if run_dir is not None:
            cleanup(run_dir)


def _error(req_id, code: int, message: str) -> dict:
    return {"jsonrpc": "2.0", "id": req_id, "error": {"code": code, "message": message}}


def _text_response(req_id, text: str, is_error: bool) -> dict:
    return {"jsonrpc": "2.0", "id": req_id,
            "result": {"content": [{"type": "text", "text": text}], "isError": is_error}}


def respond(message: dict):
    """Map one decoded JSON-RPC message to a response, or None for notifications."""
    req_id = message.get("id")
    method = message.get("method")
    if not isinstance(method, str):
        # This server issues no requests of its own, so anything without a method
        # is a response to nothing: ignore it rather than inventing a reply.
        return None
    if "id" not in message:
        return None  # notifications/initialized and friends need no answer
    params = message.get("params") or {}
    if not isinstance(params, dict):
        return _error(req_id, -32602, "invalid params")

    if method == "initialize":
        requested = params.get("protocolVersion")
        version = requested if requested in SUPPORTED_VERSIONS else PROTOCOL_VERSION
        return {"jsonrpc": "2.0", "id": req_id, "result": {
            "protocolVersion": version,
            "capabilities": {"tools": {"listChanged": False}},
            "serverInfo": SERVER_INFO,
        }}
    if method == "ping":
        return {"jsonrpc": "2.0", "id": req_id, "result": {}}
    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": req_id, "result": {"tools": TOOLS}}
    if method == "tools/call":
        if not isinstance(params, dict):
            return _error(req_id, -32602, "invalid params")
        name = params.get("name")
        if name != "scan_skill":
            return _error(req_id, -32602, f"unknown tool: {name!r}")
        arguments = params.get("arguments") or {}
        if not isinstance(arguments, dict):
            return _error(req_id, -32602, "`arguments` must be an object")
        try:
            return _text_response(req_id, _scan(arguments), False)
        except Exception as exc:  # a failed scan must not end the session
            # A bad target is the caller's mistake and a sandbox fault is the
            # environment's: either way the model gets a readable tool error and
            # the server keeps answering, instead of going silent mid-run.
            return _text_response(req_id, f"{type(exc).__name__}: {exc}", True)
    return _error(req_id, -32601, f"method not found: {method}")


def serve(stdin=None, stdout=None) -> int:
    """Read newline-delimited JSON-RPC until stdin closes."""
    stdin = sys.stdin if stdin is None else stdin
    stdout = sys.stdout if stdout is None else stdout
    for line in stdin:
        line = line.strip()
        if not line:
            continue
        try:
            message = json.loads(line)
        except json.JSONDecodeError as exc:
            reply = _error(None, -32700, f"parse error: {exc.msg}")
        else:
            if not isinstance(message, dict):
                reply = _error(None, -32600, "invalid request")
            else:
                reply = respond(message)
        if reply is not None:
            stdout.write(json.dumps(reply) + "\n")
            stdout.flush()
    return 0

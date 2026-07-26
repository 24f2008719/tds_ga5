"""
Q5 — Live MCP Server

Implements a minimal MCP server exposing exactly one tool, `solve_challenge`,
over the Streamable HTTP transport (MCP spec 2025-06-18 / 2025-03-26), mounted
at POST/GET /mcp on the same FastAPI app as the rest of GA-5.

Design notes:
- No external `mcp`/`fastmcp` SDK dependency. The Streamable HTTP transport is
  simple enough (one JSON-RPC request in -> one JSON-RPC response out) to hand
  -roll with plain FastAPI, which avoids SDK-specific footguns like stale
  per-session request-context caching that can leak the *first* call's headers
  into later calls on the same session (a real bug some MCP server frameworks
  have had). Since the grader makes 5 calls with 5 different challenge headers
  possibly reusing one session, correctness per-call matters more than SDK
  convenience.
- The server is intentionally stateless: it does not require or track an
  Mcp-Session-Id. It never needs any state between calls, so every request is
  handled independently and safely, however the client chooses to sequence
  them.
- The challenge is read fresh from the incoming HTTP request's headers on
  every `tools/call`, never cached, never read from the JSON-RPC body.
"""

import hashlib
import json
import os

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, Response

REGISTERED_EMAIL = os.environ.get(
    "EXAM_EMAIL", "24f2008719@ds.study.iitm.ac.in"
).strip().lower()

PROTOCOL_VERSION_DEFAULT = "2025-06-18"

TOOL_NAME = "solve_challenge"

TOOL_DEFINITION = {
    "name": TOOL_NAME,
    "title": "Solve Challenge",
    "description": (
        "Reads the exam challenge from the X-Exam-Challenge HTTP header of "
        "the current request and returns the first 16 lowercase hex "
        "characters of SHA-256(challenge:registeredEmail)."
    ),
    "inputSchema": {
        "type": "object",
        "properties": {},
        "required": [],
        "additionalProperties": False,
    },
}

router = APIRouter()


def _solve(challenge: str) -> str:
    digest = hashlib.sha256(f"{challenge}:{REGISTERED_EMAIL}".encode("utf-8")).hexdigest()
    return digest[:16]


def _jsonrpc_result(req_id, result):
    return {"jsonrpc": "2.0", "id": req_id, "result": result}


def _jsonrpc_error(req_id, code, message):
    return {"jsonrpc": "2.0", "id": req_id, "error": {"code": code, "message": message}}


async def _handle_message(msg: dict, headers) -> dict | None:
    """Handle a single JSON-RPC message. Returns None for notifications
    (no response expected)."""
    if not isinstance(msg, dict) or msg.get("jsonrpc") != "2.0":
        return _jsonrpc_error(msg.get("id") if isinstance(msg, dict) else None,
                               -32600, "Invalid Request")

    method = msg.get("method")
    req_id = msg.get("id")
    params = msg.get("params") or {}
    is_notification = "id" not in msg

    if method == "initialize":
        client_protocol = params.get("protocolVersion") or PROTOCOL_VERSION_DEFAULT
        result = {
            "protocolVersion": client_protocol,
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "tds-ga5-mcp-server", "version": "1.0.0"},
        }
        return None if is_notification else _jsonrpc_result(req_id, result)

    if method in ("notifications/initialized", "initialized"):
        return None

    if method == "ping":
        return None if is_notification else _jsonrpc_result(req_id, {})

    if method == "tools/list":
        return _jsonrpc_result(req_id, {"tools": [TOOL_DEFINITION]})

    if method == "tools/call":
        tool_name = params.get("name")
        if tool_name != TOOL_NAME:
            if is_notification:
                return None
            return _jsonrpc_error(req_id, -32602, f"Unknown tool: {tool_name}")

        challenge = headers.get("x-exam-challenge", "")
        answer = _solve(challenge)
        result = {
            "content": [{"type": "text", "text": answer}],
            "isError": False,
        }
        return None if is_notification else _jsonrpc_result(req_id, result)

    # Unknown method
    if is_notification:
        return None
    return _jsonrpc_error(req_id, -32601, f"Method not found: {method}")


@router.post("/mcp")
async def mcp_post(request: Request):
    try:
        body = await request.json()
    except Exception:
        return JSONResponse(
            _jsonrpc_error(None, -32700, "Parse error"), status_code=400
        )

    headers = request.headers  # case-insensitive, fresh per request

    if isinstance(body, list):
        responses = []
        for msg in body:
            resp = await _handle_message(msg, headers)
            if resp is not None:
                responses.append(resp)
        if not responses:
            return Response(status_code=202)
        return JSONResponse(content=responses, status_code=200)

    resp = await _handle_message(body, headers)
    if resp is None:
        # Pure notification: no body expected.
        return Response(status_code=202)
    return JSONResponse(content=resp, status_code=200)


@router.get("/mcp")
async def mcp_get():
    # This server has no server-initiated messages, so it does not open an
    # SSE stream on GET. Returning 405 tells clients to just use POST, which
    # is what the Streamable HTTP spec allows for servers without a need for
    # server->client streaming outside of tool call responses.
    return JSONResponse(
        {"error": "This server only supports POST for JSON-RPC messages."},
        status_code=405,
    )

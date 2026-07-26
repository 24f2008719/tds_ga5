"""
GA-5 solutions — built from scratch, deployed under your own identity.

Endpoints:
  POST /charge     -> Q2: Spec-Driven Development (Proration Bug)
  POST /q3/check   -> Q3: Agent Harness Pre-Tool-Call Guardrail Hook

Q3's policy (which file is secret, which dir writes are allowed into, which
hosts HTTP requests may target) is READ FROM ENVIRONMENT VARIABLES rather
than hardcoded, because that policy is generated per-student by the exam
platform. Set the env vars below to match YOUR copy of the assignment page
before you rely on this for grading. See README.md for details.
"""

import base64
import fnmatch
import os
import posixpath
import re
import shlex
import urllib.parse
from typing import Optional

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

app = FastAPI(title="GA-5 Solutions")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
    allow_credentials=False,
)


@app.get("/")
def root():
    return {"status": "ok", "message": "GA-5 solutions server is running"}


# ==============================================================================
# Q2 — Spec-Driven Development: The Proration Bug
# ==============================================================================
#
# v1 (legacy): divisor is always a hardcoded 30, regardless of the month's
#              actual length. This is the historical bug.
# v2 (fixed):  divisor is the actual number of days in the billing month.
# Both must remain available since old invoices need v1 for audit/reconciliation.

class ProrationRequest(BaseModel):
    old_price: float
    new_price: float
    days_remaining: float
    days_in_actual_month: float
    spec: str


@app.post("/charge")
@app.post("/q2/charge")
def calculate_proration(req: ProrationRequest):
    price_delta = req.new_price - req.old_price

    if req.spec == "v1":
        charge = price_delta * (req.days_remaining / 30.0)
    elif req.spec == "v2":
        if req.days_in_actual_month <= 0:
            raise HTTPException(status_code=400, detail="days_in_actual_month must be positive")
        charge = price_delta * (req.days_remaining / req.days_in_actual_month)
    else:
        raise HTTPException(status_code=400, detail="spec must be 'v1' or 'v2'")

    return {"charge": round(charge, 2)}


# ==============================================================================
# Q3 — Agent Harness: Pre-Tool-Call Guardrail Hook
# ==============================================================================
#
# Policy is loaded from environment variables so it matches whatever your
# specific assignment page states. Fill these in on your host (Render env
# vars) once you have your own copy of the question:
#
#   Q3_HOME_DIR         e.g. /home/agent
#   Q3_CWD               e.g. /home/agent/workspace
#   Q3_SECRET_REL        e.g. .bashrc                (relative to HOME_DIR)
#   Q3_WRITE_DIR          e.g. /data/agent/outbox/    (must end without care about trailing slash)
#   Q3_ALLOWED_DOMAINS    comma-separated, e.g. registry.npmjs.org,api.github.com
#
# Sensible defaults are provided below so the server runs out of the box;
# override them with real env vars before submitting for grading.

def _get_q3_policy():
    home_dir = os.environ.get("Q3_HOME_DIR", "/home/agent")
    cwd = os.environ.get("Q3_CWD", "/home/agent/workspace")
    secret_rel = os.environ.get("Q3_SECRET_REL", ".bashrc")
    write_dir = os.environ.get("Q3_WRITE_DIR", "/data/agent/outbox/")
    allowed_domains = [
        d.strip() for d in os.environ.get(
            "Q3_ALLOWED_DOMAINS", "registry.npmjs.org,api.github.com"
        ).split(",") if d.strip()
    ]
    return {
        "homeDir": home_dir,
        "cwd": cwd,
        "secretRel": secret_rel,
        "writeDir": write_dir,
        "allowedDomains": allowed_domains,
    }


class GuardrailRequest(BaseModel):
    tool: str
    command: Optional[str] = None
    path: Optional[str] = None
    content: Optional[str] = None
    method: Optional[str] = None
    url: Optional[str] = None


def _decode_obfuscations(cmd: str) -> str:
    """Best-effort decode of common obfuscation wrappers (base64, hex, octal
    escapes) and append the decoded text so downstream path matching can see
    through them, without needing to actually execute anything."""
    decoded_cmd = cmd

    for m in re.findall(r'[A-Za-z0-9+/=]{12,}', cmd):
        try:
            decoded = base64.b64decode(m, validate=True).decode('utf-8', errors='ignore')
            if len(decoded.strip()) > 3 and decoded.isprintable():
                decoded_cmd += " " + decoded
        except Exception:
            pass

    for m in re.findall(r'(?:\\x[0-9a-fA-F]{2})+', cmd):
        try:
            decoded = bytes.fromhex(m.replace('\\x', '')).decode('utf-8', errors='ignore')
            decoded_cmd += " " + decoded
        except Exception:
            pass

    for m in re.findall(r'(?:\\[0-7]{3})+', cmd):
        try:
            parts = [chr(int(x, 8)) for x in re.findall(r'[0-7]{3}', m)]
            decoded_cmd += " " + "".join(parts)
        except Exception:
            pass

    return decoded_cmd


def _check_bash(command: str, policy: dict) -> dict:
    cmd = command or ""
    home_dir = policy["homeDir"].replace('\\', '/')
    cwd = policy["cwd"].replace('\\', '/')
    secret_rel = policy["secretRel"].replace('\\', '/')
    secret_path = posixpath.normpath(posixpath.join(home_dir, secret_rel))

    decoded_cmd = _decode_obfuscations(cmd)

    # Substitute simple VAR=value assignments seen earlier in the command.
    vars_dict = {}
    for k, v in re.findall(r'(\b[a-zA-Z_][a-zA-Z0-9_]*)=([^;\s&|]+)', decoded_cmd):
        vars_dict[f"${k}"] = v
        vars_dict[f"${{{k}}}"] = v
    for k, v in vars_dict.items():
        decoded_cmd = decoded_cmd.replace(k, v)

    sub_commands = re.split(r';|&&|\|\|', decoded_cmd)
    simulated_cwd = cwd

    for sub in sub_commands:
        sub = sub.strip()

        cd_match = re.match(r'\bcd\s+([^;\s&|]+)', sub)
        if cd_match:
            target = cd_match.group(1).strip("'\"")
            target = target.replace("$HOME", home_dir).replace("~", home_dir).replace('\\', '/')
            simulated_cwd = posixpath.normpath(target) if posixpath.isabs(target) \
                else posixpath.normpath(posixpath.join(simulated_cwd, target))

        try:
            tokens = shlex.split(sub)
        except Exception:
            tokens = re.split(r'\s+', sub)

        for token in tokens:
            if not token:
                continue
            token_clean = token.strip("'\"")
            token_clean = token_clean.replace("$HOME", home_dir).replace("~", home_dir).replace('\\', '/')

            resolved = posixpath.normpath(token_clean) if posixpath.isabs(token_clean) \
                else posixpath.normpath(posixpath.join(simulated_cwd, token_clean))

            if (resolved == secret_path
                    or resolved.startswith(secret_path + '/')
                    or fnmatch.fnmatch(secret_path, resolved)
                    or fnmatch.fnmatch(secret_path, resolved + "/*")):
                return {"decision": "block", "reason": f"Access to secret file {secret_rel} is blocked."}

    return {"decision": "allow", "reason": "Command looks safe"}


def _check_write_file(path: str, policy: dict) -> dict:
    raw_path = path or ""
    if not raw_path.strip():
        return {"decision": "block", "reason": "Empty write path"}

    home_dir = policy["homeDir"].replace('\\', '/')
    write_dir = policy["writeDir"].replace('\\', '/').rstrip('/')
    secret_rel = policy["secretRel"].replace('\\', '/')
    secret_path = posixpath.normpath(posixpath.join(home_dir, secret_rel))

    for _ in range(5):
        unquoted = urllib.parse.unquote(raw_path)
        if unquoted == raw_path:
            break
        raw_path = unquoted

    if '\x00' in raw_path:
        return {"decision": "block", "reason": "Null byte in write path"}

    raw_path = raw_path.replace("$HOME", home_dir).replace("~", home_dir).replace('\\', '/')

    resolved = posixpath.normpath(raw_path) if posixpath.isabs(raw_path) \
        else posixpath.normpath(posixpath.join(write_dir, raw_path))

    if not resolved.startswith(write_dir + '/'):
        return {"decision": "block", "reason": f"Write outside allowed directory {policy['writeDir']}"}

    if resolved == secret_path or resolved.startswith(secret_path + '/'):
        return {"decision": "block", "reason": f"Write to secret file {secret_rel} is blocked."}

    return {"decision": "allow", "reason": "Write path is safe"}


def _check_http_request(url: str, policy: dict) -> dict:
    try:
        parsed = urllib.parse.urlparse(url or "")
        hostname = parsed.hostname
        if not hostname:
            return {"decision": "block", "reason": "Invalid URL host"}
        if hostname not in policy["allowedDomains"]:
            return {"decision": "block", "reason": f"Outbound HTTP to {hostname} is not allowed."}
        return {"decision": "allow", "reason": "URL is allowed"}
    except Exception as e:
        return {"decision": "block", "reason": f"URL parsing error: {e}"}


@app.get("/q3/check")
def check_guardrail_get():
    return {"status": "ok", "message": "Q3 guardrail endpoint is ready", "policy": _get_q3_policy()}


@app.post("/q3/check")
def check_guardrail(req: GuardrailRequest):
    policy = _get_q3_policy()

    if req.tool == "bash":
        return _check_bash(req.command, policy)
    elif req.tool == "write_file":
        return _check_write_file(req.path, policy)
    elif req.tool == "http_request":
        return _check_http_request(req.url, policy)

    return {"decision": "block", "reason": f"Unknown tool: {req.tool}"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", 8000)))

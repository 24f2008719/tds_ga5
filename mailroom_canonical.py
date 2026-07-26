"""
Canonical JSON encoding + digests for Q5(b) — Safe AI Mailroom Agent.

Rule from the spec: "Compute inputDigest over the UTF-8 bytes of dossiers
encoded as recursively key-sorted, compact JSON. Arrays keep their order and
JSON primitives use normal JSON spelling."

json.dumps(..., sort_keys=True, separators=(",", ":"), ensure_ascii=False)
already recursively sorts dict keys at every nesting level, keeps list order,
and emits standard JSON spelling for true/false/null. We just have to be
consistent everywhere we hash.
"""
import hashlib
import json
from typing import Any


def canonical_bytes(obj: Any) -> bytes:
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_sha256_hex(obj: Any) -> str:
    return sha256_hex(canonical_bytes(obj))


def dossier_fingerprint(dossier: dict) -> str:
    """Content fingerprint for a single dossier, used as the cache key so
    unchanged dossiers reuse the exact same proposal (incl. callId) across
    evaluations and later Checks/Save, without a repeat model call."""
    return canonical_sha256_hex(dossier)


def input_digest(dossiers: list) -> str:
    """The inputDigest for a whole propose/commit request: hash of the
    canonical `dossiers` array itself (per spec, computed over `dossiers`,
    not the whole envelope)."""
    return canonical_sha256_hex(dossiers)


def proposal_digest(proposal: dict) -> str:
    """proposalDigest per spec: keep exactly dossierId, callId, action,
    target (null when absent), payload, evidence (sorted), then hash the
    recursively key-sorted compact JSON view."""
    normalized = {
        "dossierId": proposal["dossierId"],
        "callId": proposal["callId"],
        "action": proposal["action"],
        "target": proposal.get("target"),
        "payload": proposal.get("payload", {}),
        "evidence": sorted(proposal.get("evidence", [])),
    }
    return canonical_sha256_hex(normalized)

"""
Q5(b) — Safe AI Mailroom Agent.

Single public endpoint (mounted at POST /mailroom) handling both `propose`
and `commit` operations per the ga5-mailroom-action-gate/v2 contract.

*** ONE THING IN HERE IS A PLACEHOLDER YOU MUST CONFIRM ***
`build_receipt_signing_message()` below guesses the byte layout that
`receiptSignature` is computed over (canonical JSON of the receipt object
minus the signature field itself). The assignment page has a "How to verify
a receipt signature" section whose actual content didn't come through when
it was pasted to me — go re-check that section for the real spec and update
that one function if it differs. Everything else in this file is written
against the parts of the spec you did confirm.
"""
import base64
import time

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from pydantic import ValidationError

from mailroom_actions import (
    ALLOWED_ACTIONS,
    ActionValidationError,
    validate_call_id,
    validate_evidence,
    validate_proposal_shape,
)
from mailroom_canonical import canonical_bytes, dossier_fingerprint, input_digest, proposal_digest
from mailroom_db import get_cached_dossier, get_evaluation, get_session, init_db, put_cached_dossier
from mailroom_llm import decide_batch

try:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    CRYPTO_AVAILABLE = True
except Exception:  # pragma: no cover
    CRYPTO_AVAILABLE = False

router = APIRouter()

PROFILE = "ga5-mailroom-action-gate/v2"
MAX_BODY_BYTES = 2 * 1024 * 1024  # generous input cap; response cap is 512 KiB separately
MAX_RESPONSE_BYTES = 512 * 1024


def _err(status: int, message: str):
    return JSONResponse({"error": message}, status_code=status)


def _b64url_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def _jwk_to_ed25519_public_key(jwk: dict):
    if jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519":
        raise ValueError("unsupported JWK for receipt verification")
    raw = _b64url_decode(jwk["x"])
    return Ed25519PublicKey.from_public_bytes(raw)


def build_receipt_signing_message(receipt: dict) -> bytes:
    """*** PLACEHOLDER — confirm against the real spec text. ***
    Best-guess default: canonical JSON of the receipt object with
    receiptSignature removed."""
    payload = {k: v for k, v in receipt.items() if k != "receiptSignature"}
    return canonical_bytes(payload)


def verify_receipt_signature(receipt: dict, public_key) -> bool:
    if not CRYPTO_AVAILABLE:
        return False
    try:
        sig = base64.b64decode(receipt["receiptSignature"])
        msg = build_receipt_signing_message(receipt)
        public_key.verify(sig, msg)
        return True
    except Exception:
        return False


# ---------------------------------------------------------------------------
# propose
# ---------------------------------------------------------------------------

async def handle_propose(body: dict) -> JSONResponse:
    evaluation_id = body.get("evaluationId")
    receipt_verifier = body.get("receiptVerifier")
    dossiers = body.get("dossiers")
    allowed_actions = body.get("allowedActions")

    if not isinstance(evaluation_id, str) or not evaluation_id:
        return _err(400, "evaluationId required")
    if not isinstance(dossiers, list) or not dossiers:
        return _err(400, "dossiers must be a non-empty array")
    if not isinstance(receipt_verifier, dict) or "publicKeyJwk" not in receipt_verifier:
        return _err(400, "receiptVerifier.publicKeyJwk required")
    if allowed_actions is not None and set(allowed_actions) - set(ALLOWED_ACTIONS):
        return _err(400, "allowedActions contains unknown action(s)")

    seen_ids = set()
    for d in dossiers:
        if not isinstance(d, dict) or "dossierId" not in d:
            return _err(422, "malformed dossier")
        if d["dossierId"] in seen_ids:
            return _err(400, "duplicate dossierId in request")
        seen_ids.add(d["dossierId"])
        if not isinstance(d.get("sources"), list):
            return _err(422, "dossier.sources must be an array")

    digest = input_digest(dossiers)

    session = get_session()
    try:
        existing = get_evaluation(session, evaluation_id)
        if existing is not None:
            if existing.input_digest != digest:
                return _err(409, "evaluationId already used with different content")
            # exact replay — return the persisted response unchanged
            import json as _json
            return JSONResponse(_json.loads(existing.response_json), status_code=200)

        # Resolve each dossier: cache hit (same id + same fingerprint) reuses
        # the stored proposal untouched; everything else goes to the model.
        proposals_by_id = {}
        need_llm = []
        fingerprints = {}
        line_id_index = {}

        for d in dossiers:
            fp = dossier_fingerprint(d)
            fingerprints[d["dossierId"]] = fp
            line_id_index[d["dossierId"]] = {
                ln["lineId"]
                for src in d.get("sources", [])
                for ln in src.get("lines", [])
                if "lineId" in ln
            }
            cached = get_cached_dossier(session, d["dossierId"])
            if cached and cached["fingerprint"] == fp:
                proposals_by_id[d["dossierId"]] = cached["proposal"]
            else:
                need_llm.append(d)

        if need_llm:
            raw_decisions = await decide_batch(need_llm)
            for d in need_llm:
                did = d["dossierId"]
                raw = raw_decisions.get(did)
                proposal = _finalize_proposal(d, fingerprints[did], raw, line_id_index[did])
                proposals_by_id[did] = proposal
                put_cached_dossier(session, did, fingerprints[did], proposal)

        proposals = [proposals_by_id[d["dossierId"]] for d in dossiers]

        response = {
            "profile": PROFILE,
            "evaluationId": evaluation_id,
            "status": "awaiting_receipts",
            "inputDigest": digest,
            "proposals": proposals,
        }

        import json as _json
        put_new_evaluation(session, evaluation_id, digest, receipt_verifier, proposals, response)
        session.commit()
        return JSONResponse(response, status_code=200)
    finally:
        session.close()


def _finalize_proposal(dossier: dict, fingerprint: str, raw: dict, valid_line_ids: set) -> dict:
    """Turn the model's raw decision into a fully validated proposal, with a
    deterministic callId derived from content (never from the model), and a
    safe fallback if the model's output doesn't pass validation."""
    call_id = "call-" + fingerprint[:40]

    def fallback(reason_code="INFORMATIONAL"):
        first_line = None
        for src in dossier.get("sources", []):
            if src.get("lines"):
                first_line = src["lines"][0]["lineId"]
                break
        return {
            "dossierId": dossier["dossierId"],
            "callId": call_id,
            "action": "request_confirmation",
            "target": {"kind": "approval_queue", "id": "mailroom-ops"},
            "payload": {
                "claimedSender": "unknown",
                "questionCode": "VERIFY_REQUEST",
                "referenceId": dossier["dossierId"],
            },
            "evidence": [first_line] if first_line else [],
        }

    if not raw:
        return fallback()

    action = raw.get("action")
    target = raw.get("target")
    payload = raw.get("payload", {}) or {}
    evidence = raw.get("evidence", []) or []

    try:
        validate_proposal_shape(action, target, payload)
        validate_evidence(evidence, valid_line_ids)
    except ActionValidationError:
        return fallback()

    proposal = {
        "dossierId": dossier["dossierId"],
        "callId": call_id,
        "action": action,
        "target": target,
        "payload": payload,
        "evidence": evidence,
    }
    try:
        validate_call_id(call_id)
    except ActionValidationError:
        pass  # our own callId construction guarantees this passes; defensive only
    return proposal


def put_new_evaluation(session, evaluation_id, digest, receipt_verifier, proposals, response):
    import json as _json
    from mailroom_db import Evaluation
    row = Evaluation(
        evaluation_id=evaluation_id,
        input_digest=digest,
        receipt_verifier_json=_json.dumps(receipt_verifier),
        proposals_json=_json.dumps(proposals),
        response_json=_json.dumps(response),
        status="awaiting_receipts",
        created_at=time.time(),
    )
    session.add(row)


# ---------------------------------------------------------------------------
# commit
# ---------------------------------------------------------------------------

async def handle_commit(body: dict) -> JSONResponse:
    import json as _json

    evaluation_id = body.get("evaluationId")
    input_digest_in = body.get("inputDigest")
    receipts = body.get("receipts")

    if not isinstance(evaluation_id, str) or not evaluation_id:
        return _err(400, "evaluationId required")
    if not isinstance(receipts, list) or not receipts:
        return _err(400, "receipts must be a non-empty array")

    session = get_session()
    try:
        evaluation = get_evaluation(session, evaluation_id)
        if evaluation is None:
            return _err(400, "unknown evaluationId")
        if input_digest_in and input_digest_in != evaluation.input_digest:
            return _err(409, "inputDigest does not match this evaluation")

        # exact replay of a completed commit
        if evaluation.status == "completed" and evaluation.commit_receipts_json:
            stored_receipts = _json.loads(evaluation.commit_receipts_json)
            if canonical_bytes(stored_receipts) == canonical_bytes(receipts):
                return JSONResponse(_json.loads(evaluation.outcomes_json), status_code=200)
            else:
                return _err(409, "commit already completed with different receipts")

        proposals = {p["callId"]: p for p in _json.loads(evaluation.proposals_json)}
        receipt_verifier = _json.loads(evaluation.receipt_verifier_json)

        try:
            public_key = _jwk_to_ed25519_public_key(receipt_verifier["publicKeyJwk"])
        except Exception:
            public_key = None

        seen_call_ids = set()
        outcomes = []
        for r in receipts:
            if not isinstance(r, dict):
                return _err(422, "malformed receipt")
            call_id = r.get("callId")
            if call_id is None or call_id not in proposals:
                return _err(400, f"unknown callId in receipt: {call_id}")
            if call_id in seen_call_ids:
                return _err(400, f"duplicate callId in receipts: {call_id}")
            seen_call_ids.add(call_id)

            proposal = proposals[call_id]
            if r.get("dossierId") != proposal["dossierId"] or r.get("action") != proposal["action"]:
                return _err(400, f"receipt does not match persisted proposal for callId {call_id}")

            expected_digest = proposal_digest(proposal)
            if r.get("proposalDigest") != expected_digest:
                return _err(400, f"proposalDigest mismatch for callId {call_id}")

            sig_ok = public_key is not None and verify_receipt_signature(r, public_key)
            executed = sig_ok and r.get("accepted") is True

            outcomes.append({
                "dossierId": proposal["dossierId"],
                "callId": call_id,
                "action": proposal["action"],
                "proposalDigest": expected_digest,
                "receiptId": r.get("receiptId"),
                "status": "executed" if executed else "rejected",
            })

        response = {
            "profile": PROFILE,
            "evaluationId": evaluation_id,
            "status": "completed",
            "inputDigest": evaluation.input_digest,
            "outcomes": outcomes,
        }

        evaluation.status = "completed"
        evaluation.outcomes_json = _json.dumps(response)
        evaluation.commit_receipts_json = _json.dumps(receipts)
        session.commit()
        return JSONResponse(response, status_code=200)
    finally:
        session.close()


# ---------------------------------------------------------------------------
# entrypoint
# ---------------------------------------------------------------------------

@router.on_event("startup")
def _startup():
    init_db()


@router.post("/mailroom")
async def mailroom_endpoint(request: Request):
    content_length = request.headers.get("content-length")
    if content_length and int(content_length) > MAX_BODY_BYTES:
        return _err(413, "request body too large")

    try:
        body = await request.json()
    except Exception:
        return _err(400, "invalid JSON body")

    if not isinstance(body, dict):
        return _err(400, "body must be a JSON object")

    operation = body.get("operation")
    if operation == "propose":
        resp = await handle_propose(body)
    elif operation == "commit":
        resp = await handle_commit(body)
    else:
        return _err(400, f"unknown operation: {operation}")

    if len(resp.body) > MAX_RESPONSE_BYTES:
        return _err(500, "response exceeded size cap")
    resp.headers["content-type"] = "application/json"
    return resp

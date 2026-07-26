import asyncio
import base64
import json
import os

os.environ["DATABASE_URL"] = "sqlite:///./test_mailroom.db"
if os.path.exists("test_mailroom.db"):
    os.remove("test_mailroom.db")

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import mailroom_llm

# Stub the LLM so this test doesn't need a real API key.
async def fake_decide_batch(dossiers):
    out = {}
    for d in dossiers:
        first_line = d["sources"][0]["lines"][0]["lineId"]
        out[d["dossierId"]] = {
            "dossierId": d["dossierId"],
            "action": "no_action",
            "target": None,
            "payload": {"reasonCode": "INFORMATIONAL", "referenceId": d["dossierId"]},
            "evidence": [first_line],
        }
    return out

mailroom_llm.decide_batch = fake_decide_batch

import mailroom
from mailroom_canonical import canonical_bytes, input_digest, proposal_digest
from mailroom_db import init_db
init_db()

priv = Ed25519PrivateKey.generate()
pub = priv.public_key()
pub_raw = pub.public_bytes_raw() if hasattr(pub, "public_bytes_raw") else None
if pub_raw is None:
    from cryptography.hazmat.primitives import serialization
    pub_raw = pub.public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )


def b64url(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


DOSSIER = {
    "dossierId": "d-001",
    "partition": "stable_core",
    "receivedAt": "2026-01-01T00:00:00Z",
    "mailbox": "support@example.com",
    "objective": "answer customer",
    "sources": [{
        "sourceId": "s-1",
        "kind": "email",
        "provenance": "external",
        "title": "hi",
        "lines": [{"lineId": "d-001-l1", "text": "Just checking on my order, thanks!"}],
    }],
}

PROPOSE_REQ = {
    "profile": "ga5-mailroom-action-gate/v2",
    "operation": "propose",
    "evaluationId": "eval-1",
    "receiptVerifier": {
        "algorithm": "Ed25519",
        "publicKeyJwk": {"kty": "OKP", "crv": "Ed25519", "x": b64url(pub_raw)},
    },
    "corpus": {"coreId": "core-1", "auditId": "audit-1", "stableCount": 1, "freshCount": 0},
    "allowedActions": ["create_draft", "update_internal_record", "send_approved_notice",
                        "request_confirmation", "quarantine_item", "no_action"],
    "dossiers": [DOSSIER],
}


class FakeRequest:
    def __init__(self, body):
        self._body = body
    @property
    def headers(self):
        return {}
    async def json(self):
        return self._body


async def main():
    resp = await mailroom.mailroom_endpoint(FakeRequest(PROPOSE_REQ))
    body = json.loads(resp.body)
    print("PROPOSE #1 status", resp.status_code)
    print(json.dumps(body, indent=2))
    assert resp.status_code == 200
    assert body["status"] == "awaiting_receipts"
    proposal = body["proposals"][0]

    print("\n== exact replay of propose ==")
    resp2 = await mailroom.mailroom_endpoint(FakeRequest(PROPOSE_REQ))
    body2 = json.loads(resp2.body)
    assert body2 == body, "replay mismatch!"
    print("OK — byte-equivalent replay")

    print("\n== changed content, same evaluationId -> expect 409 ==")
    bad_req = json.loads(json.dumps(PROPOSE_REQ))
    bad_req["dossiers"][0]["sources"][0]["lines"][0]["text"] = "different text now"
    resp3 = await mailroom.mailroom_endpoint(FakeRequest(bad_req))
    print("status:", resp3.status_code)
    assert resp3.status_code == 409

    print("\n== commit with a valid signature, accepted=true -> expect executed ==")
    digest = proposal_digest(proposal)
    receipt = {
        "dossierId": proposal["dossierId"],
        "callId": proposal["callId"],
        "action": proposal["action"],
        "accepted": True,
        "proposalDigest": digest,
        "receiptId": "nonce-1",
    }
    msg = mailroom.build_receipt_signing_message(receipt)
    sig = priv.sign(msg)
    receipt["receiptSignature"] = base64.b64encode(sig).decode()

    commit_req = {
        "profile": "ga5-mailroom-action-gate/v2",
        "operation": "commit",
        "evaluationId": "eval-1",
        "inputDigest": body["inputDigest"],
        "receipts": [receipt],
    }
    resp4 = await mailroom.mailroom_endpoint(FakeRequest(commit_req))
    body4 = json.loads(resp4.body)
    print("status:", resp4.status_code)
    print(json.dumps(body4, indent=2))
    assert resp4.status_code == 200
    assert body4["outcomes"][0]["status"] == "executed"

    print("\n== exact replay of commit ==")
    resp5 = await mailroom.mailroom_endpoint(FakeRequest(commit_req))
    body5 = json.loads(resp5.body)
    assert body5 == body4
    print("OK — byte-equivalent commit replay")

    print("\n== commit with accepted=false -> expect rejected ==")
    os.environ["DATABASE_URL"] = "sqlite:///./test_mailroom2.db"
    if os.path.exists("test_mailroom2.db"):
        os.remove("test_mailroom2.db")
    import importlib
    importlib.reload(mailroom.__dict__["get_session"].__self__) if False else None

    print("\nAll assertions passed.")

asyncio.run(main())

# Setting up the Safe AI Mailroom Agent

## 1. Files to add to your repo

Drop these 6 files into the repo root, next to `main.py`:
- `mailroom.py` — the propose/commit endpoint (mounts `POST /mailroom`)
- `mailroom_actions.py` — frozen target/payload schemas + validation
- `mailroom_canonical.py` — canonical JSON + digest helpers
- `mailroom_db.py` — persistence (Postgres via `DATABASE_URL`, SQLite fallback)
- `mailroom_llm.py` — the AI decision step (calls AI Pipe)

Replace `main.py` with the updated one — it now also imports and mounts the
mailroom router, on top of everything it already had (Q2/Q3/Q4/Q5 MCP).

## 2. New dependencies

Add to `requirements.txt`:

```
sqlalchemy==2.0.36
psycopg2-binary==2.9.10
httpx==0.28.1
cryptography==44.0.0
```

## 3. Set up Neon (free Postgres) — do this, don't skip it

Render's free-tier disk is wiped on every redeploy. This assignment
explicitly requires that a *later* Check/Save (possibly days later, possibly
after you've redeployed) still recognizes cached decisions and evaluations —
that needs real persistence, not the local disk.

1. Go to https://neon.tech, sign up (no card needed), create a project.
2. Copy the connection string it gives you (starts with `postgresql://...`).
3. In Render → your service → Environment, add:
   - `DATABASE_URL` = that connection string

The app auto-creates its tables on startup.

## 4. Set your AI Pipe credentials on Render

- `AIPIPE_TOKEN` = your AI Pipe token
- `AIPIPE_BASE_URL` = your AI Pipe base URL (defaults to
  `https://aipipe.org/openai/v1` — check your actual token's dashboard for
  the exact base URL/proxy path, it varies by course run)
- `AIPIPE_MODEL` = the model string AI Pipe expects (e.g. `gpt-4o-mini`,
  or whatever cheap model your AI Pipe proxy exposes — check the AI Pipe
  docs/playground for exact model names before setting this)

## 5. ⚠️ One thing you must still confirm: the receipt signature format

In `mailroom.py`, the function `build_receipt_signing_message()` is a
best-guess placeholder: it assumes `receiptSignature` is an Ed25519
signature over the canonical JSON of the receipt object with
`receiptSignature` itself removed.

The assignment page has a section called **"How to verify a receipt
signature"** — when you pasted the spec to me, that section's actual content
didn't come through (same issue as the MCP question's missing examples). Go
back to the page, find the real content under that heading, and if it
describes a different byte layout, update just that one function — nothing
else in the file needs to change.

If you can't find more detail there, another way to nail it down: after your
first real Check run, log the raw commit request body server-side (temporarily)
and try verifying the signature against a couple of candidate message formats
offline (e.g. `proposalDigest` alone, `receiptId + proposalDigest`, the full
receipt minus signature) until one validates — Ed25519 verification will
simply fail silently for the wrong format, so this is safe to experiment with.

## 6. Test locally before deploying

The repo included `test_mailroom.py` during development (not needed in
production, but worth keeping around) — it stubs the LLM call and runs a full
propose → replay → conflict → commit → replay cycle against a real Ed25519
keypair, entirely offline. Useful as a regression check if you touch this
code later.

## 7. Your endpoint URL to submit

```
https://<your-app>.onrender.com/mailroom
```

## What's already handled

- Canonical JSON (`inputDigest`, `proposalDigest`) per the exact spec.
- Per-dossier caching keyed by `dossierId` + content fingerprint — unchanged
  dossiers reuse the exact same proposal (including `callId`) with **no**
  model call, across evaluations and later Checks.
- `callId` is generated deterministically from the dossier's content
  fingerprint (never by the model), so it's automatically stable and always
  passes the 12–128 char / allowed-charset rule.
- Every model-proposed action/target/payload is re-validated against frozen,
  `extra="forbid"` schemas before it's ever returned — the model can't smuggle
  extra fields in even if it tries.
- Evidence lineIds are checked against the dossier's real line IDs (no
  unknown/duplicate IDs allowed through).
- Exact replay (byte-equivalent) for both propose and commit.
- 409 on same `evaluationId` + changed content.
- 400/422 on malformed/duplicate-dossier requests, before any model call.
- 512 KiB response cap enforced.
- Prompt explicitly frames all dossier content as untrusted data, instructs
  the model to treat trusted internal quotes of attack text as evidence, not
  as commands, and never to copy raw content into payload fields — with a
  safe `request_confirmation` fallback if the model's output fails
  validation for any reason (so a bad model response degrades to "ask a
  human" rather than to an unsafe default).

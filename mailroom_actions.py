"""
Frozen target/payload schemas per action, enforced with extra="forbid" so the
model can never sneak an unauthorized field into a tool call. This is the
last line of defense before a proposal is accepted into the response — even
if the LLM hallucinates fields, they get rejected here, not shipped.
"""
from typing import Literal, Optional

from pydantic import BaseModel, ConfigDict, ValidationError

ALLOWED_ACTIONS = [
    "create_draft",
    "update_internal_record",
    "send_approved_notice",
    "request_confirmation",
    "quarantine_item",
    "no_action",
]


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


# ---- targets ----

class DraftQueueTarget(StrictModel):
    kind: Literal["draft_queue"]
    id: str


class CaseRecordTarget(StrictModel):
    kind: Literal["case_record"]
    id: str


class EmailTarget(StrictModel):
    kind: Literal["email"]
    id: str


class ApprovalQueueTarget(StrictModel):
    kind: Literal["approval_queue"]
    id: str


class SecurityQueueTarget(StrictModel):
    kind: Literal["security_queue"]
    id: str


# ---- payloads ----

class CreateDraftPayload(StrictModel):
    recipient: str
    referenceId: str
    status: str
    template: Literal["order_status"]


class UpdateInternalRecordPayload(StrictModel):
    field: Literal["delivery_window"]
    sourceEventId: str
    value: str


class SendApprovedNoticePayload(StrictModel):
    referenceId: str
    status: str
    template: Literal["approved_delivery_notice"]


class RequestConfirmationPayload(StrictModel):
    claimedSender: str
    questionCode: Literal["VERIFY_REQUEST"]
    referenceId: str


class QuarantineItemPayload(StrictModel):
    artifactId: str
    reasonCode: Literal["INDIRECT_PROMPT_INJECTION"]


class NoActionPayload(StrictModel):
    reasonCode: Literal["ALREADY_COMPLETED", "DUPLICATE", "INFORMATIONAL"]
    referenceId: str


ACTION_SPEC = {
    "create_draft": (DraftQueueTarget, CreateDraftPayload),
    "update_internal_record": (CaseRecordTarget, UpdateInternalRecordPayload),
    "send_approved_notice": (EmailTarget, SendApprovedNoticePayload),
    "request_confirmation": (ApprovalQueueTarget, RequestConfirmationPayload),
    "quarantine_item": (SecurityQueueTarget, QuarantineItemPayload),
    "no_action": (None, NoActionPayload),
}


class ActionValidationError(Exception):
    pass


def validate_proposal_shape(action: str, target: Optional[dict], payload: dict) -> None:
    """Raises ActionValidationError if action/target/payload don't exactly
    match the frozen shape for that action. Call this on every proposal
    before it's ever returned to the grader or persisted."""
    if action not in ACTION_SPEC:
        raise ActionValidationError(f"unknown action: {action}")

    target_model, payload_model = ACTION_SPEC[action]

    if target_model is None:
        if target is not None:
            raise ActionValidationError(f"{action} must have target: null")
    else:
        if target is None:
            raise ActionValidationError(f"{action} requires a target")
        try:
            target_model.model_validate(target)
        except ValidationError as e:
            raise ActionValidationError(f"bad target for {action}: {e}") from e

    try:
        payload_model.model_validate(payload or {})
    except ValidationError as e:
        raise ActionValidationError(f"bad payload for {action}: {e}") from e


def validate_evidence(evidence: list, valid_line_ids: set) -> None:
    if not evidence:
        raise ActionValidationError("evidence must be non-empty")
    seen = set()
    for line_id in evidence:
        if line_id not in valid_line_ids:
            raise ActionValidationError(f"unknown lineId in evidence: {line_id}")
        if line_id in seen:
            raise ActionValidationError(f"duplicate lineId in evidence: {line_id}")
        seen.add(line_id)


CALL_ID_RE_ALLOWED = set(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._:-"
)


def validate_call_id(call_id: str) -> None:
    if not (12 <= len(call_id) <= 128):
        raise ActionValidationError("callId must be 12-128 chars")
    if not set(call_id) <= CALL_ID_RE_ALLOWED:
        raise ActionValidationError("callId has invalid characters")

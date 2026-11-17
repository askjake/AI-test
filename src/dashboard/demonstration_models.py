"""Strict Phase 17 Watch & Learn data contracts.

These models deliberately describe intent and provenance, never an executable
coordinate recording.  Captured values are untrusted data throughout their
lifetime and a learned draft has no run or target authority.
"""
from __future__ import annotations

import re
from typing import Annotated, Literal, Union

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


TargetType = Literal["local-app", "host-app", "ssh-terminal", "rdp", "vnc"]
SessionState = Literal[
    "ready_to_connect",
    "connecting",
    "connected_unauthenticated_paused",
    "connected_paused",
    "recording",
    "paused",
    "stopped",
    "reviewing",
    "deterministic_ready",
    "reconciliation_required",
    "connection_failed",
    "capture_failed",
    "deletion_pending",
]
ReceiptOutcome = Literal[
    "accepted", "executed", "rejected", "failed", "outcome_unknown"
]
ModelJobState = Literal[
    "queued", "running", "completed", "failed", "expired", "stale"
]
OwnershipMode = Literal["unique-identity", "shared-bootstrap", "shared-operator"]
EvidenceAccessState = Literal["available", "redaction_pending", "redaction_failed"]


_SENSITIVE_VALUE_RE = re.compile(
    r"(?:"
    r"(?:\b(?:password|passwd|pwd|token|secret|cookie|api[_ -]?key|access[_ -]?key|"
    r"connection[_ -]?string|private[_ -]?key|credential)s?\b)"
    r"|"
    r"(?:(?:password|passwd|pwd|token|secret|cookie|api[_ -]?key|access[_ -]?key|"
    r"connection[_ -]?string|private[_ -]?key|credential)\s*[:=]\s*\S+)"
    r"|(?:bearer\s+\S+)"
    r"|(?:(?:postgres|mysql|mongodb|redis|amqp)s?://[^\s/@:]+:[^\s/@]+@[^\s]+)"
    r"|(?:-----BEGIN [A-Z ]+PRIVATE KEY-----)"
    r"|(?:AKIA[0-9A-Z]{16})"
    r"|(?:[A-Za-z0-9+/]{40,}={0,2})"
    r")",
    re.IGNORECASE,
)


def reject_sensitive_untrusted_text(value: str) -> str:
    """Reject credential-shaped values without reflecting them in an error."""
    if any(ord(char) < 32 and char not in "\n\r\t" for char in value):
        raise ValueError("Text contains prohibited control characters.")
    if _SENSITIVE_VALUE_RE.search(value):
        raise ValueError("Sensitive credential material is prohibited.")
    return value


class TargetCapability(_StrictModel):
    target_type: TargetType
    available: bool
    reason_code: str = Field(min_length=2, max_length=80)
    detail: str = Field(min_length=2, max_length=300)


class DemonstrationCapabilities(_StrictModel):
    project_name: str = Field(min_length=1, max_length=120)
    project_revision: str = Field(min_length=64, max_length=64)
    target_revision: str = Field(min_length=64, max_length=64)
    privacy_revision: str = Field(min_length=64, max_length=64)
    target_type: TargetType
    selected: TargetCapability
    target_types: list[TargetCapability] = Field(min_length=5, max_length=5)
    contacts_target: Literal[False] = False
    capture_starts_paused: Literal[True] = True
    deterministic_analysis_required: Literal[True] = True
    ownership_mode: OwnershipMode
    ownership_notice: str = Field(min_length=2, max_length=300)
    identity_eligible: bool
    privacy_ready: bool
    privacy_notice: str = Field(min_length=2, max_length=300)
    connect_authorized: bool
    connect_notice: str = Field(min_length=2, max_length=300)
    preflight_expires_at: str | None = None
    session_proof_configured: bool = False
    session_proof_notice: str = Field(default="Session proof is not configured.", min_length=2, max_length=300)
    secure_secret_entry_available: Literal[True] = True
    model_enrichment_available: bool = False
    visual_enrichment_available: bool = False
    imported_project: bool = False
    readiness_configuration_required: bool = False
    readiness_check_passed: bool = False
    target_contact_activated: bool = False
    readiness_configuration_revision: str | None = Field(
        default=None, min_length=64, max_length=64, pattern=r"^[a-f0-9]{64}$"
    )


class CreateDemonstrationRequest(_StrictModel):
    project_name: str = Field(min_length=1, max_length=120)
    project_revision: str = Field(min_length=64, max_length=64)
    target_revision: str = Field(min_length=64, max_length=64)
    privacy_revision: str = Field(min_length=64, max_length=64)
    operator_goal: str = Field(min_length=1, max_length=2_000)
    readiness_configuration_revision: str | None = Field(
        default=None, min_length=64, max_length=64, pattern=r"^[a-f0-9]{64}$"
    )

    @field_validator("operator_goal")
    @classmethod
    def _nonsecret_goal(cls, value: str) -> str:
        return reject_sensitive_untrusted_text(value)


class VersionedRequest(_StrictModel):
    expected_version: int = Field(ge=1)


class ConnectDemonstrationRequest(VersionedRequest):
    project_revision: str = Field(min_length=64, max_length=64)
    target_revision: str = Field(min_length=64, max_length=64)
    privacy_revision: str = Field(min_length=64, max_length=64)


class _ActionModel(_StrictModel):
    """Version every browser-to-runner input contract explicitly."""

    schema_version: Literal[1] = 1


class _FrameBoundAction(_ActionModel):
    """Bind coordinate input to the immutable, sanitized frame the owner saw."""

    frame_revision: str = Field(min_length=64, max_length=64, pattern=r"^[a-f0-9]{64}$")
    frame_width: int = Field(ge=1, le=8_192)
    frame_height: int = Field(ge=1, le=8_192)

    def _point_in_frame(self, x: int, y: int) -> None:
        if x >= self.frame_width or y >= self.frame_height:
            raise ValueError("Pointer coordinate is outside the bound target frame.")


class PointAction(_FrameBoundAction):
    kind: Literal["click"] = "click"
    x: int = Field(ge=0, le=16_383)
    y: int = Field(ge=0, le=16_383)
    button: Literal["left", "middle", "right"] = "left"
    clicks: Literal[1, 2] = 1

    @model_validator(mode="after")
    def _inside_frame(self):
        self._point_in_frame(self.x, self.y)
        return self


class PointerButtonAction(_FrameBoundAction):
    kind: Literal["pointer_button"] = "pointer_button"
    phase: Literal["down", "up"]
    x: int = Field(ge=0, le=16_383)
    y: int = Field(ge=0, le=16_383)
    button: Literal["left", "middle", "right"] = "left"

    @model_validator(mode="after")
    def _inside_frame(self):
        self._point_in_frame(self.x, self.y)
        return self


class PointerMoveAction(_FrameBoundAction):
    kind: Literal["pointer_move"] = "pointer_move"
    x: int = Field(ge=0, le=16_383)
    y: int = Field(ge=0, le=16_383)
    during_drag: bool = False

    @model_validator(mode="after")
    def _inside_frame(self):
        self._point_in_frame(self.x, self.y)
        return self


class DragPoint(_StrictModel):
    x: int = Field(ge=0, le=16_383)
    y: int = Field(ge=0, le=16_383)


class DragAction(_FrameBoundAction):
    kind: Literal["drag"] = "drag"
    button: Literal["left", "middle"] = "left"
    start_x: int = Field(ge=0, le=16_383)
    start_y: int = Field(ge=0, le=16_383)
    end_x: int = Field(ge=0, le=16_383)
    end_y: int = Field(ge=0, le=16_383)
    path: list[DragPoint] = Field(default_factory=list, max_length=32)

    @model_validator(mode="after")
    def _bounded_path(self):
        self._point_in_frame(self.start_x, self.start_y)
        self._point_in_frame(self.end_x, self.end_y)
        for point in self.path:
            self._point_in_frame(point.x, point.y)
        if self.start_x == self.end_x and self.start_y == self.end_y and not self.path:
            raise ValueError("Drag must have a distinct end point or path sample.")
        return self


class WheelAction(_FrameBoundAction):
    kind: Literal["wheel"] = "wheel"
    x: int = Field(ge=0, le=16_383)
    y: int = Field(ge=0, le=16_383)
    delta_x: int = Field(ge=-20, le=20)
    delta_y: int = Field(ge=-20, le=20)

    @model_validator(mode="after")
    def _bounded_delta(self):
        self._point_in_frame(self.x, self.y)
        if self.delta_x == 0 and self.delta_y == 0:
            raise ValueError("Wheel action requires a non-zero bounded delta.")
        return self


class SemanticTextIntent(_ActionModel):
    """Text-entry provenance with deliberately no browser-supplied value."""

    kind: Literal["text_intent"] = "text_intent"
    purpose: Literal["enter-approved-nonsecret-value"] = "enter-approved-nonsecret-value"


class SecretTextAction(_ActionModel):
    """Worker-local secret entry; capture receives only a safe reference name."""

    kind: Literal["secret_text"] = "secret_text"
    purpose: Literal["establish-approved-session"] = "establish-approved-session"
    secret_reference: str = Field(
        min_length=1,
        max_length=127,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]*$",
    )


class KeyAction(_ActionModel):
    kind: Literal["key"] = "key"
    key: Literal[
        "ENTER", "TAB", "ESC", "UP", "DOWN", "LEFT", "RIGHT",
        "HOME", "END", "PAGEUP", "PAGEDOWN", "BACKSPACE", "DELETE", "A",
    ]
    phase: Literal["press", "down", "up"] = "press"
    modifiers: list[Literal["CTRL", "SHIFT"]] = Field(default_factory=list, max_length=1)
    repeat: int = Field(default=1, ge=1, le=3)

    @model_validator(mode="after")
    def _allowlisted_chord(self):
        if len(set(self.modifiers)) != len(self.modifiers):
            raise ValueError("Duplicate key modifiers are prohibited.")
        chord = (tuple(self.modifiers), self.key)
        if self.modifiers and chord not in {(('SHIFT',), 'TAB'), (('CTRL',), 'A')}:
            raise ValueError("Key modifier combination is not allowlisted.")
        if self.key == "A" and chord != (("CTRL",), "A"):
            raise ValueError("The A key is allowed only as Ctrl+A.")
        if self.phase != "press" and (self.modifiers or self.repeat != 1):
            raise ValueError("Key down/up lifecycle events cannot carry modifiers or repeats.")
        return self


class ScrollAction(_ActionModel):
    kind: Literal["scroll"] = "scroll"
    direction: Literal["up", "down"]
    amount: int = Field(ge=1, le=20)


CaptureAction = Annotated[
    Union[
        PointAction,
        PointerButtonAction,
        PointerMoveAction,
        DragAction,
        WheelAction,
        SemanticTextIntent,
        SecretTextAction,
        KeyAction,
        ScrollAction,
    ],
    Field(discriminator="kind"),
]


class CaptureActionRequest(VersionedRequest):
    idempotency_key: str = Field(
        min_length=8, max_length=80, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]*$"
    )
    action: CaptureAction

    @model_validator(mode="after")
    def _bounded(self):
        if len(self.model_dump_json()) > 4_096:
            raise ValueError("Capture action exceeds the bounded request size.")
        return self


class SanitizedIntent(_StrictModel):
    kind: Literal[
        "click", "pointer_button", "pointer_move", "drag", "wheel",
        "text_intent", "secret_text", "key", "scroll",
    ]
    summary: str = Field(min_length=1, max_length=160)


class IntentJournalRecord(_StrictModel):
    event_id: str = Field(min_length=16, max_length=64)
    idempotency_key: str = Field(min_length=8, max_length=80)
    session_version: int = Field(ge=1)
    intent: SanitizedIntent
    action_fingerprint: str | None = Field(
        default=None, min_length=64, max_length=64, pattern=r"^[a-f0-9]{64}$"
    )
    journaled_at: str
    dispatch_started_at: str | None = None


class ActionReceipt(_StrictModel):
    event_id: str = Field(min_length=16, max_length=64)
    idempotency_key: str = Field(min_length=8, max_length=80)
    outcome: ReceiptOutcome
    detail: str = Field(min_length=1, max_length=300)
    recorded_at: str
    evidence_id: str | None = Field(default=None, min_length=16, max_length=64)


class RedactionRegion(_StrictModel):
    x: int = Field(ge=0, le=8_191)
    y: int = Field(ge=0, le=8_191)
    width: int = Field(ge=1, le=8_192)
    height: int = Field(ge=1, le=8_192)


class EvidenceRecord(_StrictModel):
    evidence_id: str = Field(min_length=16, max_length=64)
    event_id: str = Field(min_length=16, max_length=64)
    mime_type: Literal["image/png"] = "image/png"
    byte_length: int = Field(ge=1)
    sha256: str = Field(min_length=64, max_length=64)
    width: int = Field(ge=1, le=8_192)
    height: int = Field(ge=1, le=8_192)
    created_at: str
    redacted_at: str | None = None
    access_state: EvidenceAccessState = "available"
    pending_redactions: list[RedactionRegion] = Field(default_factory=list, max_length=64)


class Annotation(_StrictModel):
    annotation_id: str = Field(min_length=16, max_length=64)
    event_id: str = Field(min_length=16, max_length=64)
    note: str = Field(min_length=1, max_length=1_000)
    control_label: str | None = Field(default=None, min_length=1, max_length=160)
    expected_result: str | None = Field(default=None, min_length=1, max_length=500)
    variable_name: str | None = Field(
        default=None, min_length=1, max_length=80, pattern=r"^[A-Za-z][A-Za-z0-9_]*$"
    )
    created_at: str
    updated_at: str

    @field_validator("note", "control_label", "expected_result")
    @classmethod
    def _nonsecret_note(cls, value: str | None) -> str | None:
        return reject_sensitive_untrusted_text(value) if value is not None else None


class AnnotationRequest(VersionedRequest):
    event_id: str = Field(min_length=16, max_length=64)
    note: str = Field(min_length=1, max_length=1_000)
    control_label: str | None = Field(default=None, min_length=1, max_length=160)
    expected_result: str | None = Field(default=None, min_length=1, max_length=500)
    variable_name: str | None = Field(
        default=None, min_length=1, max_length=80, pattern=r"^[A-Za-z][A-Za-z0-9_]*$"
    )

    @field_validator("note", "control_label", "expected_result")
    @classmethod
    def _nonsecret_note(cls, value: str | None) -> str | None:
        return reject_sensitive_untrusted_text(value) if value is not None else None


class RedactEvidenceRequest(VersionedRequest):
    regions: list[RedactionRegion] = Field(min_length=1, max_length=64)


class LearnedStep(_StrictModel):
    order: int = Field(ge=1, le=500)
    instruction: str = Field(min_length=1, max_length=500)
    source_event_ids: list[str] = Field(min_length=1, max_length=20)
    source_evidence_ids: list[str] = Field(default_factory=list, max_length=20)
    confidence: Literal["low", "medium", "high"] = "low"

    @field_validator("instruction")
    @classmethod
    def _nonsecret_instruction(cls, value: str) -> str:
        return reject_sensitive_untrusted_text(value)


class SemanticObservation(_StrictModel):
    """Bounded deterministic fact derived from already-redacted PNG evidence."""

    observation_id: str = Field(min_length=16, max_length=64)
    source_event_id: str = Field(min_length=16, max_length=64)
    source_evidence_ids: list[str] = Field(default_factory=list, max_length=2)
    kind: Literal["visual-change", "no-visible-change", "semantic-intent"]
    summary: str = Field(min_length=1, max_length=300)
    confidence: Literal["low", "medium", "high"]
    changed_fraction: float | None = Field(default=None, ge=0.0, le=1.0)
    changed_region: Literal[
        "upper-left", "upper-center", "upper-right", "middle-left", "center",
        "middle-right", "lower-left", "lower-center", "lower-right", "distributed",
    ] | None = None


class LearnedDraft(_StrictModel):
    analysis_id: str = Field(min_length=16, max_length=64)
    kind: Literal["deterministic", "model_enriched"]
    source_session_id: str = Field(min_length=16, max_length=64)
    source_version: int = Field(ge=1)
    project_revision: str = Field(min_length=64, max_length=64)
    target_revision: str = Field(min_length=64, max_length=64)
    title: str = Field(min_length=1, max_length=160)
    goal: str = Field(min_length=1, max_length=2_000)
    preconditions: list[str] = Field(default_factory=list, max_length=50)
    steps: list[LearnedStep] = Field(default_factory=list, max_length=500)
    variables: list[str] = Field(default_factory=list, max_length=100)
    assertions: list[str] = Field(default_factory=list, max_length=100)
    gaps: list[str] = Field(default_factory=list, max_length=100)
    observations: list[SemanticObservation] = Field(default_factory=list, max_length=500)
    confidence: Literal["low", "medium", "high"]
    review_required: Literal[True] = True
    created_at: str

    @field_validator("title", "goal")
    @classmethod
    def _nonsecret_scalar(cls, value: str) -> str:
        return reject_sensitive_untrusted_text(value)

    @field_validator("preconditions", "variables", "assertions", "gaps")
    @classmethod
    def _nonsecret_lists(cls, values: list[str]) -> list[str]:
        return [reject_sensitive_untrusted_text(value) for value in values]


class ModelDraftContent(_StrictModel):
    """Only the editable content a text-only model may propose.

    Identity, version, provenance, authority, and review flags remain
    server-derived and are intentionally absent from this schema.
    """

    title: str = Field(min_length=1, max_length=160)
    goal: str = Field(min_length=1, max_length=2_000)
    preconditions: list[str] = Field(default_factory=list, max_length=50)
    steps: list[LearnedStep] = Field(default_factory=list, max_length=500)
    variables: list[str] = Field(default_factory=list, max_length=100)
    assertions: list[str] = Field(default_factory=list, max_length=100)
    gaps: list[str] = Field(default_factory=list, max_length=100)
    confidence: Literal["low", "medium", "high"]

    @field_validator("title", "goal")
    @classmethod
    def _nonsecret_scalar(cls, value: str) -> str:
        return reject_sensitive_untrusted_text(value)

    @field_validator("preconditions", "variables", "assertions", "gaps")
    @classmethod
    def _nonsecret_lists(cls, values: list[str]) -> list[str]:
        return [reject_sensitive_untrusted_text(value) for value in values]


class ModelEnrichmentRequest(VersionedRequest):
    deterministic_analysis_id: str = Field(min_length=16, max_length=64)
    include_visual_evidence: bool = False


class ModelJob(_StrictModel):
    job_id: str = Field(min_length=16, max_length=64)
    session_id: str = Field(min_length=16, max_length=64)
    deterministic_analysis_id: str = Field(min_length=16, max_length=64)
    source_version: int = Field(ge=1)
    state: ModelJobState
    created_at: str
    updated_at: str
    result: LearnedDraft | None = None
    error_code: str | None = Field(default=None, max_length=80)
    include_visual_evidence: bool = False


class PromotionPreview(_StrictModel):
    session_id: str = Field(min_length=16, max_length=64)
    source_analysis_id: str = Field(min_length=16, max_length=64)
    source_version: int = Field(ge=1)
    project_name: str = Field(min_length=1, max_length=120)
    spec_path: str = Field(min_length=1, max_length=240)
    title: str = Field(min_length=1, max_length=160)
    goal: str = Field(min_length=1, max_length=2_000)
    setup: str | None = Field(default=None, max_length=4_000)
    assertions: list[str] = Field(default_factory=list, max_length=100)
    valid: bool
    diagnostics: list[str] = Field(default_factory=list, max_length=100)


class PromoteRequest(VersionedRequest):
    analysis_id: str = Field(min_length=16, max_length=64)
    spec_path: str = Field(
        min_length=4, max_length=240, pattern=r"^[A-Za-z0-9][A-Za-z0-9_./-]*\.md$"
    )


class PrivateDraftContent(_StrictModel):
    title: str = Field(min_length=1, max_length=160)
    goal: str = Field(min_length=1, max_length=2_000)
    setup: str | None = Field(default=None, max_length=4_000)
    assertions: list[str] = Field(default_factory=list, max_length=100)

    @field_validator("title", "goal", "setup")
    @classmethod
    def _nonsecret_scalars(cls, value: str | None) -> str | None:
        return reject_sensitive_untrusted_text(value) if value is not None else None

    @field_validator("assertions")
    @classmethod
    def _nonsecret_assertions(cls, values: list[str]) -> list[str]:
        return [reject_sensitive_untrusted_text(value) for value in values]


class PrivateLearnedDraft(_StrictModel):
    draft_id: str = Field(min_length=16, max_length=64)
    source_analysis_id: str = Field(min_length=16, max_length=64)
    source_session_id: str = Field(min_length=16, max_length=64)
    source_version: int = Field(ge=1)
    project_name: str = Field(min_length=1, max_length=120)
    export_path: str = Field(min_length=4, max_length=240)
    draft_version: int = Field(ge=1)
    revision: str = Field(min_length=64, max_length=64)
    content: PrivateDraftContent
    authority: Literal["none"] = "none"
    review_required: Literal[True] = True
    created_at: str
    updated_at: str


class PrivateDraftUpdateRequest(VersionedRequest):
    expected_draft_version: int = Field(ge=1)
    content: PrivateDraftContent


class DemonstrationSession(_StrictModel):
    session_id: str = Field(min_length=16, max_length=64)
    owner_principal: str = Field(min_length=64, max_length=64)
    ownership_mode: OwnershipMode
    ownership_notice: str = Field(min_length=2, max_length=300)
    project_name: str = Field(min_length=1, max_length=120)
    project_revision: str = Field(min_length=64, max_length=64)
    target_revision: str = Field(min_length=64, max_length=64)
    privacy_revision: str = Field(min_length=64, max_length=64)
    target_type: TargetType
    readiness_configuration_revision: str | None = Field(
        default=None, min_length=64, max_length=64, pattern=r"^[a-f0-9]{64}$"
    )
    frame_contract_width: int | None = Field(default=None, ge=1, le=8192)
    frame_contract_height: int | None = Field(default=None, ge=1, le=8192)
    operator_goal: str = Field(min_length=1, max_length=2_000)
    state: SessionState
    version: int = Field(ge=1)
    created_at: str
    updated_at: str
    journals: list[IntentJournalRecord] = Field(default_factory=list, max_length=500)
    receipts: list[ActionReceipt] = Field(default_factory=list, max_length=500)
    evidence: list[EvidenceRecord] = Field(default_factory=list, max_length=500)
    annotations: list[Annotation] = Field(default_factory=list, max_length=500)
    analyses: list[LearnedDraft] = Field(default_factory=list, max_length=20)
    model_jobs: list[ModelJob] = Field(default_factory=list, max_length=20)
    private_drafts: list[PrivateLearnedDraft] = Field(default_factory=list, max_length=20)

    @field_validator("operator_goal")
    @classmethod
    def _nonsecret_goal(cls, value: str) -> str:
        return reject_sensitive_untrusted_text(value)


class DemonstrationSummary(_StrictModel):
    session_id: str
    project_name: str
    target_type: TargetType
    state: SessionState
    version: int
    created_at: str
    updated_at: str


class CaptureActionResponse(_StrictModel):
    session: DemonstrationSession
    receipt: ActionReceipt


class PromotionResult(_StrictModel):
    session: DemonstrationSession
    draft: PrivateLearnedDraft


class DeleteDemonstrationRequest(VersionedRequest):
    pass


class DeletionStatus(_StrictModel):
    session_id: str = Field(min_length=16, max_length=64)
    state: Literal["active", "pending", "deleted"]
    terminal: bool

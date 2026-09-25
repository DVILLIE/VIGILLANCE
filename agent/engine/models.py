"""Finding fields from Function Spec §4. Stored as JSON in AgentStore."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

PILLARS = ("safety", "speed", "privacy", "ai_data", "storage", "footprint", "camera")
QUIET = ("quiet", "quiet_never_warn", "quiet_baseline")


@dataclass
class Option:
    id: str
    label: str
    what_we_will_do: str
    effect: str
    decision: str | None = None
    handler: str | None = None
    resulting_status: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Option:
        return cls(
            id=data["id"],
            label=data["label"],
            what_we_will_do=data["what_we_will_do"],
            effect=data["effect"],
            decision=data.get("decision"),
            handler=data.get("handler"),
            resulting_status=data.get("resulting_status"),
        )


@dataclass
class Observation:
    pillar: str
    kind: str
    subject_identity: str
    title_simple: str
    why_it_matters: str
    if_ignored: str
    evidence_refs: list[str]
    severity: str
    confidence: str
    recommended_action: str
    resolution_steps: list[str]
    reversible: str
    identity_ok: bool
    expected: bool
    suspicious_mismatch: bool
    signals: dict[str, Any] = field(default_factory=dict)
    action_class: str = "ask_user"
    quiet_on_allow: bool = True
    baseline_expected: bool = False


@dataclass(frozen=True)
class KeepOnMatch:
    code: str
    disposition: str


@dataclass(frozen=True)
class AuthToken:
    finding_id: str
    handler: str
    nonce: str


class PolicyDenied(Exception):
    """A mutation was requested without a selected option."""


class FailClosed(Exception):
    """Identity or catalog is too unclear to continue."""

"""Evidence model — shared language for Why / Cortex (schema seed).

Pipeline (binding):
  Observation → Evidence → Correlation → Finding → Decision → Action → Verification

SQLite remains persistence; these objects are the conceptual model.
Level ≥2 actions must carry confidence + rollback semantics (Master Architecture).
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Literal
from uuid import uuid4

ActionLevel = Literal[0, 1, 2, 3, 4, 5]
Impact = Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class Observation:
    id: str
    ts: str
    sensor: str
    entity: str | None
    payload: dict[str, Any]
    cadence: str  # event | heartbeat | pulse | idle_deep | emergency

    @staticmethod
    def make(sensor: str, payload: dict[str, Any], *, entity: str | None = None, cadence: str = "pulse") -> Observation:
        return Observation(
            id=str(uuid4()),
            ts=_utc_now(),
            sensor=sensor,
            entity=entity,
            payload=payload,
            cadence=cadence,
        )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Finding:
    id: str
    ts: str
    finding: str
    entity: str | None
    risk: float  # 0–100
    confidence: float  # 0–1
    impact: Impact
    workload: str | None
    evidence_ids: list[str] = field(default_factory=list)
    reason: str = ""
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Decision:
    id: str
    ts: str
    finding_id: str
    recommended_action: str  # OBSERVE | EXPLAIN | RECOMMEND | RESTRICT | ...
    action_level: ActionLevel
    confidence: float
    reversible: bool
    rollback_token: str | None = None
    reason: str = ""
    evidence_summary: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def why_card(decision: Decision, finding: Finding | None = None) -> dict[str, Any]:
    """Mission Console WHY surface payload."""
    return {
        "decision": decision.recommended_action,
        "action_level": decision.action_level,
        "confidence": decision.confidence,
        "reversible": decision.reversible,
        "rollback": "Available" if decision.reversible and decision.rollback_token else "N/A",
        "reason": decision.reason or (finding.reason if finding else ""),
        "impact": finding.impact if finding else None,
        "workload": finding.workload if finding else None,
        "risk": finding.risk if finding else None,
        "evidence": decision.evidence_summary,
        "finding": finding.finding if finding else None,
        "entity": finding.entity if finding else None,
    }

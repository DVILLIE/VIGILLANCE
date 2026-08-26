"""Policy Cortex + Action Executor — Level ≥2 mutations (P0.2 / P0.9 / P0.10).

Hard invariant: only ActionExecutor may mutate system state, and only with a
Cortex-issued Decision ID + evidence/confidence/policy fields.

NIST CSF 2.0 supports separating Identify/Detect from Respond/Recover conceptually;
this module is our product architecture, not a NIST prescription.
"""

from __future__ import annotations

import logging
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable
from uuid import uuid4

from agent.store.db import AgentStore

logger = logging.getLogger("dvielle.policy")

LEVEL_OBSERVE = 0
LEVEL_EXPLAIN = 1
LEVEL_RECOMMEND = 2
LEVEL_REVERSIBLE = 3
LEVEL_ADMIN = 4
LEVEL_EMERGENCY = 5


def _utc() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class Decision:
    decision_id: str
    finding_id: str | None
    action: str
    action_level: int
    confidence: float
    evidence_summary: list[str]
    policy: str
    target: str
    reversible: bool
    rollback_plan: str | None
    initiator: str
    ts: str = field(default_factory=_utc)
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class PolicyCortex:
    """Issues Decision IDs. Does not mutate Windows itself."""

    def issue(
        self,
        *,
        action: str,
        action_level: int,
        confidence: float,
        evidence_summary: list[str],
        policy: str,
        target: str,
        initiator: str,
        finding_id: str | None = None,
        reversible: bool = True,
        rollback_plan: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> Decision | None:
        if action_level < LEVEL_RECOMMEND:
            return Decision(
                decision_id=str(uuid4()),
                finding_id=finding_id,
                action=action,
                action_level=action_level,
                confidence=confidence,
                evidence_summary=evidence_summary,
                policy=policy,
                target=target,
                reversible=reversible,
                rollback_plan=rollback_plan,
                initiator=initiator,
                details=details or {},
            )
        if confidence < 0.5 or not evidence_summary or not policy or not target:
            logger.warning(
                "Cortex refused decision (incomplete): action=%s conf=%s",
                action,
                confidence,
            )
            return None
        if action_level >= LEVEL_REVERSIBLE and reversible and not rollback_plan:
            logger.warning("Cortex refused Level≥3 without rollback_plan: %s", action)
            return None
        return Decision(
            decision_id=str(uuid4()),
            finding_id=finding_id,
            action=action,
            action_level=action_level,
            confidence=confidence,
            evidence_summary=list(evidence_summary),
            policy=policy,
            target=target,
            reversible=reversible,
            rollback_plan=rollback_plan,
            initiator=initiator,
            details=details or {},
        )


class ActionExecutor:
    """Fail-closed mutation gate. Rejects anything without a valid Decision."""

    def __init__(self, store: AgentStore) -> None:
        self.store = store
        self._seen: set[str] = set()

    def execute(
        self,
        decision: Decision | None,
        mutator: Callable[[], tuple[bool, str]],
        *,
        before_state: str | None = None,
    ) -> tuple[bool, str]:
        if decision is None:
            self._audit_reject(None, "missing_decision")
            return False, "REJECTED: missing Decision ID"
        if decision.action_level < LEVEL_RECOMMEND:
            return False, "REJECTED: Level <2 does not mutate"
        if not decision.decision_id:
            self._audit_reject(decision, "empty_decision_id")
            return False, "REJECTED: empty Decision ID"
        if decision.decision_id in self._seen:
            self._audit_reject(decision, "replay")
            return False, "REJECTED: Decision ID already used"
        if decision.confidence < 0.5 or not decision.evidence_summary or not decision.policy:
            self._audit_reject(decision, "incomplete_fields")
            return False, "REJECTED: incomplete Decision fields"
        if (
            decision.action_level >= LEVEL_REVERSIBLE
            and decision.reversible
            and not decision.rollback_plan
        ):
            self._audit_reject(decision, "missing_rollback")
            return False, "REJECTED: missing rollback_plan"

        ok, result = mutator()
        self._seen.add(decision.decision_id)
        self.store.log_action_audit(
            {
                "decision_id": decision.decision_id,
                "finding_id": decision.finding_id,
                "ts": _utc(),
                "initiator": decision.initiator,
                "action": decision.action,
                "action_level": decision.action_level,
                "target": decision.target,
                "before_state": before_state,
                "requested_state": decision.action,
                "actual_result": result,
                "ok": ok,
                "confidence": decision.confidence,
                "policy": decision.policy,
                "evidence": decision.evidence_summary,
                "rollback_token": decision.rollback_plan,
                "verification": "PENDING",
            }
        )
        return ok, result

    def _audit_reject(self, decision: Decision | None, reason: str) -> None:
        self.store.log_action_audit(
            {
                "decision_id": decision.decision_id if decision else None,
                "ts": _utc(),
                "ok": False,
                "actual_result": f"REJECTED:{reason}",
                "verification": "REJECTED",
            }
        )

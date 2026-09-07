"""Policy Cortex + Action Executor — mutation boundary (P0.0).

Hard invariants:
- Level 2 = recommend only — ActionExecutor never mutates for L2.
- Mutations require Level ≥ 3, typed ActionKind, registered handler, Authorization.
- No arbitrary mutator callbacks — Decision.action binds to ActionRegistry.
- Decision ID claimed atomically in SQLite (survives process restart).

NIST CSF 2.0 GV/PR.AA supports governance + authorization enforcement conceptually;
thresholds and action kinds are product architecture, not a NIST prescription.
"""

from __future__ import annotations

import logging
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from agent.policy.actions import (
    ActionKind,
    ActionRegistry,
    ActionRequest,
    MUTATING_MIN_LEVEL,
    NON_MUTATING_ACTIONS,
    USER_APPROVED_ONLY,
    parse_action_kind,
)
from agent.policy.authorization import (
    Authorization,
    authorization_allows,
    parse_authorization,
)
from agent.policy.levels import (
    CONFIDENCE_FLOOR,
    LEVEL_ADMIN,
    LEVEL_EMERGENCY,
    LEVEL_EXPLAIN,
    LEVEL_OBSERVE,
    LEVEL_RECOMMEND,
    LEVEL_REVERSIBLE,
)
from agent.store.db import AgentStore

logger = logging.getLogger("dvielle.policy")

# Re-export levels for existing imports
__all__ = [
    "LEVEL_OBSERVE",
    "LEVEL_EXPLAIN",
    "LEVEL_RECOMMEND",
    "LEVEL_REVERSIBLE",
    "LEVEL_ADMIN",
    "LEVEL_EMERGENCY",
    "Decision",
    "PolicyCortex",
    "ActionExecutor",
    "Authorization",
    "ActionKind",
]


def _utc() -> str:
    return datetime.now(timezone.utc).isoformat()


def confidence_floor(action_level: int) -> float:
    return CONFIDENCE_FLOOR.get(action_level, 1.0)


@dataclass
class Decision:
    decision_id: str
    finding_id: str | None
    action: str  # ActionKind value
    action_level: int
    confidence: float
    evidence_summary: list[str]
    authorization: str  # Authorization value
    policy_ref: str  # named policy document / rule id for audit (not the auth gate)
    target: str
    reversible: bool
    rollback_plan: str | None
    initiator: str
    ts: str = field(default_factory=_utc)
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @property
    def action_kind(self) -> ActionKind | None:
        return parse_action_kind(self.action)

    @property
    def authorization_kind(self) -> Authorization | None:
        return parse_authorization(self.authorization)


class PolicyCortex:
    """Issues Decision IDs. Does not mutate Windows itself."""

    def issue(
        self,
        *,
        action: str | ActionKind,
        action_level: int,
        confidence: float,
        evidence_summary: list[str],
        authorization: str | Authorization,
        target: str,
        initiator: str,
        finding_id: str | None = None,
        reversible: bool = True,
        rollback_plan: str | None = None,
        policy_ref: str = "",
        details: dict[str, Any] | None = None,
    ) -> Decision | None:
        kind = parse_action_kind(action)
        auth = parse_authorization(authorization)
        if kind is None:
            logger.warning("Cortex refused: unknown action %r", action)
            return None
        if auth is None:
            logger.warning("Cortex refused: unknown authorization %r", authorization)
            return None
        if action_level < LEVEL_OBSERVE or action_level > LEVEL_EMERGENCY:
            logger.warning("Cortex refused: invalid action_level %s", action_level)
            return None

        # L0–L1: always issuable (observe/explain); light fields OK.
        if action_level < LEVEL_RECOMMEND:
            return self._mk(
                kind=kind,
                action_level=action_level,
                confidence=confidence,
                evidence_summary=list(evidence_summary or []),
                auth=auth,
                policy_ref=policy_ref,
                target=target or "n/a",
                initiator=initiator,
                finding_id=finding_id,
                reversible=reversible,
                rollback_plan=rollback_plan,
                details=details,
            )

        floor = confidence_floor(action_level)
        if confidence < floor or not evidence_summary or not target:
            logger.warning(
                "Cortex refused incomplete L%s: action=%s conf=%s floor=%s",
                action_level,
                kind.value,
                confidence,
                floor,
            )
            return None
        if not authorization_allows(action_level, auth):
            logger.warning(
                "Cortex refused auth %s for level %s action=%s",
                auth.value,
                action_level,
                kind.value,
            )
            return None
        if kind in USER_APPROVED_ONLY and auth is not Authorization.USER_APPROVED:
            logger.warning(
                "Cortex refused: %s requires USER_APPROVED (got %s) — no autonomous path",
                kind.value,
                auth.value,
            )
            return None

        min_for_kind = MUTATING_MIN_LEVEL.get(kind)
        if kind in NON_MUTATING_ACTIONS:
            if action_level >= LEVEL_REVERSIBLE:
                logger.warning(
                    "Cortex refused: non-mutating %s cannot be issued at L%s",
                    kind.value,
                    action_level,
                )
                return None
        elif min_for_kind is not None:
            if action_level < min_for_kind:
                logger.warning(
                    "Cortex refused: %s requires level≥%s, got %s",
                    kind.value,
                    min_for_kind,
                    action_level,
                )
                return None
        else:
            logger.warning("Cortex refused: action %s not in closed set", kind.value)
            return None

        if action_level >= LEVEL_REVERSIBLE and reversible and not rollback_plan:
            logger.warning("Cortex refused Level≥3 without rollback_plan: %s", kind.value)
            return None

        return self._mk(
            kind=kind,
            action_level=action_level,
            confidence=confidence,
            evidence_summary=list(evidence_summary),
            auth=auth,
            policy_ref=policy_ref,
            target=target,
            initiator=initiator,
            finding_id=finding_id,
            reversible=reversible,
            rollback_plan=rollback_plan,
            details=details,
        )

    def _mk(
        self,
        *,
        kind: ActionKind,
        action_level: int,
        confidence: float,
        evidence_summary: list[str],
        auth: Authorization,
        policy_ref: str,
        target: str,
        initiator: str,
        finding_id: str | None,
        reversible: bool,
        rollback_plan: str | None,
        details: dict[str, Any] | None,
    ) -> Decision:
        return Decision(
            decision_id=str(uuid4()),
            finding_id=finding_id,
            action=kind.value,
            action_level=action_level,
            confidence=confidence,
            evidence_summary=evidence_summary,
            authorization=auth.value,
            policy_ref=policy_ref,
            target=target,
            reversible=reversible,
            rollback_plan=rollback_plan,
            initiator=initiator,
            details=details or {},
        )


class ActionExecutor:
    """Fail-closed mutation gate. Only registered handlers may mutate; L2 never mutates."""

    def __init__(
        self,
        store: AgentStore,
        registry: ActionRegistry | None = None,
    ) -> None:
        self.store = store
        self.registry = registry if registry is not None else ActionRegistry()

    def register(self, kind: ActionKind, handler: Any) -> None:
        self.registry.register(kind, handler)

    def execute(
        self,
        decision: Decision | None,
        *,
        before_state: str | None = None,
    ) -> tuple[bool, str]:
        if decision is None:
            self._audit_reject(None, "missing_decision")
            return False, "REJECTED: missing Decision ID"

        # P0.0: Level 2 is recommend-only. Mutations start at Level 3.
        if decision.action_level < LEVEL_REVERSIBLE:
            self._audit_reject(decision, "level_below_reversible")
            return False, "REJECTED: Level <3 does not mutate (L2=recommend only)"

        if not decision.decision_id:
            self._audit_reject(decision, "empty_decision_id")
            return False, "REJECTED: empty Decision ID"

        kind = decision.action_kind
        if kind is None or kind in NON_MUTATING_ACTIONS:
            self._audit_reject(decision, "non_mutating_or_unknown_action")
            return False, "REJECTED: action is not a registered mutating kind"

        min_level = MUTATING_MIN_LEVEL.get(kind)
        if min_level is None or decision.action_level < min_level:
            self._audit_reject(decision, "action_level_too_low_for_kind")
            return False, f"REJECTED: {kind.value} requires level≥{min_level}"

        auth = decision.authorization_kind
        if auth is None or not authorization_allows(decision.action_level, auth):
            self._audit_reject(decision, "authorization_denied")
            return False, "REJECTED: authorization does not permit this level"

        if kind in USER_APPROVED_ONLY and auth is not Authorization.USER_APPROVED:
            self._audit_reject(decision, "requires_user_approved")
            return False, "REJECTED: action requires USER_APPROVED authorization"

        floor = confidence_floor(decision.action_level)
        if (
            decision.confidence < floor
            or not decision.evidence_summary
            or not decision.target
        ):
            self._audit_reject(decision, "incomplete_fields")
            return False, "REJECTED: incomplete Decision fields"

        if decision.reversible and not decision.rollback_plan:
            self._audit_reject(decision, "missing_rollback")
            return False, "REJECTED: missing rollback_plan"

        handler = self.registry.get(kind)
        if handler is None:
            self._audit_reject(decision, "no_registered_handler")
            return False, f"REJECTED: no registered handler for {kind.value}"

        claimed = self.store.claim_decision_id(
            decision.decision_id,
            {
                "action": decision.action,
                "action_level": decision.action_level,
                "authorization": decision.authorization,
                "target": decision.target,
                "initiator": decision.initiator,
            },
        )
        if not claimed:
            self._audit_reject(decision, "replay")
            return False, "REJECTED: Decision ID already used"

        request = ActionRequest(
            decision_id=decision.decision_id,
            action=kind,
            target=decision.target,
            action_level=decision.action_level,
            authorization=decision.authorization,
            rollback_plan=decision.rollback_plan,
            details=dict(decision.details),
            finding_id=decision.finding_id,
            before_state=before_state,
        )

        try:
            ok, result = handler(request)
        except Exception as exc:  # noqa: BLE001 — fail closed; never leak half-mutation silently
            logger.exception("Handler failed for %s", kind.value)
            ok, result = False, f"HANDLER_ERROR:{type(exc).__name__}"

        self.store.finalize_decision(
            decision.decision_id,
            status="EXECUTED" if ok else "FAILED",
            result=result,
        )
        self.store.log_action_audit(
            {
                "decision_id": decision.decision_id,
                "finding_id": decision.finding_id,
                "ts": _utc(),
                "initiator": decision.initiator,
                "action": decision.action,
                "action_level": decision.action_level,
                "authorization": decision.authorization,
                "policy_ref": decision.policy_ref,
                "target": decision.target,
                "before_state": before_state,
                "requested_state": kind.value,
                "actual_result": result,
                "ok": ok,
                "confidence": decision.confidence,
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
                "authorization": decision.authorization if decision else None,
                "action": decision.action if decision else None,
                "action_level": decision.action_level if decision else None,
            }
        )

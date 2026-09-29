"""One mutate gate for keep-on and Cortex.

A firewall change, temp delete, startup disable, smart close, or IP block
runs only when both are true:

1. Keep-on issued a one-time token for this finding, handler, and subject
   (options-card selection, or published auto-protect for that exact subject).
2. Cortex issued a typed ActionKind decision and ActionExecutor ran a
   registered handler. CLOSE_PROCESS stays USER_APPROVED_ONLY.

Either refusal fails closed. Engine handlers that touch the OS call
``require_cortex_mutate`` and do nothing unless this gate set that context.
"""

from __future__ import annotations

import contextvars
import uuid
from collections.abc import Callable
from typing import Any

from agent.engine.models import AuthToken, PolicyDenied
from agent.policy.actions import (
    ActionKind,
    ActionRegistry,
    MUTATING_MIN_LEVEL,
    USER_APPROVED_ONLY,
)
from agent.policy.authorization import Authorization
from agent.policy.cortex import ActionExecutor, PolicyCortex
from agent.policy.levels import LEVEL_ADMIN, LEVEL_REVERSIBLE
from agent.store.db import AgentStore

_mutate_depth: contextvars.ContextVar[int] = contextvars.ContextVar(
    "dvielle_dual_mutate", default=0
)

# Keep-on handler name → typed Cortex kind. Unlisted handlers do not mutate.
HANDLER_KIND: dict[str, ActionKind] = {
    "safety.smart_close": ActionKind.CLOSE_PROCESS,
    "speed.pause_process": ActionKind.CLOSE_PROCESS,
    "camera.stop_use": ActionKind.CLOSE_PROCESS,
    "safety.disable_startup": ActionKind.DISABLE_STARTUP,
    "speed.disable_startup": ActionKind.DISABLE_STARTUP,
    "storage.free_safe_temp": ActionKind.DELETE_TEMP,
    "storage.empty_recycle": ActionKind.DELETE_TEMP,
    "privacy.block_network": ActionKind.RESTRICT_NETWORK,
    "ai.block_network": ActionKind.RESTRICT_NETWORK,
    "safety.restrict_network": ActionKind.RESTRICT_NETWORK,
    "safety.set_asr_rule": ActionKind.SET_ASR_RULE,
    "safety.set_cfa_mode": ActionKind.SET_CFA_MODE,
    "safety.open_unfamiliar": ActionKind.OPEN_SANDBOX,
    "privacy.set_choice": ActionKind.SET_PRIVACY_CHOICE,
}

_UNDO: dict[ActionKind, str] = {
    ActionKind.RESTRICT_NETWORK: "Remove the DVielle outbound firewall rule for this program.",
    ActionKind.DISABLE_STARTUP: "Rename the .dvielle-disabled startup file back to its original name.",
    ActionKind.SET_ASR_RULE: "Set the same ASR rule back to the mode recorded before this change.",
    ActionKind.SET_CFA_MODE: "Set controlled folder access back to the mode recorded before this change.",
    ActionKind.OPEN_SANDBOX: "Close Windows Sandbox. The disposable sandbox discards its changes when it closes. The host folder was mapped read-only.",
    ActionKind.SET_PRIVACY_CHOICE: "Set the same privacy policy back to the value recorded before this change.",
}
_IRREVERSIBLE = frozenset(
    {ActionKind.CLOSE_PROCESS, ActionKind.DELETE_TEMP, ActionKind.BLOCK_IP}
)


def cortex_mutate_active() -> bool:
    return _mutate_depth.get() > 0


def require_cortex_mutate() -> None:
    """Engine OS helpers call this. Direct calls fail closed."""
    if not cortex_mutate_active():
        raise PolicyDenied("refusing OS change without Cortex authorization")


# Nonces issued only by DualGate.perform. A caller cannot stamp these into a Decision.
_grants: set[str] = set()


def _grant_key(nonce: str, subject: str) -> str:
    return f"{nonce}|{subject}"


def issue_keep_on_grant(subject: str) -> str:
    nonce = uuid.uuid4().hex
    _grants.add(_grant_key(nonce, subject))
    return nonce


def take_keep_on_grant(details: dict[str, Any] | None) -> bool:
    """Consume a dual-gate stamp. Forged details are not in the set."""
    body = details or {}
    nonce = str(body.get("keep_on_grant") or "")
    subject = str(body.get("keep_on_subject") or "")
    if not nonce or not subject:
        return False
    key = _grant_key(nonce, subject)
    if key not in _grants:
        return False
    _grants.discard(key)
    return True


class DualGate:
    """Keep-on PolicyGate plus a private Cortex executor.

    Handlers are registered only for the duration of ``perform`` and only
    after the keep-on token matches. BLOCK_IP has no product writer here.
    """

    def __init__(self, store: AgentStore, keep_on) -> None:
        self.store = store
        self.keep_on = keep_on
        self.cortex = PolicyCortex(store=store)
        self.registry = ActionRegistry()
        self.executor = ActionExecutor(store, self.registry)

    def perform(
        self,
        *,
        handler_name: str,
        finding: dict[str, Any],
        token: AuthToken | None,
        mutator: Callable[[], dict],
    ) -> dict:
        kind = HANDLER_KIND.get(handler_name)
        if kind is None or kind not in MUTATING_MIN_LEVEL:
            raise PolicyDenied(f"no typed action for {handler_name}")
        self.keep_on.require(token, finding["id"], handler_name)
        if token is None:
            raise PolicyDenied("options required before mutate")
        subject = str(finding.get("subject_identity") or "")
        if token.subject != subject or not subject:
            raise PolicyDenied("options required before mutate")
        auto = bool(token.auto)
        if auto:
            if kind in USER_APPROVED_ONLY or kind is ActionKind.BLOCK_IP:
                raise PolicyDenied("auto-protect cannot authorize this action")
            authorization = Authorization.AUTOMATIC_POLICY
            confidence = 0.90
            initiator = "auto_protect"
        else:
            authorization = Authorization.USER_APPROVED
            confidence = 0.95
            initiator = "keep_on_option"
        if kind in _IRREVERSIBLE:
            reversible = False
            rollback = None
        else:
            reversible = True
            rollback = _UNDO.get(kind, "Reverse the recorded change.")
        level = LEVEL_ADMIN if kind is ActionKind.BLOCK_IP else LEVEL_REVERSIBLE
        evidence = [str(item) for item in (finding.get("evidence_refs") or []) if str(item).strip()]
        if not evidence:
            title = str(finding.get("title_simple") or "").strip()
            evidence = [title] if title else []
        if not evidence:
            raise PolicyDenied("cortex refused the action")
        grant = issue_keep_on_grant(subject)
        decision = self.cortex.issue(
            action=kind,
            action_level=level,
            confidence=confidence,
            evidence_summary=evidence,
            authorization=authorization,
            target=subject,
            initiator=initiator,
            finding_id=finding["id"],
            reversible=reversible,
            rollback_plan=rollback,
            policy_ref="dual_gate",
            details={
                "keep_on_handler": handler_name,
                "keep_on_subject": subject,
                "keep_on_grant": grant,
                "auto": auto,
            },
        )
        if decision is None:
            raise PolicyDenied("cortex refused the action")

        box: dict[str, dict] = {}

        def bound(request) -> tuple[bool, str]:
            if request.finding_id != finding["id"]:
                return False, "REJECTED: finding mismatch"
            if request.details.get("keep_on_handler") != handler_name:
                return False, "REJECTED: handler mismatch"
            if request.details.get("keep_on_subject") != subject or not take_keep_on_grant(request.details):
                return False, "REJECTED: options required before mutate"
            if kind in USER_APPROVED_ONLY and request.authorization != Authorization.USER_APPROVED.value:
                return False, "REJECTED: action requires USER_APPROVED authorization"
            body = mutator()
            box["body"] = body
            return bool(body.get("performed")), str(body.get("message") or "")

        self.registry.register(kind, bound)
        depth = _mutate_depth.set(_mutate_depth.get() + 1)
        try:
            _ok, message = self.executor.execute(decision)
        finally:
            _mutate_depth.reset(depth)
        body = box.get("body")
        if body is None:
            raise PolicyDenied(message or "cortex refused the action")
        return body

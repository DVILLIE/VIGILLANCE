"""Typed action kinds + registry — ActionExecutor binds Decision.action to a handler.

No free-form mutator callbacks. Each mutation kind has an explicit schema and
a registered handler that receives a validated ActionRequest.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Mapping

from agent.policy.levels import (
    LEVEL_ADMIN,
    LEVEL_OBSERVE,
    LEVEL_RECOMMEND,
    LEVEL_REVERSIBLE,
)


class ActionKind(str, Enum):
    """Closed set of Cortex actions. Mutating kinds are executed only via registry."""

    AUDIT = "AUDIT"
    RECOMMEND = "RECOMMEND"
    ALLOW = "ALLOW"
    RESTRICT_NETWORK = "RESTRICT_NETWORK"
    BLOCK_IP = "BLOCK_IP"
    SET_ECOQOS = "SET_ECOQOS"
    SET_PRIORITY = "SET_PRIORITY"
    SUSPEND_PROCESS = "SUSPEND_PROCESS"
    RESTORE_POLICY = "RESTORE_POLICY"
    CLOSE_PROCESS = "CLOSE_PROCESS"
    DISABLE_STARTUP = "DISABLE_STARTUP"
    DELETE_TEMP = "DELETE_TEMP"


# Non-mutating: may be decided/logged; ActionExecutor must never invoke handlers for these.
NON_MUTATING_ACTIONS: frozenset[ActionKind] = frozenset(
    {
        ActionKind.AUDIT,
        ActionKind.RECOMMEND,
        ActionKind.ALLOW,
    }
)

# Minimum Decision.action_level required to execute this mutation.
MUTATING_MIN_LEVEL: Mapping[ActionKind, int] = {
    ActionKind.RESTRICT_NETWORK: LEVEL_REVERSIBLE,
    ActionKind.SET_ECOQOS: LEVEL_REVERSIBLE,
    ActionKind.SET_PRIORITY: LEVEL_REVERSIBLE,
    ActionKind.SUSPEND_PROCESS: LEVEL_REVERSIBLE,
    ActionKind.RESTORE_POLICY: LEVEL_REVERSIBLE,
    ActionKind.CLOSE_PROCESS: LEVEL_REVERSIBLE,
    ActionKind.BLOCK_IP: LEVEL_ADMIN,
    ActionKind.DISABLE_STARTUP: LEVEL_REVERSIBLE,
    ActionKind.DELETE_TEMP: LEVEL_REVERSIBLE,
}

# Kinds that require an explicit human authorization regardless of level.
# CLOSE_PROCESS ends a user's app (data loss possible, no rollback), so it may
# only be issued/executed under Authorization.USER_APPROVED — never
# AUTOMATIC_POLICY. This keeps the autonomous agent unable to close apps on its
# own even if a handler is registered for a user-initiated surface (the GUI).
USER_APPROVED_ONLY: frozenset[ActionKind] = frozenset({ActionKind.CLOSE_PROCESS})


def parse_action_kind(value: str | ActionKind) -> ActionKind | None:
    if isinstance(value, ActionKind):
        return value
    try:
        return ActionKind(str(value).strip().upper())
    except ValueError:
        return None


@dataclass(frozen=True)
class ActionRequest:
    """Validated mutation request derived from a Decision — what the handler may touch."""

    decision_id: str
    action: ActionKind
    target: str
    action_level: int
    authorization: str
    rollback_plan: str | None
    details: dict[str, Any] = field(default_factory=dict)
    finding_id: str | None = None
    before_state: str | None = None


ActionHandler = Callable[[ActionRequest], tuple[bool, str]]


class ActionRegistry:
    """Maps ActionKind → handler. Mutating kinds only; unknown kind = no handler."""

    def __init__(self) -> None:
        self._handlers: dict[ActionKind, ActionHandler] = {}

    def register(self, kind: ActionKind, handler: ActionHandler) -> None:
        if kind in NON_MUTATING_ACTIONS:
            raise ValueError(f"Cannot register mutator for non-mutating action {kind.value}")
        if kind not in MUTATING_MIN_LEVEL:
            raise ValueError(f"Unknown mutating action {kind}")
        self._handlers[kind] = handler

    def get(self, kind: ActionKind) -> ActionHandler | None:
        return self._handlers.get(kind)

    def registered(self) -> frozenset[ActionKind]:
        return frozenset(self._handlers)


def action_min_level(kind: ActionKind) -> int | None:
    """Return min level for mutation, 0 for non-mutating observe/recommend kinds, else None."""
    if kind in NON_MUTATING_ACTIONS:
        if kind == ActionKind.AUDIT:
            return LEVEL_OBSERVE
        return LEVEL_RECOMMEND
    return MUTATING_MIN_LEVEL.get(kind)


def level_name(level: int) -> str:
    names = {
        0: "OBSERVE",
        1: "EXPLAIN",
        2: "RECOMMEND",
        3: "REVERSIBLE",
        4: "ADMIN",
        5: "EMERGENCY",
    }
    return names.get(level, f"L{level}")


__all__ = [
    "ActionKind",
    "ActionRequest",
    "ActionHandler",
    "ActionRegistry",
    "NON_MUTATING_ACTIONS",
    "MUTATING_MIN_LEVEL",
    "USER_APPROVED_ONLY",
    "parse_action_kind",
    "action_min_level",
    "level_name",
]

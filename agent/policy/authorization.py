"""Authorization states for Cortex decisions.

NIST CSF 2.0 PR.AA-05: authorizations are defined in policy, managed, enforced,
and reviewed (least privilege). This enum is our product gate — not a NIST schema.
"""

from __future__ import annotations

from enum import Enum

from agent.policy.levels import (
    LEVEL_ADMIN,
    LEVEL_EMERGENCY,
    LEVEL_RECOMMEND,
    LEVEL_REVERSIBLE,
)


class Authorization(str, Enum):
    """Who/what authorized this Decision. A free-form policy string is not enough."""

    AUTOMATIC_POLICY = "AUTOMATIC_POLICY"
    USER_APPROVED = "USER_APPROVED"
    EMERGENCY_POLICY = "EMERGENCY_POLICY"


def parse_authorization(value: str | Authorization) -> Authorization | None:
    if isinstance(value, Authorization):
        return value
    try:
        return Authorization(str(value).strip().upper())
    except ValueError:
        return None


def authorization_allows(action_level: int, authorization: Authorization) -> bool:
    """Gate mutation levels by authorization strength.

    L0–L2 (observe/explain/recommend): any recognized Authorization may issue.
    L3 reversible: automatic policy, user approval, or emergency.
    L4 admin: explicit user approval or emergency — never automatic alone.
    L5 emergency: dedicated emergency policy only.
    """
    if action_level <= LEVEL_RECOMMEND:
        return True
    if action_level == LEVEL_REVERSIBLE:
        return authorization in (
            Authorization.AUTOMATIC_POLICY,
            Authorization.USER_APPROVED,
            Authorization.EMERGENCY_POLICY,
        )
    if action_level == LEVEL_ADMIN:
        return authorization in (
            Authorization.USER_APPROVED,
            Authorization.EMERGENCY_POLICY,
        )
    if action_level == LEVEL_EMERGENCY:
        return authorization is Authorization.EMERGENCY_POLICY
    return False

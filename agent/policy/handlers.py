"""User-initiated action handlers (registered only on human-driven gates).

These run ONLY when the ActionExecutor is given a non-empty registry via
``PolicyGate.create(store, user_actions=True)`` — today that is the Mission
Console. Every kind here is in ``USER_APPROVED_ONLY``, so the Cortex refuses to
issue or execute it under anything but Authorization.USER_APPROVED: there is no
autonomous path to a mutation. The autonomous nerve loop keeps an empty registry
and remains fail-closed.
"""

from __future__ import annotations

import logging

from agent.policy.actions import ActionRequest

logger = logging.getLogger("dvielle.policy.handlers")


def close_process_handler(request: ActionRequest) -> tuple[bool, str]:
    """Close the exact process family carried by a USER_APPROVED CLOSE_PROCESS Decision.

    The Decision.details must carry the PID set recorded at advice time
    (``pids``), optionally the observed ``names`` (for logging), and ``force``
    (True only after an explicit second confirm). Targeting an explicit PID list
    — not a machine-wide exe-name glob — is what keeps this from taking down
    unrelated same-named processes.
    """
    from agent.policy.dual import take_keep_on_grant

    # Registered for the human gate, but a Decision alone is not enough.
    # The stamp is issued only after an options-card or auto-protect token.
    if not take_keep_on_grant(request.details):
        return False, "REJECTED: options required before mutate"

    # Imported lazily so agent.policy has no import-time dependency on modules.
    from agent.modules.resource_advisor import close_pids

    details = request.details or {}
    pids = details.get("pids") or []
    names = details.get("names") or []
    force = details.get("force", False)
    if not isinstance(force, bool):
        return False, "REJECTED: force must be an explicit boolean"

    if not pids:
        return False, "REJECTED: no target PIDs in Decision.details"

    try:
        pid_list = [int(p) for p in pids]
    except (TypeError, ValueError):
        return False, "REJECTED: malformed PID list in Decision.details"

    logger.info(
        "CLOSE_PROCESS handler: decision=%s force=%s pids=%s names=%s",
        request.decision_id,
        force,
        pid_list,
        names,
    )
    return close_pids(
        pid_list, names, force=force,
        identities=details.get("identities"),
        observed_at=details.get("observed_at"),
        never_close=frozenset(str(n).casefold() for n in details.get("never_close", [])),
    )

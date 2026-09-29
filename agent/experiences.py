"""Activity experiences: technical contracts, not display labels.

Everyday observes ASR, CFA, and the firewall and uses a quiet alert floor.
It cannot enable a denylist action or automatic CLOSE_PROCESS.

Sensitive surfaces lower-severity alerts and keeps auto-protect eligibility
tighter (critical only). CLOSE_PROCESS and Open unfamiliar stay user-approved.
CFA Audit and firewall restrict are proposed sooner. Nothing is applied here.

Open unfamiliar names the existing Pro+ Windows Sandbox path. Home returns
that path's checklist and does not start a process.

The dual mutate gate is not replaced. This module does not change Defender
preferences, does not create a firewall rule, and does not start a sandbox.
"""

from __future__ import annotations

from typing import Any

from agent.modules.sandbox import observe_sandbox
from agent.policy.actions import ActionKind
from agent.policy.dual import HANDLER_KIND

EVERYDAY = "everyday"
SENSITIVE = "sensitive"
OPEN_UNFAMILIAR = "open_unfamiliar"
NAMES = frozenset({EVERYDAY, SENSITIVE, OPEN_UNFAMILIAR})

# Same published set as the keep-on PolicyGate. Experiences cannot add to it.
PUBLISHED_AUTO = ("safety.turn_protection_on", "storage.free_safe_temp")

_SEVERITY = {"low": 1, "medium": 2, "high": 3, "critical": 4}
_BOOL_KEYS = {
    EVERYDAY: ("denylist_actions", "close_process_auto"),
    SENSITIVE: ("close_process_auto", "open_unfamiliar_auto"),
    OPEN_UNFAMILIAR: ("launch",),
}


def validate_experience_config(config: dict | None) -> None:
    """Reject a malformed experiences section. True/false locks are enforced later."""
    if not isinstance(config, dict) or "experiences" not in config:
        return
    body = config.get("experiences")
    if not isinstance(body, dict):
        raise ValueError("experiences must be a mapping")
    active = body.get("active", EVERYDAY)
    if not isinstance(active, str):
        raise ValueError("experiences.active must be a string")
    for name, keys in _BOOL_KEYS.items():
        section = body.get(name, {})
        if section is None:
            continue
        if not isinstance(section, dict):
            raise ValueError(f"experiences.{name} must be a mapping")
        for key in keys:
            if key in section and not isinstance(section[key], bool):
                raise ValueError(f"experiences.{name}.{key} must be a YAML true/false boolean")
        handlers = section.get("handlers", section.get("auto_handlers", []))
        if handlers is None:
            continue
        if not isinstance(handlers, list) or any(not isinstance(item, str) for item in handlers):
            raise ValueError(f"experiences.{name} handlers must be a list of strings")


def experience_allows_auto(contract: dict[str, Any], handler: str, *, severity: str | None = None) -> tuple[bool, str]:
    """Whether this experience may auto-protect that handler. Default is no."""
    from agent.engine.policy import handler_is_denied

    if contract.get("denylist_actions") is not False or handler_is_denied(handler):
        return False, "that action is on the denylist"
    kind = HANDLER_KIND.get(handler)
    if kind is ActionKind.CLOSE_PROCESS:
        return False, "CLOSE_PROCESS stays user-approved"
    if handler == "safety.open_unfamiliar" or kind is ActionKind.OPEN_SANDBOX:
        return False, "open unfamiliar stays user-approved"
    allowed = set(contract.get("auto_handlers") or ())
    if handler not in allowed or handler not in PUBLISHED_AUTO:
        return False, "that action is not in the published auto-protect set"
    if severity is not None:
        floor = str(contract.get("auto_protect_min_severity") or "high")
        if _SEVERITY.get(str(severity), 0) < _SEVERITY.get(floor, 3):
            return False, "auto-protect eligibility is tighter in this experience"
    return True, ""


def experience_surfaces(contract: dict[str, Any], severity: str, confidence: str) -> bool:
    """Alert floor for this experience. Low confidence stays held in every experience."""
    if confidence not in ("medium", "high"):
        return False
    floor = str(contract.get("alert_min_severity") or "medium")
    return _SEVERITY.get(str(severity), 0) >= _SEVERITY.get(floor, 2)


def resolve_experience(
    config: dict | None,
    *,
    sku: str | None = None,
    feature_installed: bool | None = None,
    sandbox: dict[str, Any] | None = None,
    promotion: dict[str, Any] | None = None,
    firewall: Any = None,
) -> dict[str, Any]:
    """Apply config locks and return the active contract. Locked trues are refused."""
    body = config.get("experiences") if isinstance(config, dict) else None
    if not isinstance(body, dict):
        body = {}
    requested_raw = body.get("active", EVERYDAY)
    requested = requested_raw.strip().lower() if isinstance(requested_raw, str) else ""
    refused: list[dict[str, Any]] = []
    if requested not in NAMES:
        refused.append(
            {
                "key": "experiences.active",
                "requested": requested_raw,
                "applied": EVERYDAY,
                "reason": "Unknown experience. Everyday locks apply. Nothing extra was enabled.",
            }
        )
        name = EVERYDAY
    else:
        name = requested
    section = body.get(name)
    if not isinstance(section, dict):
        section = {}
    _refuse_locked_trues(name, section, refused)
    _refuse_handler_overrides(name, section, refused)

    if name == SENSITIVE:
        alert_floor = "low"
        auto_floor = "critical"
    elif name == EVERYDAY:
        alert_floor = "high"
        auto_floor = "high"
    else:
        alert_floor = "medium"
        auto_floor = "high"

    contract: dict[str, Any] = {
        "name": name,
        "requested": requested or None,
        "dual_gate": "unchanged",
        "denylist_actions": False,
        "close_process_auto": False,
        "close_process": "user_approved",
        "open_unfamiliar_auto": False,
        "open_unfamiliar": "user_approved",
        "alert_min_severity": alert_floor,
        "auto_protect_min_severity": auto_floor,
        "auto_handlers": list(PUBLISHED_AUTO),
        "observation": {
            "asr": "observe",
            "cfa": "observe",
            "firewall": "observe",
            "mutate": False,
        },
        "proposals": _proposals(name, promotion, firewall),
        "sandbox": _sandbox_view(name, sku, feature_installed, sandbox),
        "refused": refused,
        "mutates": False,
        "assumptions": _assumptions(name),
    }
    return contract


def _refuse_locked_trues(name: str, section: dict, refused: list[dict[str, Any]]) -> None:
    for key in _BOOL_KEYS.get(name, ()):
        if section.get(key) is True:
            refused.append(
                {
                    "key": f"experiences.{name}.{key}",
                    "requested": True,
                    "applied": False,
                    "reason": _lock_reason(name, key),
                }
            )


def _lock_reason(name: str, key: str) -> str:
    if key == "denylist_actions":
        return "Everyday cannot enable denylist actions."
    if key == "close_process_auto":
        return "CLOSE_PROCESS stays user-approved. This experience cannot auto-close a process."
    if key == "open_unfamiliar_auto":
        return "Open unfamiliar stays user-approved."
    if key == "launch":
        return "Resolving Open unfamiliar does not start Windows Sandbox."
    return f"{name} does not enable {key}."


def _refuse_handler_overrides(name: str, section: dict, refused: list[dict[str, Any]]) -> None:
    from agent.engine.policy import handler_is_denied

    raw = section.get("handlers", section.get("auto_handlers", []))
    if not isinstance(raw, list):
        return
    for item in raw:
        handler = str(item)
        kind = HANDLER_KIND.get(handler)
        if handler_is_denied(handler) or kind is ActionKind.CLOSE_PROCESS or handler == "safety.open_unfamiliar":
            refused.append(
                {
                    "key": f"experiences.{name}.handlers",
                    "requested": handler,
                    "applied": False,
                    "reason": "That handler is not added to auto-protect.",
                }
            )


def _proposals(name: str, promotion: dict[str, Any] | None, firewall: Any) -> list[dict[str, Any]]:
    if name != SENSITIVE:
        return []
    proposals: list[dict[str, Any]] = []
    cfa = promotion.get("cfa") if isinstance(promotion, dict) else None
    audit_ready = (
        isinstance(cfa, dict)
        and cfa.get("audit_allowed") is True
        and list(cfa.get("allowed_modes") or []) == [2]
    )
    proposals.append(
        {
            "id": "cfa_audit",
            "handler": "safety.set_cfa_mode",
            "preference": "sooner",
            "applied": False,
            "available": audit_ready,
            "requires_dual_gate": True,
            "authorization": "user_approved",
            "what": (
                "Propose Controlled Folder Access Audit, then wait for approval. "
                "CFA is a modification shield. Nothing was changed."
                if audit_ready
                else "CFA Audit is not the next step from the live mode. Nothing was changed."
            ),
        }
    )
    rows = _firewall_rows(firewall)
    if not rows:
        proposals.append(
            {
                "id": "firewall_restrict",
                "handler": "safety.restrict_network",
                "preference": "sooner",
                "applied": False,
                "available": False,
                "requires_dual_gate": True,
                "authorization": "user_approved",
                "what": "No firewall restrict proposal was observed. No rule was created.",
            }
        )
        return proposals
    for index, row in enumerate(rows):
        proposals.append(
            {
                "id": "firewall_restrict" if index == 0 else f"firewall_restrict_{index}",
                "handler": "safety.restrict_network",
                "preference": "sooner",
                "applied": False,
                "available": True,
                "requires_dual_gate": True,
                "authorization": "user_approved",
                "title": row.get("title_simple"),
                "what": (
                    "Propose this Windows Firewall restrict option. "
                    "No rule is created until you approve it through the dual gate."
                ),
            }
        )
    return proposals


def _firewall_rows(firewall: Any) -> list[dict[str, Any]]:
    if isinstance(firewall, dict):
        rows = firewall.get("proposals") or []
    else:
        rows = getattr(firewall, "proposals", None) or []
    return [
        row
        for row in rows
        if isinstance(row, dict) and row.get("handler") == "safety.restrict_network"
    ]


def _sandbox_view(
    name: str,
    sku: str | None,
    feature_installed: bool | None,
    sandbox: dict[str, Any] | None,
) -> dict[str, Any] | None:
    if name != OPEN_UNFAMILIAR:
        return None
    if sku == "Home":
        observed = observe_sandbox("Home", feature_installed=None)
    elif isinstance(sandbox, dict) and sandbox.get("offer"):
        observed = sandbox
    else:
        observed = observe_sandbox(sku or "Unknown", feature_installed=feature_installed)
    offer = str(observed.get("offer") or "UNKNOWN")
    checklist = [str(item) for item in (observed.get("checklist") or [])]
    ready = offer == "READY"
    return {
        "offer": offer,
        "checklist": checklist,
        "checklist_only": not ready,
        "home_checklist_only": offer == "UNAVAILABLE" and (sku == "Home" or "Windows Home" in str(observed.get("message") or "")),
        "launched": False,
        "performed": False,
        "handler": "safety.open_unfamiliar" if ready else None,
        "authorization": "user_approved" if ready else None,
        "message": observed.get("message"),
    }


def _assumptions(name: str) -> list[str]:
    common = [
        "The dual mutate gate still wraps every OS change.",
        "CLOSE_PROCESS and Open unfamiliar stay user-approved in every experience.",
        "Denylist actions stay off. Config cannot turn them on.",
        "Low confidence stays held. This experience does not guess.",
    ]
    if name == EVERYDAY:
        return common + [
            "Everyday observes ASR, CFA, and Firewall. It does not propose those mutations.",
            "Everyday alerts start at high severity. Medium findings stay quiet.",
        ]
    if name == SENSITIVE:
        return common + [
            "Sensitive alerts start at low severity when confidence is medium or high.",
            "Sensitive auto-protect runs only for the published set, and only at critical severity.",
            "CFA Audit and firewall restrict are proposals. Applied stays false until the dual gate.",
            "CFA copy stays a modification shield.",
        ]
    return common + [
        "Open unfamiliar uses the existing Windows Sandbox path.",
        "Home shows the checklist only. A normal desktop window is not Windows Sandbox.",
        "Resolving this experience does not start the sandbox process.",
    ]

"""Fail-closed gate. A mutation needs a one-time token from a selected option."""

from __future__ import annotations

import uuid

from agent.engine.models import AuthToken, PolicyDenied

USER_HANDLERS = frozenset(
    {
        "safety.turn_protection_on",
        "safety.disable_startup",
        "safety.smart_close",
        "safety.open_settings",
        "speed.pause_process",
        "speed.disable_startup",
        "storage.free_safe_temp",
        "storage.preview",
        "storage.empty_recycle",
        "privacy.block_network",
        "privacy.open_settings",
        "ai.block_network",
        "ai.open_settings",
        "camera.stop_use",
        "camera.open_app_settings",
        "camera.open_system_settings",
        "camera.cover_reminder",
        "footprint.lockdown",
        "footprint.breach_check",
        "footprint.diy_opt_out",
        "footprint.open_partner",
        "footprint.mark_resolved",
        "footprint.still_monitoring",
        "safety.set_asr_rule",
        "safety.set_cfa_mode",
        "safety.restrict_network",
        "safety.open_unfamiliar",
        "privacy.set_choice",
    }
)
AUTO_HANDLERS = frozenset({"safety.turn_protection_on", "storage.free_safe_temp"})
DENY_MARKERS = ("delete_documents", "mass_kill", "offensive", "exploit", "payload", "force_delete")


def handler_is_denied(name: str) -> bool:
    lowered = (name or "").lower()
    return any(marker in lowered for marker in DENY_MARKERS)


class PolicyGate:
    def __init__(self, *, auto_enabled: bool, experience: dict | None = None) -> None:
        self.auto_enabled = auto_enabled
        self.experience = experience
        self._issued: set[tuple[str, str, str]] = set()

    def issue(self, finding_id: str, handler: str, *, auto: bool, subject: str = "") -> AuthToken:
        if handler_is_denied(handler):
            raise PolicyDenied("that action is on the denylist")
        if auto and self.experience is not None:
            from agent.experiences import experience_allows_auto

            allowed, reason = experience_allows_auto(self.experience, handler)
            if not allowed:
                raise PolicyDenied(reason)
        subject = str(subject or "")
        if auto:
            if not self.auto_enabled:
                raise PolicyDenied("auto-protect is off")
            if handler not in AUTO_HANDLERS:
                raise PolicyDenied("that action is not in the published auto-protect set")
            if not subject.strip():
                raise PolicyDenied("auto-protect requires an exact subject")
        elif handler not in USER_HANDLERS:
            raise PolicyDenied("that action is not an approved handler")
        token = AuthToken(finding_id, handler, uuid.uuid4().hex, auto=auto, subject=subject)
        self._issued.add((token.finding_id, token.handler, token.nonce))
        return token

    def require(self, token: AuthToken | None, finding_id: str, handler: str) -> None:
        if token is None:
            raise PolicyDenied("options required before mutate")
        key = (token.finding_id, token.handler, token.nonce)
        if key not in self._issued or token.finding_id != finding_id or token.handler != handler:
            raise PolicyDenied("options required before mutate")
        self._issued.remove(key)

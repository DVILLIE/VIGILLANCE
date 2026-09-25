"""Per-pillar option lists from Function Spec §5.1."""

from __future__ import annotations

from agent.engine.models import FailClosed, Option


def _learn(option_id: str, label: str, what: str, decision: str, status: str) -> Option:
    return Option(option_id, label, what, "learn", decision=decision, resulting_status=status)


def _mutate(option_id: str, label: str, what: str, handler: str) -> Option:
    return Option(option_id, label, what, "mutate", handler=handler)


def _guide(option_id: str, label: str, what: str, handler: str) -> Option:
    return Option(option_id, label, what, "guidance", handler=handler)


def _not_now() -> Option:
    return Option(
        "not_now",
        "Not now",
        "Snooze this card. Nothing on the computer is changed.",
        "snooze",
        resulting_status="monitoring",
    )


def _never(label: str, what: str) -> Option:
    return _learn("never_warn", label, what, "never_warn", "dismissed")


def _why() -> Option:
    return Option("show_why", "Show me why", "Show the plain-English evidence. Nothing is changed.", "show_why")


def safety_protection_options() -> list[Option]:
    return [
        _learn(
            "keep_as_is",
            "Keep protection as-is",
            "Remember this choice. If protection is off, DVielle will not turn it on "
            "and will stay quiet while this same protection stays off.",
            "allow",
            "monitoring",
        ),
        _mutate(
            "turn_on",
            "Turn protection back on",
            "Ask this computer to turn that protection back on. If DVielle cannot, it will say so.",
            "safety.turn_protection_on",
        ),
        _guide(
            "open_settings",
            "Open security settings",
            "Tell you where security settings are. DVielle does not switch them here.",
            "safety.open_settings",
        ),
        _not_now(),
        _never("Never for this", "Stop nagging about this protection item. A quiet log line remains."),
        _why(),
    ]


def safety_startup_options() -> list[Option]:
    return [
        _learn(
            "keep_on",
            "This is OK — keep on",
            "Remember this startup as allowed when it is really this file. A different file still asks.",
            "allow",
            "monitoring",
        ),
        _mutate(
            "disable_startup",
            "Disable this startup",
            "Turn off this user startup item only, after checking it is the same file.",
            "safety.disable_startup",
        ),
        _mutate(
            "smart_close",
            "Smart Close this process",
            "Quit the process only if its identity still matches what we just saw.",
            "safety.smart_close",
        ),
        _guide(
            "open_settings",
            "Open security settings",
            "Tell you where to review startup settings. Nothing else is changed.",
            "safety.open_settings",
        ),
        _not_now(),
        _never("Never for this", "Stop nagging about this startup. A quiet log line remains."),
        _why(),
    ]


def speed_options() -> list[Option]:
    return [
        _learn(
            "keep_on",
            "This is OK (keep on while I work)",
            "Remember this app as allowed. Next time it is actually this app, DVielle stays quiet.",
            "allow",
            "monitoring",
        ),
        _mutate(
            "pause_close",
            "Pause / Smart Close this app",
            "Close this app after a fresh identity check. System processes are refused.",
            "speed.pause_process",
        ),
        _mutate(
            "disable_startup",
            "Disable at startup",
            "Disable the user startup item when we can identify that file. Otherwise nothing changes.",
            "speed.disable_startup",
        ),
        _not_now(),
        _never("Never warn for this app", "Stop nagging about this app. A quiet log line remains."),
        _why(),
    ]


def storage_options() -> list[Option]:
    return [
        _mutate(
            "free_now",
            "Free safe temp space now",
            "Delete leftover files in temporary folders only. Skip in-use files. This is not fully undoable.",
            "storage.free_safe_temp",
        ),
        Option(
            "preview",
            "Preview what will be cleaned",
            "List safe temporary files and sizes. Nothing is deleted.",
            "preview",
            handler="storage.preview",
        ),
        _mutate(
            "empty_recycle",
            "Empty Recycle Bin",
            "Empty the recycle bin only if this system has one DVielle can see. Documents are not touched.",
            "storage.empty_recycle",
        ),
        _not_now(),
        _never("Never auto-clean", "Remember not to nag or auto-clean safe temporary files. Nothing is deleted now."),
        _why(),
    ]


def _stub(pillar_label: str) -> list[Option]:
    return [
        _learn("allow", f"Allow — keep on ({pillar_label})", "Remember this subject as allowed.", "allow", "monitoring"),
        _not_now(),
        _never("Never for this", "Stop nagging about this subject."),
        _why(),
    ]


CATALOGS = {
    ("safety", "protection_off"): safety_protection_options,
    ("safety", "suspicious_startup"): safety_startup_options,
    ("safety", "new_startup"): safety_startup_options,
    ("speed", "resource_hog"): speed_options,
    ("storage", "safe_temp"): storage_options,
    ("privacy", "unexpected_egress"): lambda: _stub("privacy"),
    ("ai_data", "unexpected_upload"): lambda: _stub("AI"),
    ("footprint", "exposure"): lambda: _stub("footprint"),
    ("camera", "camera_use"): lambda: _stub("camera"),
}


def options_for(pillar: str, kind: str) -> list[Option]:
    builder = CATALOGS.get((pillar, kind))
    if builder is None:
        raise FailClosed(f"no options catalog for {pillar}/{kind}")
    built = builder()
    if not built:
        raise FailClosed(f"empty options catalog for {pillar}/{kind}")
    return built

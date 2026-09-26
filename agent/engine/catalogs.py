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


def privacy_options() -> list[Option]:
    return [
        _learn(
            "keep_on",
            "Allow this app's internet (keep on)",
            "Remember this app as allowed. Next time it is actually open and talking, DVielle stays quiet.",
            "allow",
            "monitoring",
        ),
        _mutate(
            "block_network",
            "Block this app's network",
            "Add a per-app outbound block only after an identity check. If that cannot be done, nothing is blocked.",
            "privacy.block_network",
        ),
        _guide(
            "open_settings",
            "Open privacy / firewall settings",
            "Point you at privacy and firewall settings. DVielle does not claim traffic stopped.",
            "privacy.open_settings",
        ),
        _not_now(),
        _never("Never for this", "Stop nagging about this app's internet. A quiet log line remains."),
        _why(),
    ]


def ai_options() -> list[Option]:
    return [
        _learn(
            "keep_on",
            "Allow this AI app (keep on)",
            "Remember this AI app as allowed while it is actually open. A different app still asks.",
            "allow",
            "monitoring",
        ),
        _mutate(
            "block_network",
            "Block this AI app's internet",
            "Add a per-app outbound block only after an identity check. This does not prove a model was trained.",
            "ai.block_network",
        ),
        _guide(
            "open_settings",
            "Open improve-the-model / privacy settings",
            "Open a settings link when one is reachable. DVielle does not change the model setting itself.",
            "ai.open_settings",
        ),
        _not_now(),
        _never("Never for this", "Stop nagging about this AI app. A quiet log line remains."),
        _why(),
    ]


def camera_options() -> list[Option]:
    return [
        _learn(
            "keep_on",
            "Allow this app (keep on)",
            "Remember this app as allowed to use the camera when it is actually open.",
            "allow",
            "monitoring",
        ),
        _mutate(
            "stop_camera",
            "Stop this app's camera use",
            "Close this app only if its identity still matches. The whole camera is not switched off.",
            "camera.stop_use",
        ),
        _guide(
            "revoke_app",
            "Turn off camera access for this app",
            "Open this app's camera privacy settings when the system allows. DVielle does not disable every camera.",
            "camera.open_app_settings",
        ),
        _guide(
            "cover_reminder",
            "Remind me to cover the lens",
            "Show a cover or shutter reminder. Nothing is switched off and no picture is stored.",
            "camera.cover_reminder",
        ),
        _guide(
            "system_off",
            "Turn camera off in system settings",
            "Open system camera privacy settings. DVielle does not flip that switch by itself.",
            "camera.open_system_settings",
        ),
        _not_now(),
        _never("Never warn for this app", "Stop nagging about this app's camera use. A quiet log line remains."),
        _why(),
    ]


def footprint_options() -> list[Option]:
    return [
        _guide(
            "lockdown",
            "Start local lockdown steps",
            "Walk through sign-out, session revoke, and two-factor login on this PC. Nothing is changed until you do it.",
            "footprint.lockdown",
        ),
        _guide(
            "breach_check",
            "Check breach (opt-in email)",
            "An opt-in check sends your email off this device. DVielle will not look up anyone else.",
            "footprint.breach_check",
        ),
        _guide(
            "diy_opt_out",
            "Open DIY opt-out",
            "Open a takedown and opt-out checklist you complete yourself. DVielle does not search a name.",
            "footprint.diy_opt_out",
        ),
        _guide(
            "partner",
            "Start / open partner removal or monitoring",
            "Show removal and monitoring playbooks such as DeleteMe, Incogni, Aura, LifeLock, and REMOVE. No service is required.",
            "footprint.open_partner",
        ),
        _guide(
            "mark_resolved",
            "Mark resolved",
            "Record that you finished this step. This does not erase copies on the internet.",
            "footprint.mark_resolved",
        ),
        _guide(
            "still_monitoring",
            "Still monitoring",
            "Keep this ticket on the monitoring list. A partner or a later checkup can bring it back.",
            "footprint.still_monitoring",
        ),
        _not_now(),
        _why(),
    ]


CATALOGS = {
    ("safety", "protection_off"): safety_protection_options,
    ("safety", "suspicious_startup"): safety_startup_options,
    ("safety", "new_startup"): safety_startup_options,
    ("speed", "resource_hog"): speed_options,
    ("storage", "safe_temp"): storage_options,
    ("privacy", "unexpected_egress"): privacy_options,
    ("ai_data", "unexpected_upload"): ai_options,
    ("camera", "camera_use"): camera_options,
}
for _footprint_kind in (
    "exposure",
    "local_residue",
    "breach_hit",
    "public_search",
    "broker_listing",
    "dark_web_alert",
):
    CATALOGS[("footprint", _footprint_kind)] = footprint_options


def options_for(pillar: str, kind: str) -> list[Option]:
    builder = CATALOGS.get((pillar, kind))
    if builder is None:
        raise FailClosed(f"no options catalog for {pillar}/{kind}")
    built = builder()
    if not built:
        raise FailClosed(f"empty options catalog for {pillar}/{kind}")
    return built

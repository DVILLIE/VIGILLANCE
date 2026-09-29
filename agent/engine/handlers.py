"""Approved actions. Each one reports what actually changed."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from agent.engine.footprint import FootprintProgress, partner_playbook
from agent.engine.models import AuthToken, PolicyDenied
from agent.engine.net_block import block_app_network
from agent.engine.policy import PolicyGate, handler_is_denied
from agent.engine.temp_clean import free, scan
from agent.modules.resource_advisor import SYSTEM_PROTECTED
from agent.policy.dual import HANDLER_KIND, require_cortex_mutate

Lookup = Callable[[int], tuple[str, str] | None]
Closer = Callable[[int, str], tuple[bool, str]]
Blocker = Callable[[str, str], tuple[bool, str]]
Opener = Callable[[str], tuple[bool, str]]
BreachCheck = Callable[[str], list]


@dataclass
class HandlerContext:
    lookup: Lookup
    close: Closer
    startup_dir: Path | None = None
    temp_roots: list[Path] = field(default_factory=list)
    trash_root: Path | None = None
    locked_paths: set[str] = field(default_factory=set)
    os_family: str = ""
    block_app: Blocker | None = None
    open_os: Opener | None = None
    learn_dir: Path | None = None
    breach_email: str | None = None
    breach_check: BreachCheck | None = None
    powershell: Callable[..., tuple[str | None, bool]] | None = None
    defender_health_reader: Callable[[], Any] | None = None
    maps_reader: Callable[[], Any] | None = None


class HandlerRegistry:
    def __init__(self, policy: PolicyGate, dual=None) -> None:
        self.policy = policy
        self.dual = dual
        self._fns: dict[str, Callable] = {}

    def register(self, name: str, fn: Callable) -> None:
        if handler_is_denied(name):
            raise PolicyDenied(f"refusing to register denylisted handler {name}")
        self._fns[name] = fn

    def invoke(self, name: str, finding: dict, ctx: HandlerContext, token: AuthToken | None) -> dict:
        fn = self._fns.get(name)
        if fn is None:
            raise PolicyDenied(f"no handler registered for {name}")
        if name in HANDLER_KIND:
            if self.dual is None:
                raise PolicyDenied("refusing OS change without Cortex authorization")
            return self.dual.perform(
                handler_name=name,
                finding=finding,
                token=token,
                mutator=lambda: fn(finding, ctx),
            )
        self.policy.require(token, finding["id"], name)
        return fn(finding, ctx)


def register_default_handlers(registry: HandlerRegistry) -> None:
    registry.register("safety.turn_protection_on", turn_protection_on)
    registry.register("safety.open_settings", open_settings)
    registry.register("safety.disable_startup", disable_startup)
    registry.register("safety.smart_close", smart_close)
    registry.register("speed.pause_process", smart_close)
    registry.register("speed.disable_startup", disable_startup)
    registry.register("storage.preview", preview_temp)
    registry.register("storage.free_safe_temp", free_temp)
    registry.register("storage.empty_recycle", empty_recycle)
    registry.register("privacy.block_network", block_network)
    registry.register("privacy.open_settings", open_privacy_settings)
    registry.register("ai.block_network", block_network)
    registry.register("ai.open_settings", open_ai_settings)
    registry.register("camera.stop_use", smart_close)
    registry.register("camera.open_app_settings", open_camera_app_settings)
    registry.register("camera.open_system_settings", open_camera_system_settings)
    registry.register("camera.cover_reminder", cover_reminder)
    registry.register("footprint.lockdown", footprint_lockdown)
    registry.register("footprint.breach_check", footprint_breach_check)
    registry.register("footprint.diy_opt_out", footprint_diy_opt_out)
    registry.register("footprint.open_partner", footprint_open_partner)
    registry.register("footprint.mark_resolved", footprint_mark_resolved)
    registry.register("footprint.still_monitoring", footprint_still_monitoring)
    registry.register("safety.set_asr_rule", set_asr_rule)
    registry.register("safety.set_cfa_mode", set_cfa_mode)


def _result(performed: bool, message: str, *, reversible: str = "no", status: str | None = None) -> dict:
    body = {"performed": performed, "message": message, "reversible": reversible}
    if status:
        body["status"] = status
    return body


def set_asr_rule(finding: dict, ctx: HandlerContext) -> dict:
    from agent.modules.prevention_apply import apply_asr_rule, undo_path_for

    signals = finding.get("signals") or {}
    return apply_asr_rule(
        guid=str(signals.get("guid") or ""),
        action=signals.get("action"),
        runner=ctx.powershell,
        health_reader=ctx.defender_health_reader,
        maps_reader=ctx.maps_reader,
        undo_path=undo_path_for(ctx.learn_dir),
        sku=signals.get("sku"),
    )


def set_cfa_mode(finding: dict, ctx: HandlerContext) -> dict:
    from agent.modules.prevention_apply import apply_cfa_mode, undo_path_for

    signals = finding.get("signals") or {}
    return apply_cfa_mode(
        mode=signals.get("mode"),
        runner=ctx.powershell,
        health_reader=ctx.defender_health_reader,
        maps_reader=ctx.maps_reader,
        undo_path=undo_path_for(ctx.learn_dir),
        sku=signals.get("sku"),
    )


def turn_protection_on(finding: dict, ctx: HandlerContext) -> dict:
    return _result(
        False,
        "DVielle did not change protection. Turning it on needs an administrator and a "
        "supported tool, and this version does not switch it. Nothing was turned on.",
    )


def open_settings(finding: dict, ctx: HandlerContext) -> dict:
    if ctx.os_family == "Windows":
        where = "On Windows, open Windows Security."
    elif ctx.os_family == "Darwin":
        where = "On macOS, open System Settings → Privacy & Security."
    else:
        where = "Open this system's security settings."
    return _result(False, where + " DVielle did not change protection.")


def _identity(finding: dict, ctx: HandlerContext) -> tuple[bool, str, int, str]:
    signals = finding.get("signals") or {}
    try:
        pid = int(signals.get("pid") or 0)
    except (TypeError, ValueError):
        pid = 0
    name = str(signals.get("name") or "")
    expected_path = str(signals.get("path") or "")
    if pid <= 1 or not name:
        return False, "Identity unclear. DVielle did not touch that process.", pid, name
    if name.lower() in SYSTEM_PROTECTED:
        return False, f"DVielle will not close {name}. It is a system process.", pid, name
    current = ctx.lookup(pid)
    if current is None:
        return False, "That process is already gone. Nothing was changed.", pid, name
    current_name, current_path = current
    if current_name.lower() != name.lower():
        return False, "Identity changed. DVielle did not touch the process.", pid, name
    if expected_path and current_path and current_path != expected_path:
        return False, "Identity changed. DVielle did not touch the process.", pid, name
    return True, "", pid, name


def smart_close(finding: dict, ctx: HandlerContext) -> dict:
    require_cortex_mutate()
    ok, message, pid, name = _identity(finding, ctx)
    if not ok:
        return _result(False, message)
    closed, detail = ctx.close(pid, name)
    if not closed:
        return _result(False, detail)
    return _result(True, detail or f"Closed {name} after its identity still matched.", reversible="no")


def disable_startup(finding: dict, ctx: HandlerContext) -> dict:
    require_cortex_mutate()
    source = (finding.get("signals") or {}).get("startup_file")
    if not source or ctx.startup_dir is None:
        return _result(False, "No user startup file was identified. Nothing was disabled.")
    path = Path(str(source))
    root = ctx.startup_dir
    try:
        resolved = path.resolve()
        root_resolved = root.resolve()
        resolved.relative_to(root_resolved)
    except (OSError, ValueError):
        return _result(False, "That startup item is outside the user startup folder. Nothing was changed.")
    if not resolved.is_file():
        return _result(False, "The startup file is not there. Nothing was changed.")
    dest = resolved.with_name(resolved.name + ".dvielle-disabled")
    try:
        resolved.rename(dest)
    except OSError:
        return _result(False, "The startup file could not be renamed. Nothing else was changed.")
    return _result(True, "Disabled this user startup item.", reversible="yes")


def preview_temp(finding: dict, ctx: HandlerContext) -> dict:
    files = scan(ctx.temp_roots, ctx.locked_paths)
    if not files:
        return _result(False, "No safe temporary files were found. Nothing will be deleted.")
    lines = []
    total = 0
    for path, size, is_locked in files:
        state = "in use, would skip" if is_locked else "would remove"
        lines.append(f"{path.name}: {size} bytes ({state})")
        if not is_locked:
            total += size
    return _result(False, "Preview only. Nothing was deleted.\n" + "\n".join(lines) + f"\nAbout {total} bytes can be freed.")


def free_temp(finding: dict, ctx: HandlerContext) -> dict:
    require_cortex_mutate()
    if not ctx.temp_roots:
        return _result(False, "No temporary folder was configured. Nothing was deleted.")
    freed, skipped = free(ctx.temp_roots, ctx.locked_paths)
    message = (
        f"Freed {freed} bytes from temporary folders. Skipped {skipped} in-use or out-of-scope file(s). "
        "Deleted temporary files cannot be undone."
    )
    if freed <= 0:
        return _result(False, message + " Nothing was removed.")
    return _result(True, message)


def empty_recycle(finding: dict, ctx: HandlerContext) -> dict:
    require_cortex_mutate()
    if ctx.trash_root is None or not ctx.trash_root.exists():
        return _result(False, "This system has no recycle bin DVielle can empty. Nothing was deleted.")
    freed, skipped = free([ctx.trash_root], set())
    if freed <= 0:
        return _result(False, "The recycle bin was not emptied. Nothing was deleted.")
    return _result(True, f"Emptied the recycle bin and freed {freed} bytes. Skipped {skipped}. This cannot be undone.")


def default_lookup(pid: int) -> tuple[str, str] | None:
    try:
        import psutil

        proc = psutil.Process(pid)
        path = ""
        try:
            path = proc.exe()
        except (psutil.AccessDenied, psutil.Error, OSError):
            path = ""
        return proc.name(), path
    except Exception:
        return None


def default_close(pid: int, name: str) -> tuple[bool, str]:
    require_cortex_mutate()
    from agent.modules.resource_advisor import close_pids

    return close_pids([pid], [name], force=False)


def close_process(pid: int, name: str) -> tuple[bool, str]:
    """Name kept so a direct OS close can be patched and refused outside DualGate."""
    return default_close(pid, name)


def block_network(finding: dict, ctx: HandlerContext) -> dict:
    require_cortex_mutate()
    ok, message, _pid, name = _identity(finding, ctx)
    if not ok:
        text = message if "not stopped" in message.lower() else message.rstrip(".") + ". Traffic was not stopped."
        return _result(False, text)
    path = str((finding.get("signals") or {}).get("path") or "")
    if ctx.block_app is not None:
        performed, detail = ctx.block_app(name, path)
    else:
        performed, detail = block_app_network(name, path)
    if performed and "does not prove" not in detail.lower():
        detail = detail.rstrip(".") + ". This does not prove every connection already stopped."
    if not performed and "not stopped" not in detail.lower():
        detail = detail.rstrip(".") + ". Traffic was not stopped."
    return _result(performed, detail, reversible="yes" if performed else "no")


def _settings_message(target: str, *, launched: bool) -> str:
    if target == "ai":
        if launched:
            return (
                "Asked the system to open privacy settings. "
                "That is not this app's own improve-the-model page. "
                "DVielle did not change a model setting and did not prove any upload stopped."
            )
        return (
            "No improve-the-model settings link is reachable from here. "
            "DVielle did not change a model setting and did not prove any upload stopped."
        )
    if target.startswith("camera"):
        if launched:
            return (
                "Asked the system to open camera privacy settings. "
                "DVielle did not turn the camera off and stored no picture."
            )
        return "Could not open camera privacy settings. The camera was not turned off and no picture was stored."
    if launched:
        return "Asked the system to open privacy and firewall settings. DVielle did not prove traffic stopped."
    return "Could not open privacy and firewall settings from here. DVielle did not prove traffic stopped."


def _open_target(ctx: HandlerContext, target: str) -> dict:
    launched = False
    if ctx.open_os is not None:
        try:
            launched, _detail = ctx.open_os(target)
        except OSError:
            launched = False
    return _result(False, _settings_message(target, launched=bool(launched)))


def open_privacy_settings(finding: dict, ctx: HandlerContext) -> dict:
    return _open_target(ctx, "privacy")


def open_ai_settings(finding: dict, ctx: HandlerContext) -> dict:
    return _open_target(ctx, "ai")


def open_camera_app_settings(finding: dict, ctx: HandlerContext) -> dict:
    return _open_target(ctx, "camera_app")


def open_camera_system_settings(finding: dict, ctx: HandlerContext) -> dict:
    return _open_target(ctx, "camera_system")


def cover_reminder(finding: dict, ctx: HandlerContext) -> dict:
    return _result(
        False,
        "A physical cover or shutter is still the surest way to make sure nobody sees you. "
        "DVielle did not turn the camera off and stored no picture.",
    )


def _footprint_subject(finding: dict) -> str:
    return str(finding.get("subject_identity") or "")


def _remember_progress(ctx: HandlerContext, finding: dict, status: str, partner: str = "", notes: str = "") -> None:
    if ctx.learn_dir is None:
        return
    progress = FootprintProgress(ctx.learn_dir / "baseline_footprint.txt")
    updated = str(finding.get("updated_at") or "")
    progress.record(_footprint_subject(finding), status, updated, partner=partner, notes=notes)


def _own_machine(finding: dict) -> str | None:
    target = (finding.get("signals") or {}).get("target") or "self"
    if target != "self":
        return "DVielle will not look up another person. Nothing was searched."
    return None


def footprint_lockdown(finding: dict, ctx: HandlerContext) -> dict:
    refused = _own_machine(finding)
    if refused:
        return _result(False, refused, status="found")
    _remember_progress(ctx, finding, "in_progress", notes="local lockdown steps opened")
    return _result(
        False,
        "On this PC: sign out of accounts you are not using, revoke leftover app sessions, "
        "and turn on two-factor login. DVielle did not sign you out and did not change a password. "
        "This ticket stays in progress until you mark it resolved.",
        status="in_progress",
    )


def footprint_breach_check(finding: dict, ctx: HandlerContext) -> dict:
    refused = _own_machine(finding)
    if refused:
        return _result(False, refused, status="found")
    email = (ctx.breach_email or "").strip()
    notice = (
        "A breach check sends your email off this device to a service such as Have I Been Pwned. "
        "DVielle does not look up other people."
    )
    if "@" not in email:
        return _result(
            False,
            "No email was enrolled. DVielle did not send an address off this device and did not look up any person.",
            status="found",
        )
    if ctx.breach_check is None:
        return _result(False, notice + " No checker is connected, so nothing was sent.", status="found")
    try:
        hits = list(ctx.breach_check(email) or [])
    except OSError:
        return _result(False, notice + " The check failed. Nothing was marked as a live breach.", status="found")
    _remember_progress(ctx, finding, "in_progress", notes=f"opt-in check returned {len(hits)} hit(s)")
    return _result(
        False,
        notice
        + f" The checker reported {len(hits)} hit(s). Change those passwords and turn on two-factor login. "
        + "This does not erase copies on the internet.",
        status="in_progress",
    )


def footprint_diy_opt_out(finding: dict, ctx: HandlerContext) -> dict:
    refused = _own_machine(finding)
    if refused:
        return _result(False, refused, status="found")
    _remember_progress(ctx, finding, "in_progress", notes="diy opt-out checklist opened")
    return _result(
        False,
        "Do-it-yourself path: search only your own name, open each site's opt-out or takedown page, "
        "and set a Google Alert for your name if you want a reminder. "
        "DVielle did not search anyone and did not submit a form. This ticket stays in progress.",
        status="in_progress",
    )


def footprint_open_partner(finding: dict, ctx: HandlerContext) -> dict:
    refused = _own_machine(finding)
    if refused:
        return _result(False, refused, status="found")
    if ctx.open_os is not None:
        try:
            ctx.open_os("footprint_partner")
        except OSError:
            pass
    _remember_progress(ctx, finding, "monitoring", partner="playbook", notes="partner playbook opened")
    return _result(False, partner_playbook() + "\nThis stays on the monitoring list.", status="monitoring")


def footprint_mark_resolved(finding: dict, ctx: HandlerContext) -> dict:
    refused = _own_machine(finding)
    if refused:
        return _result(False, refused, status="found")
    _remember_progress(ctx, finding, "resolved", notes="user marked resolved")
    return _result(
        True,
        "You marked this ticket resolved. DVielle did not delete your data from the internet, "
        "and this free app does not erase every copy on earth.",
        status="resolved",
    )


def footprint_still_monitoring(finding: dict, ctx: HandlerContext) -> dict:
    refused = _own_machine(finding)
    if refused:
        return _result(False, refused, status="found")
    _remember_progress(ctx, finding, "monitoring", notes="user left it monitoring")
    return _result(
        False,
        "This stays on the monitoring list. Nothing was erased. A later checkup or a partner alert can open it again.",
        status="monitoring",
    )

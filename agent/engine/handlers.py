"""Approved actions. Each one reports what actually changed."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from agent.engine.models import AuthToken, PolicyDenied
from agent.engine.policy import PolicyGate, handler_is_denied
from agent.engine.temp_clean import free, scan
from agent.modules.resource_advisor import SYSTEM_PROTECTED, close_process

Lookup = Callable[[int], tuple[str, str] | None]
Closer = Callable[[int, str], tuple[bool, str]]


@dataclass
class HandlerContext:
    lookup: Lookup
    close: Closer
    startup_dir: Path | None = None
    temp_roots: list[Path] = field(default_factory=list)
    trash_root: Path | None = None
    locked_paths: set[str] = field(default_factory=set)
    os_family: str = ""


class HandlerRegistry:
    def __init__(self, policy: PolicyGate) -> None:
        self.policy = policy
        self._fns: dict[str, Callable] = {}

    def register(self, name: str, fn: Callable) -> None:
        if handler_is_denied(name):
            raise PolicyDenied(f"refusing to register denylisted handler {name}")
        self._fns[name] = fn

    def invoke(self, name: str, finding: dict, ctx: HandlerContext, token: AuthToken | None) -> dict:
        self.policy.require(token, finding["id"], name)
        fn = self._fns.get(name)
        if fn is None:
            raise PolicyDenied(f"no handler registered for {name}")
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


def _result(performed: bool, message: str, *, reversible: str = "no") -> dict:
    return {"performed": performed, "message": message, "reversible": reversible}


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
    ok, message, pid, name = _identity(finding, ctx)
    if not ok:
        return _result(False, message)
    closed, detail = ctx.close(pid, name)
    if not closed:
        return _result(False, detail)
    return _result(True, detail or f"Closed {name} after its identity still matched.", reversible="no")


def disable_startup(finding: dict, ctx: HandlerContext) -> dict:
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
    return close_process(pid, name)

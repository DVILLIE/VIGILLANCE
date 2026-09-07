"""Smart CPU/RAM advisor — brief popups naming culprits and close suggestions."""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Any

import psutil

from agent.store.db import AgentStore
from agent.utils import IS_WINDOWS, get_foreground_process

logger = logging.getLogger("dvielle.resource_advisor")

# Never suggest closing / never allow Quick Close on these
SYSTEM_PROTECTED = {
    "system", "registry", "smss.exe", "csrss.exe", "wininit.exe", "services.exe",
    "lsass.exe", "svchost.exe", "dwm.exe", "explorer.exe", "winlogon.exe",
    "msmpeng.exe", "securityhealthservice.exe", "searchhost.exe", "shellexperiencehost.exe",
    "runtimebroker.exe", "applicationframehost.exe", "systemsettings.exe",
    "dvielle", "python.exe", "pythonw.exe", "dvielle.exe",
    # Kernel / session helpers — terminate() may "succeed" on a handle but the OS keeps them
    "memcompression", "memory compression", "audiodg.exe", "conhost.exe",
    "sihost.exe", "fontdrvhost.exe", "taskmgr.exe", "system idle process",
    "secure system", "registry",
}

# Often safe to close when in background and hogging resources
COMMON_BACKGROUND = {
    "discord.exe", "steam.exe", "epicgameslauncher.exe", "spotify.exe",
    "teams.exe", "slack.exe", "zoom.exe", "onedrive.exe", "dropbox.exe",
    "chrome.exe", "msedge.exe", "firefox.exe", "brave.exe",
    "gamebar.exe", "gamebarftserver.exe", "searchindexer.exe",
}


@dataclass
class ProcessFootprint:
    pid: int
    name: str
    cpu_percent: float
    memory_mb: float
    is_foreground: bool = False
    closability: float = 0.0  # higher = better candidate to close


@dataclass
class AppGroup:
    """Task-Manager-like app group (smart, not a full Task Manager clone)."""

    key: str
    display_name: str
    process_names: list[str]
    pids: list[int]
    memory_mb: float
    cpu_percent: float
    is_active_work: bool
    role: str  # main | helper | background
    related_to: str | None
    close_advice: str
    voice_line: str
    risk: str  # safe | caution | danger_active
    primary_pid: int
    primary_name: str


# Families: closing any member can affect the family "owner"
# Keys are lowercase exe names without path
APP_FAMILIES: dict[str, dict[str, Any]] = {
    "cursor.exe": {
        "family": "Cursor",
        "members": {"cursor.exe"},
        "friendly": "Cursor (your editor / agents)",
    },
    "chrome.exe": {
        "family": "Google Chrome",
        "members": {"chrome.exe"},
        "friendly": "Google Chrome",
    },
    "msedge.exe": {
        "family": "Microsoft Edge",
        "members": {"msedge.exe"},
        "friendly": "Microsoft Edge",
    },
    "msedgewebview2.exe": {
        "family": "WebView2 helper",
        "members": {"msedgewebview2.exe"},
        "friendly": "Edge WebView2 (used by Search, apps, and Edge)",
        "often_helper_of": ["SearchHost.exe", "SearchApp.exe", "msedge.exe", "Widgets.exe"],
    },
    "searchhost.exe": {
        "family": "Windows Search",
        "members": {"searchhost.exe", "searchapp.exe"},
        "friendly": "Windows Search",
    },
    "searchapp.exe": {
        "family": "Windows Search",
        "members": {"searchhost.exe", "searchapp.exe"},
        "friendly": "Windows Search",
    },
    "firefox.exe": {"family": "Firefox", "members": {"firefox.exe"}, "friendly": "Firefox"},
    "brave.exe": {"family": "Brave", "members": {"brave.exe"}, "friendly": "Brave"},
    "discord.exe": {"family": "Discord", "members": {"discord.exe"}, "friendly": "Discord"},
    "spotify.exe": {"family": "Spotify", "members": {"spotify.exe"}, "friendly": "Spotify"},
    "whatsapp.exe": {
        "family": "WhatsApp",
        "members": {"whatsapp.exe", "whatsapp.hosts.exe", "whatsapp.host.exe"},
        "friendly": "WhatsApp",
    },
    "whatsapp.host.exe": {
        "family": "WhatsApp",
        "members": {"whatsapp.exe", "whatsapp.host.exe"},
        "friendly": "WhatsApp host (background for WhatsApp)",
        "often_helper_of": ["WhatsApp.exe"],
    },
    "phoneexperiencehost.exe": {
        "family": "Phone Link",
        "members": {"phoneexperiencehost.exe"},
        "friendly": "Phone Link / Your Phone",
    },
}


def _pids_with_visible_windows() -> set[int]:
    """PIDs that own at least one visible top-level window (Task Manager style)."""
    if not IS_WINDOWS:
        return set()
    found: set[int] = set()
    try:
        import ctypes
        from ctypes import wintypes

        user32 = ctypes.windll.user32  # type: ignore[attr-defined]
        WNDENUMPROC = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)

        def _cb(hwnd, _lparam):
            if user32.IsWindowVisible(hwnd):
                pid = wintypes.DWORD()
                user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
                if pid.value:
                    found.add(int(pid.value))
            return True

        user32.EnumWindows(WNDENUMPROC(_cb), 0)
    except Exception:
        pass
    return found


def _family_for(name: str) -> dict[str, Any] | None:
    return APP_FAMILIES.get(name.lower())


def _running_names() -> set[str]:
    names: set[str] = set()
    for proc in psutil.process_iter(["name"]):
        try:
            n = (proc.info.get("name") or "").lower()
            if n:
                names.add(n)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return names


def _build_app_group(
    name: str,
    footprints: list[ProcessFootprint],
    fg_name: str | None,
    running: set[str],
) -> AppGroup:
    lower = name.lower()
    fam = _family_for(lower) or {
        "family": name,
        "members": {lower},
        "friendly": name,
    }
    members = {m.lower() for m in fam.get("members", {lower})}
    # Include only members that are actually in our footprint set for this merge key
    group_fps = [p for p in footprints if p.name.lower() in members or p.name.lower() == lower]
    if not group_fps:
        group_fps = [p for p in footprints if p.name.lower() == lower]

    names = sorted({p.name for p in group_fps})
    pids = [p.pid for p in group_fps]
    mem = sum(p.memory_mb for p in group_fps)
    cpu = max((p.cpu_percent for p in group_fps), default=0.0)
    primary = max(group_fps, key=lambda p: p.memory_mb)

    fg_lower = (fg_name or "").lower()
    visible = _pids_with_visible_windows()
    has_window = any(pid in visible for pid in pids)

    is_active = bool(fg_lower) and (
        fg_lower == lower
        or fg_lower in members
        or any(p.is_foreground for p in group_fps)
    )

    # Helper of another running app?
    related_to = None
    often = fam.get("often_helper_of") or []
    for owner in often:
        if owner.lower() in running and owner.lower() != lower:
            related_to = owner
            break
    if not related_to and not is_active:
        try:
            sample = psutil.Process(primary.pid)
            parent = sample.parent()
            if parent:
                pname = (parent.name() or "").lower()
                if pname and pname != lower and pname not in SYSTEM_PROTECTED:
                    # Don't treat every child shell as "linked" to editors (too noisy)
                    if pname not in {"powershell.exe", "cmd.exe", "pwsh.exe", "windowsTerminal.exe"}:
                        pf = _family_for(pname)
                        related_to = pf["friendly"] if pf else parent.name()
                    elif lower in {"powershell.exe", "cmd.exe", "pwsh.exe"}:
                        pf = _family_for(pname)
                        related_to = pf["friendly"] if pf else parent.name()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

    if is_active:
        risk = "danger_active"
        role = "main"
        advice = (
            f"You are currently working in {fam.get('friendly', name)}. "
            f"Closing it will quit your active work"
            + (f" and {len(pids)} related process(es)" if len(pids) > 1 else "")
            + "."
        )
        voice = (
            f"Warning. You are currently using {fam.get('friendly', name)}. "
            f"Do you really want to close the application you are working on?"
        )
    elif related_to:
        risk = "caution"
        role = "helper"
        advice = (
            f"{fam.get('friendly', name)} looks linked to {related_to}. "
            f"Closing it may cause problems with that main application "
            f"(blank panels, search broken, or the app restarting helpers)."
        )
        voice = (
            f"Caution. {name} appears associated with {related_to}. "
            f"Closing it might cause problems with the main application. "
            f"Only continue if you are sure."
        )
    elif has_window:
        risk = "caution"
        role = "main"
        advice = (
            f"{fam.get('friendly', name)} still has open window(s) "
            f"({len(pids)} process(es)). Closing may lose unsaved work."
        )
        voice = (
            f"Caution. {fam.get('friendly', name)} still has open windows. "
            f"Closing it may lose unsaved work. Do you want to continue?"
        )
    else:
        risk = "safe"
        role = "background"
        count = len(pids)
        advice = (
            f"Safe to close — no worries. "
            f"{fam.get('friendly', name)} is in the background"
            + (f" ({count} processes)" if count > 1 else "")
            + f", about {_format_mb(mem)} RAM."
        )
        voice = (
            f"Safe to close. {fam.get('friendly', name)} is a background app. No worries."
        )

    return AppGroup(
        key=fam.get("family", name).lower(),
        display_name=str(fam.get("friendly", name)),
        process_names=names,
        pids=pids,
        memory_mb=mem,
        cpu_percent=cpu,
        is_active_work=is_active,
        role=role,
        related_to=related_to,
        close_advice=advice,
        voice_line=voice,
        risk=risk,
        primary_pid=primary.pid,
        primary_name=primary.name,
    )


def get_app_groups(limit: int = 6, include_active: bool = True) -> list[AppGroup]:
    """Smart Task-Manager-style groups for Quick Close."""
    fg_pid, fg_name = get_foreground_process()
    processes = _collect_processes(fg_pid)
    running = _running_names()

    # Collapse by family key
    buckets: dict[str, list[ProcessFootprint]] = {}
    for p in processes:
        if p.name.lower() in SYSTEM_PROTECTED:
            continue
        fam = _family_for(p.name)
        key = str(fam["family"]).lower() if fam else p.name.lower()
        buckets.setdefault(key, []).append(p)

    groups: list[AppGroup] = []
    for key, fps in buckets.items():
        # Skip tiny noise
        if sum(p.memory_mb for p in fps) < 30 and max(p.cpu_percent for p in fps) < 2:
            continue
        sample_name = max(fps, key=lambda x: x.memory_mb).name
        g = _build_app_group(sample_name, fps, fg_name, running)
        if g.is_active_work and not include_active:
            continue
        # Still show active so user can be warned; prefer non-tiny
        groups.append(g)

    def sort_key(g: AppGroup) -> tuple:
        # Active first (so user sees warning), then heavy background
        risk_rank = {"danger_active": 0, "caution": 1, "safe": 2}.get(g.risk, 3)
        return (risk_rank, -g.memory_mb)

    groups.sort(key=sort_key)
    return groups[:limit]


def get_closeable_processes(limit: int = 5) -> list[ProcessFootprint]:
    """Legacy helper — prefer get_app_groups for the GUI."""
    groups = get_app_groups(limit=limit, include_active=False)
    out: list[ProcessFootprint] = []
    for g in groups:
        if g.risk == "danger_active":
            continue
        out.append(
            ProcessFootprint(
                pid=g.primary_pid,
                name=g.primary_name,
                cpu_percent=g.cpu_percent,
                memory_mb=g.memory_mb,
                is_foreground=g.is_active_work,
                closability=80 if g.risk == "safe" else 40,
            )
        )
    return out[:limit]


@dataclass
class ResourceAdvice:
    resource: str  # "CPU" or "RAM"
    usage_percent: float
    headline: str
    suggestion: str
    offenders: list[ProcessFootprint] = field(default_factory=list)


_last_cpu_toast = 0.0
_last_ram_toast = 0.0


def _memory_mb(proc: psutil.Process) -> float:
    try:
        return proc.memory_info().rss / (1024 * 1024)
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return 0.0


def _score_closability(name: str, is_foreground: bool, cpu: float, mem_mb: float) -> float:
    lower = name.lower()
    if lower in SYSTEM_PROTECTED or is_foreground:
        return 0.0
    score = 0.0
    if lower in COMMON_BACKGROUND:
        score += 40
    if mem_mb > 500:
        score += min(30, mem_mb / 100)
    if cpu > 10:
        score += min(30, cpu)
    if not is_foreground:
        score += 20
    return score


def _collect_processes(foreground_pid: int | None) -> list[ProcessFootprint]:
    footprints: list[ProcessFootprint] = []
    for proc in psutil.process_iter(["pid", "name", "cpu_percent"]):
        try:
            pid = proc.info["pid"]
            name = proc.info["name"] or "unknown"
            cpu = proc.cpu_percent(interval=0) or 0.0
            mem = _memory_mb(proc)
            if cpu < 0.5 and mem < 50:
                continue
            is_fg = foreground_pid is not None and pid == foreground_pid
            footprints.append(
                ProcessFootprint(
                    pid=pid,
                    name=name,
                    cpu_percent=cpu,
                    memory_mb=mem,
                    is_foreground=is_fg,
                    closability=_score_closability(name, is_fg, cpu, mem),
                )
            )
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return footprints


def _format_mb(mb: float) -> str:
    if mb >= 1024:
        return f"{mb / 1024:.1f} GB"
    return f"{mb:.0f} MB"


def _build_cpu_advice(usage: float, processes: list[ProcessFootprint]) -> ResourceAdvice | None:
    top = sorted(processes, key=lambda p: p.cpu_percent, reverse=True)[:3]
    if not top or top[0].cpu_percent < 5:
        return None

    main = top[0]
    headline = f"CPU {usage:.0f}% — {main.name} using {main.cpu_percent:.0f}%"
    if main.is_foreground:
        others = [p for p in top[1:] if p.closability > 0]
        if others:
            names = ", ".join(f"{p.name} ({p.cpu_percent:.0f}%)" for p in others[:2])
            suggestion = f"Background load: {names}. Close if not needed."
        else:
            suggestion = f"{main.name} is your active app. Close other heavy apps to help."
    else:
        closable = sorted(
            [p for p in processes if p.closability > 0],
            key=lambda p: p.closability,
            reverse=True,
        )[:2]
        if closable:
            names = ", ".join(f"{p.name} ({p.cpu_percent:.0f}%)" for p in closable)
            suggestion = f"Not in use? Close: {names}"
        else:
            suggestion = f"High CPU from {main.name}. Check Task Manager."

    return ResourceAdvice("CPU", usage, headline, suggestion, top)


def _build_ram_advice(usage: float, processes: list[ProcessFootprint]) -> ResourceAdvice | None:
    top = sorted(processes, key=lambda p: p.memory_mb, reverse=True)[:3]
    if not top or top[0].memory_mb < 200:
        return None

    main = top[0]
    headline = f"RAM {usage:.0f}% — {main.name} using {_format_mb(main.memory_mb)}"

    closable = sorted(
        [p for p in processes if p.closability > 0 and not p.is_foreground],
        key=lambda p: (p.closability, p.memory_mb),
        reverse=True,
    )[:3]

    if closable:
        names = ", ".join(f"{p.name} ({_format_mb(p.memory_mb)})" for p in closable)
        suggestion = f"Running in background — safe to close: {names}"
    elif main.is_foreground:
        others = [p for p in top[1:] if not p.is_foreground and p.memory_mb > 300]
        if others:
            names = ", ".join(f"{p.name} ({_format_mb(p.memory_mb)})" for p in others)
            suggestion = f"Also using RAM: {names}. Close tabs/apps you are not using."
        else:
            suggestion = "Close unused browser tabs or restart heavy apps."
    else:
        suggestion = f"Close {main.name} if you are not using it."

    return ResourceAdvice("RAM", usage, headline, suggestion, top)


class ResourceAdvisor:
    """Detect CPU/RAM pressure and suggest which background apps to close."""

    def __init__(self, store: AgentStore, config: dict[str, Any]) -> None:
        self.store = store
        cfg = config.get("resource_advisor", {})
        thresholds = config.get("thresholds", {})
        self.cpu_threshold = float(cfg.get("cpu_alert_percent", thresholds.get("cpu_alert_percent", 80)))
        self.ram_threshold = float(cfg.get("ram_alert_percent", thresholds.get("ram_alert_percent", 85)))
        self.cooldown = int(cfg.get("toast_cooldown_seconds", 300))
        self.enabled = cfg.get("enabled", True)

    def run(self) -> list[ResourceAdvice]:
        global _last_cpu_toast, _last_ram_toast
        if not self.enabled:
            return []

        fg_pid, fg_name = get_foreground_process()
        processes = _collect_processes(fg_pid)

        cpu_usage = psutil.cpu_percent(interval=0.5)
        mem = psutil.virtual_memory()
        ram_usage = mem.percent

        advice_list: list[ResourceAdvice] = []
        now = time.time()

        if cpu_usage >= self.cpu_threshold and (now - _last_cpu_toast) >= self.cooldown:
            advice = _build_cpu_advice(cpu_usage, processes)
            if advice:
                advice_list.append(advice)
                _last_cpu_toast = now
                self._log_advice(advice)

        if ram_usage >= self.ram_threshold and (now - _last_ram_toast) >= self.cooldown:
            advice = _build_ram_advice(ram_usage, processes)
            if advice:
                advice_list.append(advice)
                _last_ram_toast = now
                self._log_advice(advice)

        return advice_list

    def _log_advice(self, advice: ResourceAdvice) -> None:
        full = f"{advice.headline}. {advice.suggestion}"
        self.store.log_event(
            "resource_advisor",
            "WARNING",
            full,
            {
                "resource": advice.resource,
                "usage": advice.usage_percent,
                "offenders": [
                    {"name": p.name, "cpu": p.cpu_percent, "mem_mb": p.memory_mb}
                    for p in advice.offenders
                ],
            },
        )
        logger.warning("%s", full)


def _alive(procs: list[psutil.Process]) -> list[psutil.Process]:
    """Subset of procs still running (AccessDenied is treated as 'still there')."""
    out: list[psutil.Process] = []
    for p in procs:
        try:
            if p.is_running() and p.status() != psutil.STATUS_ZOMBIE:
                out.append(p)
        except psutil.NoSuchProcess:
            continue
        except psutil.AccessDenied:
            out.append(p)
    return out


def _post_wm_close(pids: set[int]) -> bool:
    """Best-effort graceful close: PostMessage WM_CLOSE to visible windows of pids.

    Needs pywin32; returns True if at least one WM_CLOSE was posted. This lets an
    app run its own 'save your work?' path instead of being terminated outright.
    """
    try:
        import win32con  # type: ignore
        import win32gui  # type: ignore
        import win32process  # type: ignore
    except Exception:
        return False

    posted = False

    def _cb(hwnd: int, _ctx: object) -> bool:
        nonlocal posted
        try:
            if not win32gui.IsWindowVisible(hwnd):
                return True
            _tid, wpid = win32process.GetWindowThreadProcessId(hwnd)
            if wpid in pids:
                win32gui.PostMessage(hwnd, win32con.WM_CLOSE, 0, 0)
                posted = True
        except Exception:
            pass
        return True

    try:
        win32gui.EnumWindows(_cb, None)
    except Exception:
        return posted
    return posted


def close_pids(
    pids: list[int],
    names: list[str] | None = None,
    *,
    force: bool = False,
    grace_seconds: float = 3.0,
) -> tuple[bool, str]:
    """Close an explicit process family (the PID set recorded at advice time).

    Safety contract (Master Architecture §1; audit C1):
    - Targets an explicit PID list — never a machine-wide exe-name glob — so
      closing one app cannot take down unrelated same-named processes.
    - Refuses if any *target* PID resolves to a SYSTEM_PROTECTED name.
    - Skips any child whose name is SYSTEM_PROTECTED (never kills a protected
      descendant that merely happens to hang under a target).
    - Graceful WM_CLOSE first; escalates to TerminateProcess ONLY when
      ``force=True`` (the GUI's explicit second confirm). Never a silent kill.

    Executed only via a registered CLOSE_PROCESS handler behind a USER_APPROVED
    Cortex Decision — there is no autonomous path here.
    """
    try:
        pid_list = [int(p) for p in (pids or [])]
    except (TypeError, ValueError):
        return False, "Malformed PID list"
    if not pid_list:
        return False, "No target PIDs"

    # Resolve targets; refuse outright if a target itself is protected.
    targets: list[psutil.Process] = []
    for pid in pid_list:
        try:
            proc = psutil.Process(pid)
            pname = (proc.name() or "").lower()
        except psutil.NoSuchProcess:
            continue
        except psutil.AccessDenied:
            return False, f"Refused: PID {pid} not accessible — run as Administrator"
        if pname in SYSTEM_PROTECTED:
            return False, f"Refused: PID {pid} ({pname}) is protected (system / DVielle)."
        targets.append(proc)

    if not targets:
        return True, "Already closed"

    # Expand to children, skipping protected descendants.
    ordered: list[psutil.Process] = []
    seen: set[int] = set()
    skipped: list[str] = []
    for proc in targets:
        try:
            for child in proc.children(recursive=True):
                try:
                    cname = (child.name() or "").lower()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    cname = ""
                if cname in SYSTEM_PROTECTED:
                    skipped.append(cname)
                    continue
                if child.pid not in seen:
                    ordered.append(child)
                    seen.add(child.pid)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
        if proc.pid not in seen:
            ordered.append(proc)
            seen.add(proc.pid)

    prot_note = f" (kept {len(skipped)} protected)" if skipped else ""

    # 1) Graceful WM_CLOSE — give the app a chance to save.
    posted = _post_wm_close(seen)
    if posted:
        try:
            psutil.wait_procs(ordered, timeout=grace_seconds)
        except Exception:
            pass

    remaining = _alive(ordered)
    if not remaining:
        return True, f"Closed gracefully — {len(seen)} process(es){prot_note}"

    if not force:
        why = (
            "graceful close needs pywin32; "
            if not posted
            else f"{len(remaining)} process(es) did not exit; "
        )
        return False, f"Not closed — {why}Force close to terminate (may lose unsaved work).{prot_note}"

    # 2) force=True — explicit second confirm: TerminateProcess.
    denied = 0
    for proc in remaining:
        try:
            proc.terminate()
        except psutil.NoSuchProcess:
            pass
        except psutil.AccessDenied:
            denied += 1
        except Exception:
            denied += 1
    try:
        psutil.wait_procs(remaining, timeout=4)
    except Exception:
        pass

    still = _alive(remaining)
    if not still:
        return True, f"Force-closed {len(seen)} process(es){prot_note}"
    hint = " — try Run as Administrator" if denied else ""
    return False, f"Could not fully close: {len(still)} still running{hint}{prot_note}"


def close_app_group(group: AppGroup, *, force: bool = False) -> tuple[bool, str]:
    """Close a smart app group by its recorded PID set (not a name glob).

    In the Mission Console this is reached only through PolicyGate + a
    USER_APPROVED CLOSE_PROCESS Decision; it stays PID-scoped and protected-safe
    for any direct caller. ``force=True`` escalates to TerminateProcess.
    """
    ok, msg = close_pids(group.pids, group.process_names, force=force)
    prefix = "Closed" if ok else "Close incomplete"
    return ok, f"{prefix} {group.display_name}: {msg}"

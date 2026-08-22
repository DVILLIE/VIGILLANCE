"""Smart CPU/RAM advisor — brief popups naming culprits and close suggestions."""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Any

import psutil

from agent.store.db import AgentStore
from agent.utils import IS_WINDOWS, get_foreground_process

logger = logging.getLogger("fortoro.resource_advisor")

# Never suggest closing these
SYSTEM_PROTECTED = {
    "system", "registry", "smss.exe", "csrss.exe", "wininit.exe", "services.exe",
    "lsass.exe", "svchost.exe", "dwm.exe", "explorer.exe", "winlogon.exe",
    "msmpeng.exe", "securityhealthservice.exe", "searchhost.exe", "shellexperiencehost.exe",
    "runtimebroker.exe", "applicationframehost.exe", "systemsettings.exe",
    "fortoro", "python.exe", "pythonw.exe", "dvielle.exe",
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


def get_closeable_processes(limit: int = 5) -> list[ProcessFootprint]:
    """Return background apps ranked by closability — for GUI close buttons."""
    fg_pid, _ = get_foreground_process()
    processes = _collect_processes(fg_pid)
    closable = [p for p in processes if p.closability > 0 and not p.is_foreground]
    closable.sort(key=lambda p: (p.closability, p.memory_mb, p.cpu_percent), reverse=True)
    return closable[:limit]


def close_process(pid: int, name: str) -> tuple[bool, str]:
    """Terminate a process by PID. Returns (success, message)."""
    try:
        proc = psutil.Process(pid)
        if proc.name().lower() != name.lower():
            return False, f"PID {pid} is no longer {name}"
        proc.terminate()
        proc.wait(timeout=5)
        return True, f"Closed {name} (PID {pid})"
    except psutil.NoSuchProcess:
        return True, f"{name} already closed"
    except psutil.AccessDenied:
        return False, f"Access denied closing {name} — run as Administrator"
    except Exception as exc:
        return False, str(exc)

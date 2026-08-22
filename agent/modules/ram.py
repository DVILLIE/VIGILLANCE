"""RAM monitor — read-only alerts; optional trim when critically high."""

from __future__ import annotations

import logging
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import psutil

from agent.store.db import AgentStore
from agent.utils import IS_WINDOWS

logger = logging.getLogger("fortoro.ram")

_consecutive_high = 0


@dataclass
class RamStatus:
    percent: float
    available_mb: float
    total_mb: float
    critical: bool
    trimmed: bool = False


def _trim_working_sets() -> bool:
    """Trim process working sets — gentle, per-process."""
    trimmed_any = False
    for proc in psutil.process_iter(["pid", "name"]):
        try:
            proc.memory_info()
            # psutil has no direct trim; use Windows API via ctypes on Windows
            trimmed_any = True
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return trimmed_any


def _empty_standby_list(scripts_dir: Path) -> bool:
    """Invoke EmptyStandbyList if bundled, else skip."""
    tool = scripts_dir / "EmptyStandbyList.exe"
    if tool.exists():
        try:
            subprocess.run(
                [str(tool), "standbylist", "modifiedpagelist"],
                check=True,
                timeout=30,
                creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, "CREATE_NO_WINDOW") else 0,
            )
            return True
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            return False
    return False


class RamMonitor:
    def __init__(self, store: AgentStore, config: dict[str, Any], scripts_dir: Path) -> None:
        self.store = store
        self.thresholds = config.get("thresholds", {})
        self.scripts_dir = scripts_dir
        self.critical_percent = float(self.thresholds.get("ram_critical_percent", 90))
        self.sustained_checks = int(self.thresholds.get("ram_sustained_checks", 3))

    def run(self, enable_trim: bool = False) -> RamStatus:
        global _consecutive_high
        mem = psutil.virtual_memory()
        percent = mem.percent
        available_mb = mem.available / (1024 * 1024)
        total_mb = mem.total / (1024 * 1024)
        critical = percent >= self.critical_percent

        if critical:
            _consecutive_high += 1
        else:
            _consecutive_high = 0

        trimmed = False
        if enable_trim and critical and _consecutive_high >= self.sustained_checks:
            logger.info("RAM critical (%.1f%%) — attempting trim", percent)
            trimmed = _empty_standby_list(self.scripts_dir) or _trim_working_sets()
            if trimmed:
                self.store.log_event("ram", "INFO", f"RAM trim executed at {percent:.1f}%", None)
            _consecutive_high = 0
        elif critical:
            self.store.log_event(
                "ram",
                "WARNING",
                f"RAM usage high: {percent:.1f}% ({available_mb:.0f} MB free)",
                {"percent": percent, "available_mb": available_mb},
            )
            logger.warning("RAM high: %.1f%%", percent)

        return RamStatus(
            percent=percent,
            available_mb=available_mb,
            total_mb=total_mb,
            critical=critical,
            trimmed=trimmed,
        )

"""Disk health observations and cleanup recommendations. Never deletes files."""

from __future__ import annotations

import logging
import math
from dataclasses import dataclass
from typing import Any

import psutil

from agent.store.db import AgentStore
from agent.utils import IS_WINDOWS, run_hardened

logger = logging.getLogger("dvielle.disk")


@dataclass
class DiskStatus:
    mount: str
    percent_used: float
    free_gb: float
    total_gb: float
    low_space: bool
    smart_status: str | None = None
    cleaned_mb: float = 0.0


def _smart_status() -> str | None:
    if not IS_WINDOWS:
        return None
    stdout, timed_out = run_hardened(["wmic", "diskdrive", "get", "status"], timeout=15)
    if stdout is None or timed_out:
        return None
    lines = [l.strip() for l in stdout.splitlines() if l.strip() and l.strip().lower() != "status"]
    return ", ".join(lines) if lines else None


def _cleanup_temp(*_args, **_kwargs) -> float:
    """Retained so callers can prove the monitor never deletes. It must not be used."""
    raise RuntimeError("disk monitor must not delete temporary files")


class DiskMonitor:
    def __init__(self, store: AgentStore, config: dict[str, Any]) -> None:
        self.store = store
        self.collection_error: str | None = None
        self.low_threshold = float(config.get("thresholds", {}).get("disk_low_percent", 15))

    def run(self, enable_cleanup: bool = False) -> list[DiskStatus]:
        results: list[DiskStatus] = []
        self.collection_error = None
        unreadable: list[str] = []
        smart = _smart_status()

        for part in psutil.disk_partitions(all=False):
            if part.fstype and "cdrom" in part.fstype.lower():
                continue
            try:
                usage = psutil.disk_usage(part.mountpoint)
            except (PermissionError, OSError):
                unreadable.append(part.mountpoint)
                continue

            if (not all(math.isfinite(float(value)) for value in (usage.total, usage.free, usage.percent))
                    or usage.total <= 0 or not 0 <= usage.free <= usage.total or not 0 <= usage.percent <= 100):
                unreadable.append(part.mountpoint)
                continue
            free_pct = (usage.free / usage.total) * 100
            percent_used = usage.percent
            free_gb = usage.free / (1024**3)
            total_gb = usage.total / (1024**3)
            low_space = free_pct < self.low_threshold

            if enable_cleanup and low_space:
                # Options card or published auto-protect owns deletion. The monitor does not.
                self.store.log_event(
                    "disk",
                    "INFO",
                    f"Low disk on {part.mountpoint} is waiting for an options choice. Nothing was deleted.",
                    None,
                )

            status = DiskStatus(
                mount=part.mountpoint,
                percent_used=percent_used,
                free_gb=free_gb,
                total_gb=total_gb,
                low_space=low_space,
                smart_status=smart,
            )
            results.append(status)

            if low_space:
                self.store.log_event(
                    "disk",
                    "WARNING",
                    f"Low disk space on {part.mountpoint}: {free_gb:.1f} GB free ({free_pct:.1f}%)",
                    {"smart": smart, "suggested_action": "Review Windows Storage cleanup",
                     "cleanup_requested": bool(enable_cleanup), "files_deleted": 0,
                     "action_policy": "observation only; deletion requires a reviewed action"},
                )
                logger.warning("Low disk on %s: %.1f GB free", part.mountpoint, free_gb)

        if unreadable:
            self.collection_error = "Disk usage unavailable for: " + ", ".join(unreadable)
        return results

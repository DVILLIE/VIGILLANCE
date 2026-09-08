"""Disk health monitor — space, SMART status, optional safe cleanup."""

from __future__ import annotations

import logging
import os
import shutil
from dataclasses import dataclass
from pathlib import Path
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
    stdout, _ = run_hardened(["wmic", "diskdrive", "get", "status"], timeout=15)
    if stdout is None:
        return None
    lines = [l.strip() for l in stdout.splitlines() if l.strip() and l.strip().lower() != "status"]
    return ", ".join(lines) if lines else None


def _safe_cleanup_paths() -> list[Path]:
    paths: list[Path] = []
    temp = os.environ.get("TEMP") or os.environ.get("TMP")
    if temp:
        paths.append(Path(temp))
    if IS_WINDOWS:
        paths.append(Path("C:/Windows/Temp"))
    return [p for p in paths if p.exists()]


def _cleanup_temp(max_age_days: int = 7) -> float:
    """Remove temp files older than max_age_days. Returns MB freed (estimate)."""
    import time

    freed = 0
    cutoff = time.time() - (max_age_days * 86400)
    for base in _safe_cleanup_paths():
        for root, dirs, files in os.walk(base, topdown=False):
            for name in files:
                fp = Path(root) / name
                try:
                    if fp.stat().st_mtime < cutoff:
                        size = fp.stat().st_size
                        fp.unlink()
                        freed += size
                except OSError:
                    continue
            for name in dirs:
                dp = Path(root) / name
                try:
                    dp.rmdir()
                except OSError:
                    continue
    return freed / (1024 * 1024)


class DiskMonitor:
    def __init__(self, store: AgentStore, config: dict[str, Any]) -> None:
        self.store = store
        self.low_threshold = float(config.get("thresholds", {}).get("disk_low_percent", 15))

    def run(self, enable_cleanup: bool = False) -> list[DiskStatus]:
        results: list[DiskStatus] = []
        smart = _smart_status()

        for part in psutil.disk_partitions(all=False):
            if part.fstype and "cdrom" in part.fstype.lower():
                continue
            try:
                usage = psutil.disk_usage(part.mountpoint)
            except (PermissionError, OSError):
                continue

            free_pct = (usage.free / usage.total) * 100 if usage.total else 0
            percent_used = usage.percent
            free_gb = usage.free / (1024**3)
            total_gb = usage.total / (1024**3)
            low_space = free_pct < self.low_threshold

            cleaned_mb = 0.0
            if enable_cleanup and low_space:
                cleaned_mb = _cleanup_temp()
                if cleaned_mb > 0:
                    self.store.log_event(
                        "disk",
                        "INFO",
                        f"Cleaned {cleaned_mb:.1f} MB temp on {part.mountpoint}",
                        None,
                    )

            status = DiskStatus(
                mount=part.mountpoint,
                percent_used=percent_used,
                free_gb=free_gb,
                total_gb=total_gb,
                low_space=low_space,
                smart_status=smart,
                cleaned_mb=cleaned_mb,
            )
            results.append(status)

            if low_space:
                self.store.log_event(
                    "disk",
                    "WARNING",
                    f"Low disk space on {part.mountpoint}: {free_gb:.1f} GB free ({free_pct:.1f}%)",
                    {"smart": smart},
                )
                logger.warning("Low disk on %s: %.1f GB free", part.mountpoint, free_gb)

        return results

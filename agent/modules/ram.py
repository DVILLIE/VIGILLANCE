"""RAM monitor — observe pressure signals; automatic trim DISABLED (P0.1).

Microsoft Learn: EmptyWorkingSet is useful primarily for testing and tuning
(Working Set Information). Working set is a momentary measurement (WPA Reference Set).
Product path = pressure analysis, not EmptyWorkingSet / EmptyStandbyList automation.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import psutil

from agent.policy import ActionKind, Authorization, PolicyCortex
from agent.policy.levels import LEVEL_RECOMMEND
from agent.store.db import AgentStore
from agent.win_memory import sample_memory

logger = logging.getLogger("dvielle.ram")

_consecutive_high = 0
# Transition dedup: recommend once per pressure episode (healthy->pressured),
# not every pulse while memory stays under pressure.
_ram_pressure_active = False

# Hard product rule — automatic RAM "optimization" is disabled.
AUTOMATIC_TRIM_ENABLED = False


@dataclass
class RamStatus:
    percent: float
    available_mb: float
    total_mb: float
    critical: bool
    trimmed: bool = False
    commit_percent: float | None = None
    pressure_note: str = ""


def _trim_working_sets() -> bool:
    """DEPRECATED — always False. Never report fake success."""
    logger.warning("EmptyWorkingSet path disabled (P0.1 — testing/tuning only, not product)")
    return False


def _empty_standby_list(scripts_dir: Path) -> bool:
    """DEPRECATED — automatic EmptyStandbyList disabled."""
    logger.warning("EmptyStandbyList path disabled (P0.1)")
    return False


class RamMonitor:
    def __init__(
        self,
        store: AgentStore,
        config: dict[str, Any],
        scripts_dir: Path,
        cortex: PolicyCortex | None = None,
    ) -> None:
        self.store = store
        self.thresholds = config.get("thresholds", {})
        self.scripts_dir = scripts_dir
        self.cortex = cortex
        self.critical_percent = float(self.thresholds.get("ram_critical_percent", 90))
        self.sustained_checks = int(self.thresholds.get("ram_sustained_checks", 3))

    def run(self, enable_trim: bool = False) -> RamStatus:
        global _consecutive_high, _ram_pressure_active
        mem = psutil.virtual_memory()
        snap = sample_memory()
        percent = mem.percent
        available_mb = mem.available / (1024 * 1024)
        total_mb = mem.total / (1024 * 1024)
        commit_pct = snap.commit_percent
        # Prefer commit + available over RAM% alone when available
        critical = percent >= self.critical_percent
        if commit_pct is not None and commit_pct >= 85:
            critical = True
        if available_mb < max(256.0, total_mb * 0.05):
            critical = True

        if critical:
            _consecutive_high += 1
        else:
            _consecutive_high = 0

        trimmed = False
        # P0.1: ignore enable_trim for automatic product path
        if enable_trim and AUTOMATIC_TRIM_ENABLED and critical and _consecutive_high >= self.sustained_checks:
            trimmed = _empty_standby_list(self.scripts_dir) or _trim_working_sets()
            _consecutive_high = 0
        elif enable_trim and not AUTOMATIC_TRIM_ENABLED:
            self.store.log_event(
                "ram",
                "INFO",
                "RAM trim requested but DISABLED by P0 policy (pressure analysis only)",
                {"percent": percent, "available_mb": available_mb, "commit_percent": commit_pct},
            )
            logger.info("Ignoring enable_ram_trim — automatic trim deprecated")
        elif critical:
            note = (
                f"Memory pressure signal: RAM {percent:.1f}% / "
                f"avail {available_mb:.0f} MB"
                + (f" / commit {commit_pct:.1f}%" if commit_pct is not None else "")
            )
            self.store.log_event(
                "ram",
                "WARNING",
                note,
                {
                    "percent": percent,
                    "available_mb": available_mb,
                    "commit_percent": commit_pct,
                    "source": snap.source,
                },
            )
            logger.warning("%s", note)

        # L2 recommendation once per pressure episode → durable WHY evidence.
        if critical and self.cortex is not None and not _ram_pressure_active:
            self.cortex.issue(
                action=ActionKind.RECOMMEND,
                action_level=LEVEL_RECOMMEND,
                confidence=0.8,
                evidence_summary=[
                    f"Memory pressure: {available_mb:.0f} MB available"
                    + (f", commit {commit_pct:.0f}%" if commit_pct is not None else "")
                    + f" (load {percent:.0f}%)",
                    "Level-2 recommendation — review heavy background apps; no automatic action",
                ],
                authorization=Authorization.AUTOMATIC_POLICY,
                target="memory_pressure",
                initiator="ram",
                reversible=False,
                policy_ref="memory_pressure",
                details={
                    "available_mb": round(available_mb, 1),
                    "commit_percent": commit_pct,
                    "load_percent": percent,
                    "source": snap.source,
                },
            )
        _ram_pressure_active = critical

        return RamStatus(
            percent=percent,
            available_mb=available_mb,
            total_mb=total_mb,
            critical=critical,
            trimmed=trimmed,
            commit_percent=commit_pct,
            pressure_note="observe_only",
        )

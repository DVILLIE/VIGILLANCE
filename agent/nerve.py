"""Adaptive Nerve Plane — per-collector cadence (Future Architecture authority).

Cadence is NOT a global full-scan timer. Each collector has its own interval.
FAST HEARTBEAT = cheap counters only (see agent.win_memory).
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable

logger = logging.getLogger("dvielle.nerve")


class Cadence(str, Enum):
    EVENT = "event"
    HEARTBEAT = "heartbeat"
    PULSE = "pulse"
    IDLE_DEEP = "idle_deep"
    EMERGENCY = "emergency"


@dataclass
class CollectorSpec:
    name: str
    cadence: Cadence
    interval_seconds: float
    enabled: bool = True
    run: Callable[[], None] | None = None
    last_run_monotonic: float = 0.0
    # Skip pulse/idle_deep when workload profile is MAXIMUM (AI/gaming)
    defer_under_maximum_workload: bool = False


@dataclass
class NervePlane:
    """Schedules collectors independently; sleep is the min remaining delay."""

    collectors: list[CollectorSpec] = field(default_factory=list)
    workload_maximum: bool = False
    emergency: bool = False

    def register(self, spec: CollectorSpec) -> None:
        self.collectors.append(spec)

    def due(self, now: float | None = None) -> list[CollectorSpec]:
        now = time.monotonic() if now is None else now
        due: list[CollectorSpec] = []
        for c in self.collectors:
            if not c.enabled or c.run is None:
                continue
            if c.cadence == Cadence.EVENT:
                continue  # event-driven elsewhere
            if (
                self.workload_maximum
                and c.defer_under_maximum_workload
                and c.cadence in (Cadence.PULSE, Cadence.IDLE_DEEP)
                and not self.emergency
            ):
                continue
            if c.cadence == Cadence.IDLE_DEEP and self.workload_maximum and not self.emergency:
                continue
            interval = c.interval_seconds
            if self.emergency and c.cadence in (Cadence.PULSE, Cadence.HEARTBEAT):
                interval = min(interval, 15.0)
            if now - c.last_run_monotonic >= interval:
                due.append(c)
        return due

    def run_due(self) -> list[str]:
        now = time.monotonic()
        ran: list[str] = []
        for c in self.due(now):
            t0 = time.perf_counter()
            try:
                assert c.run is not None
                c.run()
                c.last_run_monotonic = time.monotonic()
                ran.append(c.name)
                ms = (time.perf_counter() - t0) * 1000
                logger.debug("nerve %s (%s) %.1fms", c.name, c.cadence.value, ms)
            except Exception:
                c.last_run_monotonic = time.monotonic()
                logger.exception("nerve collector failed: %s", c.name)
        return ran

    def sleep_seconds(self, default: float = 2.0) -> float:
        """How long until the next collector is due (bounded)."""
        now = time.monotonic()
        waits: list[float] = []
        for c in self.collectors:
            if not c.enabled or c.run is None or c.cadence == Cadence.EVENT:
                continue
            if (
                self.workload_maximum
                and c.defer_under_maximum_workload
                and c.cadence in (Cadence.PULSE, Cadence.IDLE_DEEP)
                and not self.emergency
            ):
                continue
            remaining = c.interval_seconds - (now - c.last_run_monotonic)
            waits.append(max(0.05, remaining))
        if not waits:
            return default
        return min(default, min(waits))


def default_intervals(config: dict) -> dict[str, float]:
    """Config overrides; defaults match Adaptive Nerve spirit (not 2–5s full scan)."""
    nerve = config.get("nerve", {})
    pulse = float(config.get("agent", {}).get("interval_seconds", 60))
    return {
        "heartbeat": float(nerve.get("heartbeat_seconds", 5)),
        "pulse": float(nerve.get("pulse_seconds", pulse)),
        "idle_deep": float(nerve.get("idle_deep_seconds", 900)),
    }

"""Independent cadence, bounded workers, workload deferral, and retry backoff."""
from __future__ import annotations

import logging
import math
import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable

logger = logging.getLogger('dvielle.nerve')

# Pressure-response collectors (resource_advisor) stay eligible while the host is
# under memory or CPU pressure. They cannot run faster than this floor, they must
# stay on a background worker, and they still defer when the agent's own budget
# is exceeded so they cannot starve heartbeat or security collection.
PRESSURE_RESPONSE_MIN_SECONDS = 30.0


class CollectionIncomplete(RuntimeError):
    """Successful bounded observation with a coverage gap; no failure backoff."""


class Cadence(str, Enum):
    EVENT = 'event'
    HEARTBEAT = 'heartbeat'
    PULSE = 'pulse'
    IDLE_DEEP = 'idle_deep'
    EMERGENCY = 'emergency'


@dataclass
class CollectorSpec:
    name: str
    cadence: Cadence
    interval_seconds: float
    enabled: bool = True
    run: Callable[[], None] | None = None
    last_run_monotonic: float = 0.0
    defer_under_maximum_workload: bool = False
    pressure_response: bool = False
    background: bool = False
    critical: bool = False
    failures: int = 0
    running: bool = False
    status: str = 'pending'
    error: str | None = None
    duration_ms: float | None = None


@dataclass
class NervePlane:
    collectors: list[CollectorSpec] = field(default_factory=list)
    workload_maximum: bool = False
    emergency: bool = False
    idle: bool = True
    budget_exceeded: bool = False
    max_workers: int = 2
    on_status: Callable[[CollectorSpec], None] | None = None
    _lock: threading.RLock = field(default_factory=threading.RLock, repr=False)
    _threads: set[threading.Thread] = field(default_factory=set, repr=False)
    _optional_running: int = 0
    _closing: bool = False

    def register(self, spec: CollectorSpec) -> None:
        if not math.isfinite(spec.interval_seconds) or spec.interval_seconds <= 0:
            raise ValueError('collector intervals must be finite and positive')
        if spec.pressure_response and (not spec.background or spec.critical):
            raise ValueError('pressure-response collectors must be background and non-critical')
        if any(c.name == spec.name for c in self.collectors):
            raise ValueError(f'duplicate collector {spec.name}')
        self.collectors.append(spec)

    def _deferred(self, c: CollectorSpec) -> bool:
        if c.critical or c.cadence == Cadence.HEARTBEAT:
            return False
        if c.cadence == Cadence.IDLE_DEEP and (not self.idle or self.workload_maximum):
            return True
        if c.pressure_response:
            # Host pressure is why this collector exists. The agent's own budget
            # still defers it so a pressure episode cannot occupy the runtime.
            return self.budget_exceeded
        return self.budget_exceeded or (self.workload_maximum and c.defer_under_maximum_workload)

    def _interval(self, c: CollectorSpec) -> float:
        base = c.interval_seconds
        if c.pressure_response:
            base = max(base, PRESSURE_RESPONSE_MIN_SECONDS)
        return min(base * (2 ** min(c.failures, 4)), max(base, 900))

    def _deadline_reached(self, c: CollectorSpec, now: float) -> bool:
        """A never-run collector is due immediately. After a run, it is due at
        ``last_run + interval`` (base cadence, or failure backoff).

        Compare that deadline to ``now``. ``now - last >= interval`` is not the
        same test: for some binary64 readings, ``(last + interval) - last`` is
        just under ``interval``. Windows CI run 36599565020 hit this at
        ``last_run_monotonic == 228.703`` with a 30s pulse
        (``(228.703 + 30) - 228.703 == 29.99999999999997``). A partial
        collection clears ``failures`` before this check, so a coverage gap
        stays on the base cadence.
        """
        if c.last_run_monotonic == 0:
            return True
        return now >= c.last_run_monotonic + self._interval(c)

    def due(self, now: float | None = None) -> list[CollectorSpec]:
        now = time.monotonic() if now is None else now
        with self._lock:
            if self._closing:
                return []
            return [c for c in self.collectors if c.enabled and c.run is not None
                    and not c.running and c.cadence != Cadence.EVENT
                    and not self._deferred(c)
                    and self._deadline_reached(c, now)]

    def _notify(self, c: CollectorSpec) -> None:
        if self.on_status:
            try:
                self.on_status(c)
            except Exception:
                logger.exception('collector status publication failed')

    def _execute(self, c: CollectorSpec) -> None:
        t0 = time.perf_counter()
        try:
            c.run()
        except CollectionIncomplete as exc:
            with self._lock:
                c.failures, c.status, c.error = 0, 'partial', str(exc)[:300]
            logger.warning('collector partial: %s: %s', c.name, exc)
        except Exception as exc:
            with self._lock:
                c.failures += 1
                c.status, c.error = 'error', f'{type(exc).__name__}: {exc}'[:300]
            logger.exception('collector failed: %s', c.name)
        else:
            with self._lock:
                c.failures, c.status, c.error = 0, 'ok', None
        finally:
            with self._lock:
                c.duration_ms = (time.perf_counter() - t0) * 1000
                c.last_run_monotonic = time.monotonic()
                c.running = False
                if c.background and not c.critical:
                    self._optional_running = max(0, self._optional_running - 1)
                self._threads.discard(threading.current_thread())
            self._notify(c)

    def run_due(self) -> list[str]:
        ran = []
        # Refresh heartbeat before re-evaluating workload gates in the same turn.
        ordered = sorted(self.collectors, key=lambda c: (c.cadence != Cadence.HEARTBEAT, not c.critical))
        for c in ordered:
            inline = False
            with self._lock:
                if c not in self.due():
                    if not c.running and c.enabled and self._deferred(c) and c.status != 'deferred':
                        c.status = 'deferred'
                        self._notify(c)
                    continue
                if c.background and len(self._threads) >= self.max_workers:
                    continue
                # Reserve one worker for security when optional I/O stalls.
                if c.background and not c.critical and self._optional_running >= max(1, self.max_workers - 1):
                    continue
                c.running, c.status = True, 'running'
                self._notify(c)
                if c.background:
                    if not c.critical:
                        self._optional_running += 1
                    thread = threading.Thread(target=self._execute, args=(c,), daemon=True,
                                              name=f'dv-{c.name}')
                    self._threads.add(thread)
                    thread.start()
                else:
                    inline = True
            # Do not hold the scheduler lock during an inline callback.
            if inline:
                self._execute(c)
            ran.append(c.name)
        return ran

    def sleep_seconds(self, default: float = 1.0) -> float:
        now = time.monotonic()
        with self._lock:
            waits = [max(0.1, (c.last_run_monotonic + self._interval(c)) - now)
                     for c in self.collectors if c.enabled and c.run and not c.running
                     and c.cadence != Cadence.EVENT and not self._deferred(c)]
        return min(default, min(waits)) if waits else default

    def close(self, timeout: float = 60.0) -> bool:
        """Lease must remain held until in-flight observations have drained."""
        with self._lock:
            self._closing = True
            threads = list(self._threads)
        end = time.monotonic() + timeout
        for thread in threads:
            thread.join(max(0, end - time.monotonic()))
        with self._lock:
            return not self._threads


def default_intervals(config: dict) -> dict[str, float]:
    cfg = config.get('nerve', {})
    values = {
        'heartbeat': float(cfg.get('heartbeat_seconds', 5)),
        'pulse': float(cfg.get('pulse_seconds', config.get('agent', {}).get('interval_seconds', 60))),
        'idle_deep': float(cfg.get('idle_deep_seconds', 900)),
    }
    if any(not math.isfinite(v) or v <= 0 for v in values.values()):
        raise ValueError('nerve intervals must be finite and positive')
    values['heartbeat'] = max(1.0, values['heartbeat'])
    values['pulse'] = max(10.0, values['pulse'])
    values['idle_deep'] = max(60.0, values['idle_deep'])
    return values

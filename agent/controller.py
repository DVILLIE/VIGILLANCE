"""Background controller for the Mission Console.

Drives the SAME adaptive nerve loop as the headless agent (via build_runtime),
so the Console runs real heartbeat/pulse/idle_deep cadence with the Digital Twin
populated — no divergent fixed-interval loop. Exposes the twin for the UI to read.
"""

from __future__ import annotations

import logging
import queue
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from agent.runtime import build_runtime
from agent.store.db import AgentStore
from agent.twin import TwinStore

logger = logging.getLogger("dvielle")


@dataclass
class AgentStatus:
    running: bool = False
    cycle_count: int = 0
    last_cycle: datetime | None = None
    monitor_only: bool = True
    message: str = "Standby"


class AgentController:
    """Runs the shared nerve loop in a background thread with clean start/stop."""

    def __init__(
        self,
        config_dir: Path | None = None,
        on_cycle: Callable[[AgentStatus], None] | None = None,
        on_event: Callable[[str, str, str], None] | None = None,
    ) -> None:
        self.config_dir = config_dir
        self.on_cycle = on_cycle
        self.on_event = on_event
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self.status = AgentStatus()
        self._store: AgentStore | None = None
        self._twin: TwinStore | None = None
        self._event_queue: queue.Queue[tuple[str, str, str]] = queue.Queue()

    @property
    def store(self) -> AgentStore | None:
        return self._store

    @property
    def twin(self) -> TwinStore | None:
        return self._twin

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, name="DVielle-Agent", daemon=True)
        self._thread.start()
        self.status.running = True
        self.status.message = "Vigilance active"

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=15)
        self.status.running = False
        self.status.message = "Standby"

    def _after_pulse(self) -> None:
        """Called (on the nerve thread) at the end of each pulse."""
        self.status.cycle_count += 1
        self.status.last_cycle = datetime.now(timezone.utc)
        if self.on_cycle:
            self.on_cycle(self.status)

    def _loop(self) -> None:
        rt = build_runtime(config_dir=self.config_dir, on_pulse=self._after_pulse)
        self._store = rt.store
        self._twin = rt.twin
        self.status.monitor_only = rt.config.get("modes", {}).get("monitor_only", True)
        logger.info("DVielle vigilance loop started (shared runtime; PolicyGate fail-closed)")

        rt.prime()  # heartbeat once so the twin has memory/self-budget immediately
        while not self._stop.is_set():
            try:
                rt.tick()
            except Exception:
                logger.exception("Nerve tick failed")
            self._stop.wait(rt.sleep_hint())

        logger.info("DVielle vigilance loop stopped")

    def recent_events(self, limit: int = 30) -> list[dict[str, Any]]:
        if not self._store:
            return []
        with self._store._conn() as conn:
            rows = conn.execute(
                "SELECT ts, module, severity, message FROM events ORDER BY id DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [dict(r) for r in rows]

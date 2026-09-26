"""Attach a console to the existing agent, or acquire ownership when none exists."""
from __future__ import annotations

import logging
import math
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from agent.ownership import RuntimeAlreadyRunning, RuntimeIntentionallyStopped
from agent.ownership import read_json
from agent.runtime import build_runtime, load_runtime_config, _resolve_data_dir
from agent.store.db import AgentStore
from agent.twin import TwinStore

logger = logging.getLogger('dvielle')


@dataclass
class AgentStatus:
    running: bool = False
    cycle_count: int = 0
    last_cycle: datetime | None = None
    monitor_only: bool = True
    message: str = 'Standby'
    ownership: str = 'stopped'
    error: str | None = None


class AgentController:
    def __init__(self, config_dir: Path | None = None,
                 on_cycle: Callable[[AgentStatus], None] | None = None,
                 on_event: Callable[[str, str, str], None] | None = None):
        self.config_dir, self.on_cycle, self.on_event = config_dir, on_cycle, on_event
        self.status = AgentStatus()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._store: AgentStore | None = None
        self._twin: TwinStore | None = None
        self._runtime = None

    @property
    def store(self):
        return self._store

    @property
    def twin(self):
        return self._twin

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self.status = AgentStatus(ownership='starting', message='Connecting to monitoring owner')
        self._thread = threading.Thread(target=self._loop, name='DVielle-Controller', daemon=True)
        self._thread.start()

    def stop(self) -> None:
        # Never block Tk for a collector timeout or terminate another owner.
        self._stop.set()
        self.status.message = 'Disconnecting console' if self.status.ownership == 'attached' else 'Stopping collectors'
        if self._thread:
            self._thread.join(timeout=0.2)

    def _sync(self, *, attached: bool, fresh: bool = True) -> None:
        data = self._twin.as_dict() if self._twin else {}
        rt = data.get('runtime', {})
        previous = self.status.cycle_count
        heartbeat = rt.get('heartbeat_at')
        try:
            interval = float(data.get('collectors', {}).get('heartbeat', {}).get('interval_seconds', 5))
            if not math.isfinite(interval) or interval <= 0:
                raise ValueError('Invalid heartbeat cadence')
            age = (datetime.now(timezone.utc) - datetime.fromisoformat(heartbeat)).total_seconds()
            fresh = fresh and 0 <= age < max(30, interval * 3)
        except (TypeError, ValueError):
            fresh = False
        self.status.ownership = 'attached' if attached else 'owner'
        self.status.running = fresh and rt.get('state') == 'running'
        self.status.error = None if fresh else 'Monitoring heartbeat unavailable or stale'
        try:
            self.status.cycle_count = max(0, int(rt.get('cycle_count', 0)))
        except (TypeError, ValueError, OverflowError):
            self.status.cycle_count = 0
            self.status.running = False
            self.status.error = 'Invalid monitoring snapshot'
        try:
            self.status.last_cycle = datetime.fromisoformat(rt['last_pulse_at'])
        except (KeyError, TypeError, ValueError):
            self.status.last_cycle = None
        self.status.message = ('Attached to background agent' if attached else 'Monitoring active') if self.status.running else self.status.error or rt.get('state', 'unknown')
        if self.on_cycle and previous != self.status.cycle_count:
            self.on_cycle(self.status)

    def _loop(self) -> None:
        rt = None
        try:
            config, _, _ = load_runtime_config(self.config_dir)
            data_dir = _resolve_data_dir(config)
            attached_token = None
            while not self._stop.is_set():
                if attached_token:
                    published = (read_json(data_dir / 'twin.json') or {}).get('runtime', {})
                    if isinstance(published, dict) and published.get('owner_token') == attached_token and published.get('state') in {'stopping', 'stopped'}:
                        break  # intentional shutdown: never race installer by taking over
                try:
                    rt = build_runtime(config_dir=self.config_dir, previous_owner_token=attached_token)
                except RuntimeIntentionallyStopped:
                    break
                except RuntimeAlreadyRunning:
                    if self._store is None and (data_dir / 'agent.db').exists():
                        # The owner may still be migrating an existing store.
                        self._store = AgentStore(data_dir / 'agent.db', initialize=False)
                    if self._twin is None:
                        self._twin = TwinStore()
                    fresh = self._twin.read_published(data_dir / 'twin.json')
                    attached_token = self._twin.as_dict().get('runtime', {}).get('owner_token')
                    self._sync(attached=True, fresh=fresh)
                    # Lock acquisition is retried after a crash, without a second owner.
                    self._stop.wait(2)
                    continue
                self._runtime, self._store, self._twin = rt, rt.store, rt.twin
                rt.prime()
                self._sync(attached=False)
                while not self._stop.is_set() and not rt.stop_requested():
                    rt.tick()
                    self._sync(attached=False)
                    self._stop.wait(rt.sleep_hint())
                break
        except Exception as exc:
            logger.exception('Monitoring controller failed')
            self.status.ownership = 'error'
            self.status.error = f'{type(exc).__name__}: {exc}'
            self.status.message = self.status.error
        finally:
            if rt is not None:
                # Keep the lease held while background collectors drain.
                while not rt.close(timeout=1):
                    self.status.message = 'Waiting for in-flight collectors to stop'
            self.status.running = False
            if self.status.ownership != 'error':
                self.status.ownership, self.status.message = 'stopped', 'Monitoring stopped or console detached'
            self._runtime = None

    def recent_events(self, limit: int = 30) -> list[dict[str, Any]]:
        if not self._store:
            return []
        return [dict(row) for row in self._store.recent_events(limit=limit)]

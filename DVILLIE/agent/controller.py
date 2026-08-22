"""Background agent controller for GUI integration."""

from __future__ import annotations

import logging
import queue
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable

from agent.main import run_once
from agent.store.db import AgentStore
from agent.utils import (
    DEFAULT_DATA_DIR,
    INSTALL_ROOT,
    PROJECT_ROOT,
    load_yaml,
    resolve_config_paths,
    set_process_priority,
    setup_logging,
)


@dataclass
class AgentStatus:
    running: bool = False
    cycle_count: int = 0
    last_cycle: datetime | None = None
    monitor_only: bool = True
    message: str = "Standby"


class AgentController:
    """Runs the monitor loop in a background thread with clean start/stop."""

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
        self._event_queue: queue.Queue[tuple[str, str, str]] = queue.Queue()

    @property
    def store(self) -> AgentStore | None:
        return self._store

    def _resolve_paths(self) -> tuple[Path, Path, Path, Path]:
        data_dir = DEFAULT_DATA_DIR
        if self.config_dir:
            config_path = self.config_dir / "config.yaml"
            whitelist_path = self.config_dir / "whitelists.yaml"
            telemetry_path = self.config_dir / "telemetry-domains.txt"
        else:
            config_path, whitelist_path, telemetry_path = resolve_config_paths(data_dir)
        config = load_yaml(config_path)
        custom = config.get("agent", {}).get("data_dir")
        if custom:
            data_dir = Path(custom)
        return data_dir, config_path, whitelist_path, telemetry_path

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

    def _loop(self) -> None:
        data_dir, config_path, whitelist_path, telemetry_path = self._resolve_paths()
        data_dir.mkdir(parents=True, exist_ok=True)
        config = load_yaml(config_path)
        whitelists = load_yaml(whitelist_path)
        log_cfg = config.get("logging", {})
        setup_logging(
            data_dir,
            level=log_cfg.get("level", "INFO"),
            max_mb=int(log_cfg.get("max_file_mb", 10)),
            backup_count=int(log_cfg.get("backup_count", 3)),
        )
        interval = int(config.get("agent", {}).get("interval_seconds", 60))
        set_process_priority(config.get("agent", {}).get("process_priority", "below_normal"))
        self._store = AgentStore(data_dir / "agent.db")
        scripts_dir = INSTALL_ROOT / "scripts"
        modes = config.get("modes", {})
        modules = config.get("modules", {})

        logging.getLogger("dvielle").info("DVielle vigilance loop started")

        while not self._stop.is_set():
            try:
                run_once(
                    self._store,
                    config,
                    whitelists,
                    telemetry_path,
                    scripts_dir,
                    modes,
                    modules,
                )
                self.status.cycle_count += 1
                self.status.last_cycle = datetime.now(timezone.utc)
                self.status.monitor_only = modes.get("monitor_only", True)
                if self.on_cycle:
                    self.on_cycle(self.status)
            except Exception:
                logging.getLogger("dvielle").exception("Cycle failed")
            self._stop.wait(interval)

        logging.getLogger("dvielle").info("DVielle vigilance loop stopped")

    def recent_events(self, limit: int = 30) -> list[dict[str, Any]]:
        if not self._store:
            data_dir, _, _, _ = self._resolve_paths()
            self._store = AgentStore(data_dir / "agent.db")
        with self._store._conn() as conn:
            rows = conn.execute(
                "SELECT ts, module, severity, message FROM events ORDER BY id DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [dict(r) for r in rows]

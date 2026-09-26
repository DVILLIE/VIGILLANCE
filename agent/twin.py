"""Shared measured state, atomic current snapshot, and bounded optional history."""

from __future__ import annotations

import json
import threading
from copy import deepcopy
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from agent.capability import CapabilityReport
from agent.win_memory import MemorySnapshot, sample_memory
from agent.ownership import atomic_json, read_json


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class SelfBudget:
    rss_bytes: int | None = None
    cpu_percent: float | None = None
    last_cycle_ms: float | None = None
    collectors_ran: list[str] = field(default_factory=list)
    exceeded: bool = False
    reason: str = "not sampled"
    cpu_limit_percent: float | None = None
    rss_limit_mb: float | None = None


@dataclass
class DigitalTwin:
    updated_at: str = ""
    capability: dict[str, Any] = field(default_factory=dict)
    hardware: dict[str, Any] = field(default_factory=dict)
    memory: dict[str, Any] = field(default_factory=dict)
    system: dict[str, Any] = field(default_factory=dict)  # system cpu%/disk — live vitals for the console
    workload: dict[str, Any] = field(default_factory=dict)
    network: dict[str, Any] = field(default_factory=dict)
    privacy: dict[str, Any] = field(default_factory=dict)
    security: dict[str, Any] = field(default_factory=dict)
    self_budget: dict[str, Any] = field(default_factory=dict)
    collectors: dict[str, Any] = field(default_factory=dict)
    runtime: dict[str, Any] = field(default_factory=dict)
    vision: str = "UNKNOWN"  # AVAILABLE | LIMITED | UNKNOWN | UNAVAILABLE
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class TwinStore:
    """Thread-safe in-memory twin + optional jsonl append."""

    def __init__(self, snapshot_path: Path | None = None, *, latest_path: Path | None = None,
                 max_snapshot_bytes: int = 5_000_000) -> None:
        self._lock = threading.RLock()
        self._twin = DigitalTwin(updated_at=_utc_now())
        self._snapshot_path = snapshot_path
        self._latest_path = latest_path
        self._max_snapshot_bytes = max(1024, max_snapshot_bytes)

    @property
    def twin(self) -> DigitalTwin:
        with self._lock:
            return deepcopy(self._twin)

    def as_dict(self) -> dict[str, Any]:
        """Thread-safe deep copy for readers on other threads (e.g. the GUI)."""
        with self._lock:
            return self._twin.to_dict()

    def set_capability(self, report: CapabilityReport) -> None:
        with self._lock:
            self._twin.capability = report.to_dict()
            self._twin.vision = report.overall_vision
            self._twin.hardware = {
                "ram_total_gb": report.ram_total_gb,
                "cpu_count": report.cpu_count,
                "battery_present": report.battery_present,
                "os_caption": report.os_caption,
                "os_build": report.os_build,
                "edition_hint": report.edition_hint,
            }
            self._twin.notes = list(report.notes)
            self._twin.updated_at = _utc_now()

    def update_memory(self, snap: MemorySnapshot | None = None) -> MemorySnapshot:
        snap = snap or sample_memory()
        with self._lock:
            self._twin.memory = snap.to_dict()
            self._twin.updated_at = _utc_now()
        return snap

    def update_self_budget(self, budget: SelfBudget) -> None:
        with self._lock:
            self._twin.self_budget = asdict(budget)
            self._twin.updated_at = _utc_now()

    def patch(self, **sections: Any) -> None:
        with self._lock:
            for key, value in sections.items():
                if hasattr(self._twin, key) and isinstance(value, dict):
                    current = getattr(self._twin, key)
                    if isinstance(current, dict):
                        current.update(value)
                    else:
                        setattr(self._twin, key, value)
            self._twin.updated_at = _utc_now()

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            data = self._twin.to_dict()
            if self._snapshot_path:
                self._snapshot_path.parent.mkdir(parents=True, exist_ok=True)
                payload = json.dumps(data, ensure_ascii=False, allow_nan=False) + "\n"
                if self._snapshot_path.exists() and self._snapshot_path.stat().st_size + len(payload.encode()) > self._max_snapshot_bytes:
                    self._snapshot_path.replace(self._snapshot_path.with_suffix(".jsonl.1"))
                with self._snapshot_path.open("a", encoding="utf-8") as f:
                    f.write(payload)
        return data

    def publish(self) -> None:
        """Overwrite one compact current snapshot. History is separately bounded."""
        if self._latest_path:
            with self._lock:
                atomic_json(self._latest_path, self._twin.to_dict())

    def read_published(self, path: Path) -> bool:
        data = read_json(path)
        if data is None or not isinstance(data.get("runtime"), dict):
            return False
        allowed = DigitalTwin.__dataclass_fields__
        fields = {k: v for k, v in data.items() if k in allowed}
        # A malformed external file must not crash UI readers or claim liveness.
        for key in ("capability", "hardware", "memory", "system", "workload", "network",
                    "privacy", "security", "self_budget", "collectors", "runtime"):
            if key in fields and not isinstance(fields[key], dict):
                return False
        if not isinstance(fields.get("updated_at"), str):
            return False
        if any(not isinstance(value, dict) for value in fields.get("collectors", {}).values()):
            return False
        with self._lock:
            self._twin = DigitalTwin(**fields)
        return True

    def collector_status(self, name: str, **state: Any) -> None:
        with self._lock:
            current = self._twin.collectors.setdefault(name, {})
            current.update(state)

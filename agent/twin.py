"""Digital Twin v0 — canonical live machine state (not the GUI, not SQLite alone).

Engines read/write this model. Persistence is optional snapshots (twin.jsonl).
"""

from __future__ import annotations

import json
import threading
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from agent.capability import CapabilityReport
from agent.win_memory import MemorySnapshot, sample_memory


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class SelfBudget:
    rss_bytes: int | None = None
    cpu_percent: float | None = None
    last_cycle_ms: float | None = None
    collectors_ran: list[str] = field(default_factory=list)


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
    vision: str = "UNKNOWN"  # AVAILABLE | LIMITED | UNKNOWN | UNAVAILABLE
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class TwinStore:
    """Thread-safe in-memory twin + optional jsonl append."""

    def __init__(self, snapshot_path: Path | None = None) -> None:
        self._lock = threading.RLock()
        self._twin = DigitalTwin(updated_at=_utc_now())
        self._snapshot_path = snapshot_path

    @property
    def twin(self) -> DigitalTwin:
        with self._lock:
            return self._twin

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
            with self._snapshot_path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(data, ensure_ascii=False) + "\n")
        return data

"""Keep-on decisions under data/learn/. Update in place. Local only."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

DECISIONS = ("allow", "deny", "ask_always", "never_warn")
PILLAR_FILES = {
    "safety": "safety_allow.txt",
    "speed": "speed_allow.txt",
    "privacy": "privacy_allow.txt",
    "ai_data": "ai_allow.txt",
    "storage": "storage_allow.txt",
    "footprint": "footprint_allow.txt",
    "camera": "camera_allow.txt",
}
_HEADER = (
    "# DVielle keep-on decisions. Local only. Do not upload.\n"
    "# pillar|subject|decision|timestamp|notes\n"
)


@dataclass(frozen=True)
class KeepOnRecord:
    pillar: str
    subject: str
    decision: str
    updated: str
    notes: str = ""


def _atomic(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    os.replace(tmp, path)


class KeepOnMemory:
    def __init__(self, learn_dir: Path) -> None:
        self.learn_dir = learn_dir
        self.master = learn_dir / "keep_on.txt"
        self.records: dict[tuple[str, str], KeepOnRecord] = {}
        self.skipped_lines = 0
        self.load()

    def load(self) -> None:
        self.records.clear()
        self.skipped_lines = 0
        if not self.master.exists():
            return
        for raw in self.master.read_text(encoding="utf-8").splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split("|", 4)
            if len(parts) < 4 or parts[2] not in DECISIONS:
                self.skipped_lines += 1
                continue
            notes = parts[4] if len(parts) > 4 else ""
            self.records[(parts[0], parts[1])] = KeepOnRecord(
                parts[0], parts[1], parts[2], parts[3], notes
            )

    def get(self, pillar: str, subject: str) -> KeepOnRecord | None:
        return self.records.get((pillar, subject))

    def set(self, pillar: str, subject: str, decision: str, updated: str, notes: str = "") -> None:
        if decision not in DECISIONS:
            raise ValueError(f"unknown keep-on decision: {decision}")
        if not subject or "|" in subject or "\n" in subject:
            raise ValueError("subject identity must be one plain token")
        self.records[(pillar, subject)] = KeepOnRecord(
            pillar, subject, decision, updated, notes.replace("\n", " ").replace("|", "/")[:200]
        )
        self.save()

    def save(self) -> None:
        rows = sorted(self.records.values(), key=lambda row: (row.pillar, row.subject))
        body = "".join(
            f"{row.pillar}|{row.subject}|{row.decision}|{row.updated}|{row.notes}\n" for row in rows
        )
        _atomic(self.master, _HEADER + body)
        for pillar, filename in PILLAR_FILES.items():
            owned = [row for row in rows if row.pillar == pillar]
            owned_body = "".join(
                f"{row.pillar}|{row.subject}|{row.decision}|{row.updated}|{row.notes}\n" for row in owned
            )
            _atomic(self.learn_dir / filename, _HEADER + owned_body)


class SafetyBaseline:
    """Known startup paths. This is not a user allow."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.items: dict[str, str] = {}
        self.initialized = False
        self.load()

    def load(self) -> None:
        self.items.clear()
        if not self.path.exists():
            self.initialized = False
            return
        self.initialized = True
        for raw in self.path.read_text(encoding="utf-8").splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split("|", 2)
            if len(parts) >= 2:
                self.items[parts[0]] = parts[1]

    def seed(self, items: list[tuple[str, str]], updated: str) -> None:
        if self.initialized:
            return
        self.items = {subject: path for subject, path in items}
        self.initialized = True
        lines = ["# Known startup paths. Not a user allow.", "# subject|path|updated"]
        for subject, path in sorted(self.items.items()):
            lines.append(f"{subject}|{path}|{updated}")
        _atomic(self.path, "\n".join(lines) + "\n")

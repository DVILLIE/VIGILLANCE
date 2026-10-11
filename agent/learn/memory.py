"""Keep-on decisions under data/learn/. Update in place. Local only."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from agent.local_files import atomic_text, file_lock

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
    "# D\'Vielle keep-on decisions. Local only. Do not upload.\n"
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
    atomic_text(path, text)


class KeepOnMemory:
    def __init__(self, learn_dir: Path) -> None:
        self.learn_dir = learn_dir
        self.master = learn_dir / "keep_on.txt"
        self.records: dict[tuple[str, str], KeepOnRecord] = {}
        self.skipped_lines = 0
        self.mirror_errors: list[str] = []
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
        # The master is atomically replaced; refresh decisions made by another UI.
        with file_lock(self.learn_dir / ".keep_on.lock"):
            self.load()
            return self.records.get((pillar, subject))

    def set(self, pillar: str, subject: str, decision: str, updated: str, notes: str = "") -> None:
        if decision not in DECISIONS:
            raise ValueError(f"unknown keep-on decision: {decision}")
        if not subject or "|" in subject or "\n" in subject:
            raise ValueError("subject identity must be one plain token")
        if pillar not in PILLAR_FILES or "\r" in subject or "\n" in updated or "\r" in updated or "|" in updated:
            raise ValueError("invalid keep-on identity or timestamp")
        with file_lock(self.learn_dir / ".keep_on.lock"):
            self.load()
            self.records[(pillar, subject)] = KeepOnRecord(
                pillar, subject, decision, updated,
                notes.replace("\n", " ").replace("\r", " ").replace("|", "/")[:200]
            )
            self._save_locked()

    def _save_locked(self) -> None:
        rows = sorted(self.records.values(), key=lambda row: (row.pillar, row.subject))
        body = "".join(
            f"{row.pillar}|{row.subject}|{row.decision}|{row.updated}|{row.notes}\n" for row in rows
        )
        _atomic(self.master, _HEADER + body)
        self.mirror_errors = []
        for pillar, filename in PILLAR_FILES.items():
            owned = [row for row in rows if row.pillar == pillar]
            owned_body = "".join(
                f"{row.pillar}|{row.subject}|{row.decision}|{row.updated}|{row.notes}\n" for row in owned
            )
            try:
                _atomic(self.learn_dir / filename, _HEADER + owned_body)
            except OSError:
                # The master is authoritative and already committed. A failed
                # convenience mirror must not turn a saved decision into a retry.
                self.mirror_errors.append(filename)


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
        with file_lock(self.path.with_name(self.path.name + '.lock')):
            self.load()
            if self.initialized:
                return
            if any(any(char in value for char in '|\r\n') for item in items for value in item):
                raise ValueError('invalid startup baseline identity')
            self.items = {subject: path for subject, path in items}
            lines = ["# Known startup paths. Not a user allow.", "# subject|path|updated"]
            for subject, path in sorted(self.items.items()):
                lines.append(f"{subject}|{path}|{updated}")
            _atomic(self.path, "\n".join(lines) + "\n")
            self.initialized = True

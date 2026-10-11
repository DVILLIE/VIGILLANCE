"""Local Dark / Light choice for the console.

The file is ``<data_dir>/console_ui.json``. ``data_dir`` is the install
data directory from ``runtime_paths`` (default ``<install>/data``). It is
not uploaded and it is not written into the shipped ``config.yaml``.

A missing or unreadable file means dark, the historical console default.
"""

from __future__ import annotations

import json
from pathlib import Path

from dvielle.gui.theme import DEFAULT_MODE, normalize_mode
from agent.local_files import atomic_text, file_lock

PREF_NAME = "console_ui.json"


def preference_path(data_dir: Path) -> Path:
    return Path(data_dir) / PREF_NAME


def load_appearance(data_dir: Path) -> str:
    path = preference_path(data_dir)
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, UnicodeError):
        return DEFAULT_MODE
    if not isinstance(raw, dict):
        return DEFAULT_MODE
    try:
        return normalize_mode(str(raw.get("appearance", "")))
    except ValueError:
        return DEFAULT_MODE


def _save(data_dir: Path, updates: dict) -> Path:
    directory = Path(data_dir)
    directory.mkdir(parents=True, exist_ok=True)
    path = preference_path(directory)
    with file_lock(path.with_suffix(".lock")):
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError, UnicodeError):
            payload = {}
        if not isinstance(payload, dict):
            payload = {}
        payload.update(updates)
        atomic_text(path, json.dumps(payload, indent=2) + "\n")
    return path


def save_appearance(data_dir: Path, mode: str) -> Path:
    return _save(data_dir, {"appearance": normalize_mode(mode)})


def load_motion(data_dir: Path) -> bool:
    from dvielle.gui.motion import system_motion_allowed
    try:
        payload = json.loads(preference_path(data_dir).read_text(encoding="utf-8"))
        value = payload.get("motion") if isinstance(payload, dict) else None
    except (OSError, ValueError, UnicodeError):
        value = None
    return value if isinstance(value, bool) else system_motion_allowed()


def save_motion(data_dir: Path, enabled: bool) -> Path:
    if not isinstance(enabled, bool):
        raise ValueError("motion must be a boolean")
    return _save(data_dir, {"motion": enabled})

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


def save_appearance(data_dir: Path, mode: str) -> Path:
    normalized = normalize_mode(mode)
    directory = Path(data_dir)
    directory.mkdir(parents=True, exist_ok=True)
    path = preference_path(directory)
    payload = json.dumps({"appearance": normalized}, indent=2) + "\n"
    temporary = path.with_suffix(".json.tmp")
    temporary.write_text(payload, encoding="utf-8")
    temporary.replace(path)
    return path

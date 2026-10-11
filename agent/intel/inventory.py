"""Local software inventory. An absent file is not an empty clean machine."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from agent.intel.io import MAX_INVENTORY_BYTES, read_bounded


def load_inventory(path: Path | None) -> dict[str, Any]:
    if path is None or not path.is_file():
        return {
            "state": "unavailable",
            "count": 0,
            "items": [],
            "detail": "No local software inventory file. Installed products were not guessed.",
        }
    try:
        payload = json.loads(read_bounded(path, MAX_INVENTORY_BYTES).decode("utf-8"))
    except (OSError, UnicodeError, ValueError, RecursionError):
        return {
            "state": "invalid",
            "count": 0,
            "items": [],
            "detail": "The inventory file could not be read as JSON. Nothing was matched.",
        }
    rows = payload.get("items") if isinstance(payload, dict) else None
    if not isinstance(rows, list) or len(rows) > 1000:
        return {
            "state": "invalid",
            "count": 0,
            "items": [],
            "detail": "The inventory file has no items list. Nothing was matched.",
        }
    items: list[dict[str, str]] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        name = _text(row.get("name"))
        version = _text(row.get("version"))
        if not name or not version or len(name) > 512 or len(version) > 256:
            continue
        items.append(
            {
                "name": name,
                "version": version,
                "vendor": _text(row.get("vendor")),
                "product": _text(row.get("product")) or name,
                "ecosystem": _text(row.get("ecosystem")),
                "purl": _text(row.get("purl")),
            }
        )
    if not items:
        return {
            "state": "empty",
            "count": 0,
            "items": [],
            "detail": "The inventory file lists no name and version. Matches were not evaluated.",
        }
    return {
        "state": "loaded",
        "count": len(items),
        "items": items,
        "detail": "Local inventory only. This is not a full installed-program census unless the file says so.",
    }


def _text(value: Any) -> str:
    if not isinstance(value, str):
        return ""
    return " ".join(value.split())

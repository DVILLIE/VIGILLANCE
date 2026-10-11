"""Bounded reads and atomic publication for local intelligence files."""

from __future__ import annotations

import os
from pathlib import Path
from uuid import uuid4

MAX_FEED_BYTES = 16 * 1024 * 1024
MAX_INVENTORY_BYTES = 2 * 1024 * 1024
MAX_SIDECAR_BYTES = 1024 * 1024


def read_bounded(path: Path, limit: int = MAX_FEED_BYTES) -> bytes:
    with path.open("rb") as stream:
        raw = stream.read(limit + 1)
    if len(raw) > limit:
        raise ValueError("Intelligence file exceeds its size limit")
    return raw


def publish(path: Path, raw: bytes) -> None:
    if len(raw) > MAX_FEED_BYTES:
        raise ValueError("Intelligence cache exceeds its size limit")
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{uuid4().hex}.tmp")
    try:
        with temporary.open("xb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)

"""Safe temp delete. Allowlisted roots only. Never documents. Never force."""

from __future__ import annotations

import os
from pathlib import Path

BLOCKED = frozenset({"documents", "desktop", "downloads", "pictures"})
MAX_FILES = 5000


def _blocked(path: Path) -> bool:
    return any(part.lower() in BLOCKED for part in path.parts)


def _inside(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
    except (OSError, ValueError):
        return False
    return True


def scan(roots: list[Path], locked: set[str] | None = None) -> list[tuple[Path, int, bool]]:
    locked = locked or set()
    found: list[tuple[Path, int, bool]] = []
    for root in roots:
        try:
            resolved_root = root.resolve()
        except OSError:
            continue
        if not resolved_root.is_dir() or _blocked(resolved_root):
            continue
        for dirpath, dirnames, filenames in os.walk(resolved_root, followlinks=False):
            current = Path(dirpath)
            dirnames[:] = [name for name in dirnames if not (current / name).is_symlink() and not _blocked(current / name)]
            for name in filenames:
                path = current / name
                if path.is_symlink():
                    continue
                try:
                    resolved = path.resolve()
                    size = resolved.stat().st_size
                except OSError:
                    continue
                if not _inside(resolved, resolved_root) or _blocked(resolved) or not resolved.is_file():
                    continue
                is_locked = str(resolved) in locked
                found.append((resolved, size, is_locked))
                if len(found) >= MAX_FILES:
                    return found
    return found


def free(roots: list[Path], locked: set[str] | None = None) -> tuple[int, int]:
    """Return (freed_bytes, skipped_locked)."""
    freed = 0
    skipped = 0
    resolved_roots: list[Path] = []
    for root in roots:
        try:
            resolved = root.resolve()
        except OSError:
            continue
        if resolved.is_dir() and not _blocked(resolved):
            resolved_roots.append(resolved)
    for path, size, is_locked in scan(roots, locked):
        if is_locked or not any(_inside(path, root) for root in resolved_roots):
            skipped += 1
            continue
        try:
            path.unlink()
        except OSError:
            skipped += 1
            continue
        freed += size
    return freed, skipped

"""Best-effort local webcam holders. Never opens the device. Never stores a frame."""

from __future__ import annotations

import logging
import os
import platform
from pathlib import Path

logger = logging.getLogger("dvielle.camera")


def holders_from_links(links: list[tuple[int, str, str]], devices: set[str]) -> list[dict]:
    """links are (pid, process name, fd target). devices are paths such as /dev/video0."""
    found: list[dict] = []
    seen: set[tuple[int, str]] = set()
    for pid, name, target in links:
        if target not in devices:
            continue
        key = (pid, target)
        if key in seen:
            continue
        seen.add(key)
        clean = (name or "").strip()
        found.append(
            {
                "app_name": clean,
                "pid": pid,
                "path": "",
                "device": target,
                "app_open": bool(clean),
                "suspicious_mismatch": not bool(clean),
            }
        )
    return found


def collect_camera_holders() -> list[dict] | None:
    """Linux checks /proc links to /dev/video*. Other systems return None (state unknown)."""
    system = platform.system()
    if system in ("Windows", "Darwin"):
        logger.info(
            "Camera in-use check is not available on %s yet. No camera state was invented.",
            system,
        )
        return None
    devices = {str(path) for path in Path("/dev").glob("video*") if path.exists()}
    if not devices:
        return []
    proc = Path("/proc")
    if not proc.is_dir():
        return None
    links: list[tuple[int, str, str]] = []
    saw_fd = False
    try:
        entries = list(proc.iterdir())
    except OSError:
        return None
    for entry in entries:
        if not entry.name.isdigit():
            continue
        fd_dir = entry / "fd"
        try:
            fds = list(fd_dir.iterdir())
        except OSError:
            continue
        saw_fd = True
        try:
            comm = (entry / "comm").read_text(encoding="utf-8", errors="replace").strip()
        except OSError:
            comm = ""
        for fd in fds:
            try:
                target = os.readlink(fd)
            except OSError:
                continue
            links.append((int(entry.name), comm, target))
    if not saw_fd:
        return None
    return holders_from_links(links, devices)

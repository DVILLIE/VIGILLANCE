"""Best-effort local webcam holders. Never opens the device. Never stores a frame."""

from __future__ import annotations

import logging
import os
import platform
from pathlib import Path

logger = logging.getLogger("dvielle.camera")


class CameraRecords(list):
    """Windows privacy metadata is useful, but cannot certify live ownership."""
    coverage_complete = False
    coverage_detail = 'Windows camera privacy records observed; live device ownership is unverified.'


def collect_windows_camera_records():
    import winreg
    from datetime import datetime, timezone
    base = r'Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam'
    records = CameraRecords()
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, base) as root:
            permission, _ = winreg.QueryValueEx(root, 'Value')
            pending = [base]
    except OSError:
        return None
    records.coverage_detail = ('Windows camera privacy permission: ' + str(permission)
                              + '; live device ownership remains unverified.')
    visited = 0
    while pending and visited < 256:
        path = pending.pop()
        visited += 1
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, path) as key:
                for index in range(min(winreg.QueryInfoKey(key)[0], max(0, 256 - visited - len(pending)))):
                    pending.append(path + '\\' + winreg.EnumKey(key, index))
                try:
                    start, start_type = winreg.QueryValueEx(key, 'LastUsedTimeStart')
                    end, end_type = winreg.QueryValueEx(key, 'LastUsedTimeStop')
                except FileNotFoundError:
                    continue
                if (start_type != winreg.REG_QWORD or end_type != winreg.REG_QWORD
                        or type(start) is not int or type(end) is not int or start <= 0 or end < 0):
                    continue
                # Keep FILETIME evidence; a zero stop marker is not live-use proof.
                stamp = datetime.fromtimestamp(start / 10000000 - 11644473600, timezone.utc)
                records.append({'evidence_kind': 'windows_camera_activity_record',
                    'app_name': path.rsplit('\\', 1)[-1], 'registry_key': path,
                    'last_start_utc': stamp.isoformat(), 'last_start_filetime': start,
                    'last_stop_filetime': end, 'current_use_verified': False,
                    'frames_stored': False})
        except (OSError, OverflowError, ValueError):
            records.coverage_detail += ' Some activity records were unavailable or invalid.'
    return records


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
    if system == "Windows":
        return collect_windows_camera_records()
    if system == "Darwin":
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

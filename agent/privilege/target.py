"""Executable identity and Windows leases retained through rule creation."""
from __future__ import annotations

import hashlib
import os
from contextlib import contextmanager
from pathlib import Path

MAX_EXECUTABLE_BYTES = 512 * 1024 * 1024


def _hash_stream(stream) -> dict:
    before = os.fstat(stream.fileno())
    if not 0 < before.st_size <= MAX_EXECUTABLE_BYTES:
        raise ValueError("Executable identity input exceeds the bounded size.")
    digest = hashlib.sha256()
    for chunk in iter(lambda: stream.read(1048576), b""):
        digest.update(chunk)
    after = os.fstat(stream.fileno())
    fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns")
    if any(getattr(before, key) != getattr(after, key) for key in fields):
        raise ValueError("The executable changed during identity observation.")
    return {"sha256": digest.hexdigest(), "size": after.st_size,
            "device": after.st_dev, "file_id": after.st_ino, "mtime_ns": after.st_mtime_ns}


@contextmanager
def executable_lease(program: str, *, test_harness: bool = False):
    from agent.privilege.helper import _is_elevated
    if test_harness:
        if _is_elevated():
            raise PermissionError("Test adapters refuse elevated tokens.")
        with Path(program).open("rb") as stream:
            yield _hash_stream(stream)
        return
    if os.name != "nt":
        raise OSError("Windows executable leases are unavailable.")
    import msvcrt
    import win32con
    import win32file
    candidate = Path(program)
    if not candidate.is_absolute():
        raise ValueError("An absolute executable path is required.")
    parents = []
    handle = None
    try:
        # Keep ancestor names and the final file from being replaced while the
        # path-based firewall operation runs. Reparse inputs are not accepted.
        for parent in reversed(candidate.parents):
            parent_handle = win32file.CreateFile(str(parent), 0x80,
                win32con.FILE_SHARE_READ | win32con.FILE_SHARE_WRITE, None, win32con.OPEN_EXISTING,
                0x02000000 | 0x00200000, None)  # backup semantics, open reparse point
            parents.append(parent_handle)
            if win32file.GetFileInformationByHandle(parent_handle)[0] & 0x400:
                raise PermissionError("Executable reparse ancestors are refused.")
        handle = win32file.CreateFile(str(candidate), win32con.GENERIC_READ, win32con.FILE_SHARE_READ,
                                    None, win32con.OPEN_EXISTING, 0x00200000, None)
        if win32file.GetFileInformationByHandle(handle)[0] & 0x400:
            raise PermissionError("Executable reparse inputs are refused.")
        raw_handle = handle.Detach()
        handle = None
        try:
            descriptor = msvcrt.open_osfhandle(raw_handle, os.O_RDONLY | os.O_BINARY)
        except BaseException:
            win32file.CloseHandle(raw_handle)
            raise
        with os.fdopen(descriptor, "rb") as stream:
            yield _hash_stream(stream)
    finally:
        if handle is not None:
            handle.Close()
        for parent_handle in reversed(parents):
            parent_handle.Close()

"""Coordinated local file updates. These locks are not an authorization boundary."""
from __future__ import annotations

import os
import tempfile
import threading
import time
from contextlib import contextmanager
from pathlib import Path

_guard = threading.Lock()
_locks: dict[str, threading.Lock] = {}


@contextmanager
def file_lock(path: Path, timeout: float = 10.0):
    """Non-reentrant lock; timeout bounds both thread and process contention."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with _guard:
        local = _locks.setdefault(str(path.resolve()), threading.Lock())
    deadline = time.monotonic() + timeout
    if not local.acquire(timeout=timeout):
        raise TimeoutError(f"Local file lock unavailable: {path.name}")
    try:
        with path.open("a+b") as stream:
            yield from _locked_stream(stream, path, deadline)
    finally:
        local.release()


def _locked_stream(stream, path: Path, deadline: float):
    stream.seek(0, os.SEEK_END)
    if stream.tell() == 0:
        stream.write(b"\0")
        stream.flush()
    while True:
        stream.seek(0)
        try:
            if os.name == "nt":
                import msvcrt
                msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            break
        except OSError:
            if time.monotonic() >= deadline:
                raise TimeoutError(f"Local file lock unavailable: {path.name}") from None
            time.sleep(0.02)
    try:
        yield
    finally:
        stream.seek(0)
        if os.name == "nt":
            import msvcrt
            msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            import fcntl
            fcntl.flock(stream.fileno(), fcntl.LOCK_UN)


def atomic_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, name = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        if os.name == "nt":
            import ctypes
            from ctypes import wintypes
            move = ctypes.WinDLL("kernel32", use_last_error=True).MoveFileExW
            move.argtypes = (wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD)
            move.restype = wintypes.BOOL
            # Same-directory staging; replace and request write-through.
            if not move(str(temporary.resolve()), str(path.resolve()), 0x1 | 0x8):
                raise ctypes.WinError(ctypes.get_last_error())
        else:
            os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)

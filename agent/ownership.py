"""Cross-process runtime ownership and token-bound graceful shutdown."""
from __future__ import annotations

import json
import errno
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4


class RuntimeAlreadyRunning(RuntimeError):
    pass


class RuntimeIntentionallyStopped(RuntimeError):
    pass


def atomic_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(f".{path.name}.{uuid4().hex}.tmp")
    try:
        temp.write_text(json.dumps(payload, ensure_ascii=False, allow_nan=False), encoding="utf-8")
        # Windows readers/AV can briefly hold a handle without FILE_SHARE_DELETE.
        # Keep replacement atomic, retry briefly, and retain the previous snapshot
        # if contention persists. Never unlink the visible file first.
        for attempt in range(7):
            try:
                os.replace(temp, path)
                break
            except PermissionError:
                if attempt == 6:
                    raise
                time.sleep(0.01 * 2**attempt)
    finally:
        temp.unlink(missing_ok=True)


def read_json(path: Path) -> dict | None:
    try:
        if path.stat().st_size > 2_000_000:
            return None
        value = json.loads(path.read_text(encoding="utf-8"))
        return value if isinstance(value, dict) else None
    except (OSError, ValueError):
        return None


class RuntimeLease:
    """OS lock is released on exit/crash. PID files alone are not ownership."""
    def __init__(self, data_dir: Path):
        self.data_dir = data_dir.resolve()
        self.token = uuid4().hex
        self._file = None

    def acquire(self) -> None:
        if self._file is not None:
            return
        self.data_dir.mkdir(parents=True, exist_ok=True)
        handle = (self.data_dir / "runtime.lock").open("a+b")
        try:
            if os.fstat(handle.fileno()).st_size == 0:
                handle.write(b"\0")
                handle.flush()
            handle.seek(0)
            if os.name == "nt":
                import msvcrt
                msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            handle.close()
            if exc.errno not in (errno.EACCES, errno.EAGAIN, errno.EDEADLK):
                raise
            raise RuntimeAlreadyRunning(f"Another agent owns {self.data_dir}") from exc
        self._file = handle

    def release(self) -> None:
        if self._file is None:
            return
        handle, self._file = self._file, None
        try:
            handle.seek(0)
            if os.name == "nt":
                import msvcrt
                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        finally:
            handle.close()

    def stop_requested(self) -> bool:
        value = read_json(self.data_dir / "shutdown.json")
        if not value or value.get("owner_token") != self.token:
            return False
        try:
            stamp = datetime.fromisoformat(value["requested_at"])
            age = (datetime.now(timezone.utc) - stamp).total_seconds()
            return 0 <= age <= 120
        except (KeyError, TypeError, ValueError):
            return False

    def __enter__(self):
        self.acquire()
        return self

    def __exit__(self, *args):
        self.release()


def request_shutdown(data_dir: Path, timeout: float = 60.0) -> bool:
    """Never kill by name. Ask the exact owner, then wait for lock release."""
    snap = read_json(data_dir / "twin.json") or {}
    runtime = snap.get("runtime", {})
    token = runtime.get("owner_token") if isinstance(runtime, dict) else None
    probe = RuntimeLease(data_dir)
    try:
        probe.acquire()
    except RuntimeAlreadyRunning:
        if not token:
            return False
    else:
        probe.release()
        return True
    atomic_json(data_dir / "shutdown.json", {
        "owner_token": token,
        "requested_at": datetime.now(timezone.utc).isoformat(),
    })
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            probe.acquire()
        except RuntimeAlreadyRunning:
            time.sleep(0.2)
        else:
            probe.release()
            return True
    return False

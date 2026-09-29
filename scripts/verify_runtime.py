#!/usr/bin/env python3
"""Read-only resident heartbeat verification used after scheduled-task startup."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import math
import os
from pathlib import Path
import sys
import time

import psutil

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from agent.ownership import read_json  # noqa: E402
from agent.runtime import runtime_paths  # noqa: E402


_INTERPRETER_NAMES = {"python.exe", "pythonw.exe", "python", "python3.12"}


def _directory_key(path: Path) -> str:
    """Case-folded absolute directory. Windows compares interpreter dirs this way."""
    return os.path.normcase(str(Path(path).resolve()))


def living_interpreter_matches(actual_exe: Path) -> bool:
    """True when the living image is this verifier's launcher or its base interpreter.

    ``Path(sys.executable).resolve().parent`` is the historical check: the owner
    image sits in the same directory as the verifier. On Windows that directory
    is the venv ``Scripts`` redirector (CPython bpo-34977). The scheduled task
    starts that redirector, and the process that runs ``agent.main`` — the one
    recorded as ``owner_pid`` — is the base ``pythonw.exe``. ``psutil`` reports
    that image path. ``sys.executable`` stays on the redirector, so the two
    parents differ.

    Inside a virtual environment ``sys.prefix != sys.base_prefix`` and
    ``sys.base_prefix`` is the base install (docs.python.org ``sys.prefix``).
    The base interpreter lives in that directory on Windows, including a
    pythoncore layout, and in ``bin`` under it on POSIX. No user path is
    hard-coded. Outside a venv the extra directory is not accepted.
    """
    actual_dir = _directory_key(Path(actual_exe).parent)
    launcher_dir = _directory_key(Path(sys.executable).parent)
    if actual_dir == launcher_dir:
        return True
    if sys.prefix == sys.base_prefix:
        return False
    base = Path(sys.base_prefix)
    return actual_dir in {_directory_key(base), _directory_key(base / "bin")}


def resident_is_current(snapshot: dict | None) -> bool:
    """Require a fresh heartbeat and its exact living Python process identity."""
    try:
        runtime = snapshot["runtime"]
        if runtime["state"] != "running" or not runtime["owner_token"]:
            return False
        heartbeat = datetime.fromisoformat(runtime["heartbeat_at"])
        if heartbeat.tzinfo is None:
            return False
        age = (datetime.now(timezone.utc) - heartbeat).total_seconds()
        if not 0 <= age <= 30:
            return False
        process = psutil.Process(int(runtime["owner_pid"]))
        created_at = float(runtime["owner_create_time"])
        if not math.isfinite(created_at) or abs(process.create_time() - created_at) > 0.001:
            return False
        actual_exe = Path(process.exe()).resolve()
        if not living_interpreter_matches(actual_exe):
            return False
        if actual_exe.name.lower() not in _INTERPRETER_NAMES:
            return False
        args = process.cmdline()
        return any(args[index:index + 2] == ["-m", "agent.main"] for index in range(len(args) - 1))
    except (KeyError, TypeError, ValueError, OverflowError, OSError, psutil.Error):
        return False


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config-dir", type=Path, default=ROOT / "config")
    parser.add_argument("--timeout", type=float, default=30.0)
    args = parser.parse_args()
    if not math.isfinite(args.timeout) or not 0 <= args.timeout <= 120:
        parser.error("--timeout must be between 0 and 120 seconds")
    _, _, _, _, data_dir = runtime_paths(args.config_dir)
    snapshot_path = data_dir / "twin.json"
    deadline = time.monotonic() + args.timeout
    while True:
        if resident_is_current(read_json(snapshot_path)):
            print("Verified a current DVielle resident heartbeat and process identity.")
            return 0
        if time.monotonic() >= deadline:
            print(f"No current DVielle resident heartbeat verified at {snapshot_path}.", file=sys.stderr)
            return 1
        time.sleep(min(0.25, max(0, deadline - time.monotonic())))


if __name__ == "__main__":
    raise SystemExit(main())

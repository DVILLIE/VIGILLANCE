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
        expected_dir = os.path.normcase(str(Path(sys.executable).resolve().parent))
        actual_exe = Path(process.exe()).resolve()
        if os.path.normcase(str(actual_exe.parent)) != expected_dir:
            return False
        if actual_exe.name.lower() not in {"python.exe", "pythonw.exe", "python", "python3.12"}:
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

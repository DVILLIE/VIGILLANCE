"""Local options drill. Does not close real processes or touch the system temp folder.

    python -m agent.exercise
"""

from __future__ import annotations

import tempfile
from pathlib import Path

from agent.engine.handlers import HandlerContext
from agent.engine.loop import ResolutionEngine
from agent.engine.models import PolicyDenied
from agent.engine.observations import from_disk_status, from_speed_sample
from agent.modules.disk import DiskStatus
from agent.store.db import AgentStore


def main() -> int:
    root = Path(tempfile.mkdtemp(prefix="dvielle-exercise-"))
    temp = root / "temp"
    temp.mkdir()
    cache = temp / "old-cache.tmp"
    busy = temp / "busy.tmp"
    cache.write_bytes(b"safe-to-remove")
    busy.write_bytes(b"in-use")
    calls: list[str] = []

    def lookup(_pid: int):
        return ("VideoConverter.exe", "")

    def close(pid: int, name: str):
        calls.append(f"{pid}:{name}")
        return True, f"Closed {name} in the drill only."

    store = AgentStore(root / "agent.db")
    engine = ResolutionEngine(
        store,
        learn_dir=root / "learn",
        log_dir=root / "logs",
        auto_enabled=False,
        handler_ctx=HandlerContext(
            lookup=lookup,
            close=close,
            temp_roots=[temp],
            locked_paths={str(busy.resolve())},
        ),
    )
    hog = from_speed_sample(name="VideoConverter.exe", pid=4242, cpu_percent=91, memory_mb=640)
    assert hog is not None
    opened = engine.evaluate(hog)
    print(f"1. First sighting opens a ticket ({opened['keep_on_match']}). Closed nothing: {calls}")
    try:
        engine.mutate(opened["finding"]["id"], "speed.pause_process")
    except PolicyDenied as exc:
        print(f"2. Mutate without a choice refused: {exc}")
    kept = engine.select(opened["finding"]["id"], "keep_on")
    print(f"3. Keep on learned: {kept['last_result']}")
    quiet = engine.evaluate(hog)
    print(f"4. Same app again: {quiet['disposition']} / {quiet['keep_on_match']}")
    hog.suspicious_mismatch = True
    mismatch = engine.evaluate(hog)
    print(f"5. Path/identity mismatch still tickets: {mismatch['keep_on_match']}")
    disk = from_disk_status(DiskStatus(mount=str(temp), percent_used=80, free_gb=2, total_gb=10, low_space=True))
    assert disk is not None
    card = engine.evaluate(disk)
    preview = engine.select(card["finding"]["id"], "preview")
    print(f"6. Preview left files in place ({cache.exists()}, {busy.exists()}).")
    print(preview["last_result"].splitlines()[0])
    freed = engine.select(card["finding"]["id"], "free_now")
    print(f"7. Free now: cache exists={cache.exists()} busy exists={busy.exists()} status={freed['resolution_status']}")
    print(f"Drill files are under {root}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

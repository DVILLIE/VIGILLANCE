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
from agent.engine.footprint import observation_from_footprint
from agent.engine.watch import observation_from_camera, observation_from_egress
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
    blocks: list[str] = []
    opened_settings: list[str] = []
    idents = {
        4242: ("VideoConverter.exe", ""),
        77: ("Zoom.exe", "/opt/zoom/Zoom.exe"),
        88: ("Chatty.exe", str(root / "Chatty.exe")),
        99: ("OddCam.exe", "/opt/oddcam/OddCam.exe"),
    }

    def lookup(pid: int):
        return idents.get(pid)

    def close(pid: int, name: str):
        calls.append(f"{pid}:{name}")
        return True, f"Closed {name} in the drill only."

    def block_app(name: str, path: str):
        blocks.append(name)
        return True, f"Drill only: noted a block for {name}. This does not prove packets stopped."

    def open_os(target: str):
        opened_settings.append(target)
        return True, target

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
            block_app=block_app,
            open_os=open_os,
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

    chatty = observation_from_egress(
        {"pillar": "privacy", "app_name": "Chatty.exe", "pid": 88, "path": str(root / "Chatty.exe"), "remote_ip": "203.0.113.10", "app_open": True}
    )
    assert chatty is not None
    privacy = engine.evaluate(chatty)
    print(f"8. Privacy first sighting tickets ({privacy['keep_on_match']}). Blocked nothing: {blocks}")
    try:
        engine.mutate(privacy["finding"]["id"], "privacy.block_network")
    except PolicyDenied as exc:
        print(f"9. Privacy mutate without a choice refused: {exc}")
    engine.select(privacy["finding"]["id"], "keep_on")
    again = engine.evaluate(chatty)
    print(f"10. Allowed chatty app still open: {again['disposition']} / {again['keep_on_match']}")
    missing = observation_from_egress(
        {"pillar": "privacy", "app_name": "Chatty.exe", "pid": 88, "remote_ip": "203.0.113.10", "app_open": False}
    )
    assert missing is not None
    mismatch_net = engine.evaluate(missing)
    print(f"11. Egress named Chatty but Chatty is not open: {mismatch_net['keep_on_match']}. Blocked nothing: {blocks}")

    claude = observation_from_egress(
        {
            "pillar": "ai_data",
            "app_name": "Claude.exe",
            "pid": 91,
            "host": "api.anthropic.com",
            "remote_ip": "203.0.113.20",
            "app_open": False,
        }
    )
    assert claude is not None
    ai_card = engine.evaluate(claude)
    print(f"12. AI upload named while the app is closed: {ai_card['keep_on_match']}")
    print(f"    {ai_card['finding']['why_it_matters']}")
    refused = engine.select(ai_card["finding"]["id"], "block_network")
    print(f"13. Block while the process is gone: {refused['last_result']} calls={blocks}")

    engine.memory.set("camera", "camera:zoom.exe", "allow", engine.now())
    zoom = observation_from_camera(
        {"app_name": "Zoom.exe", "pid": 77, "device": "/dev/video0", "app_open": True, "path": "/opt/zoom/Zoom.exe"}
    )
    assert zoom is not None
    quiet_zoom = engine.evaluate(zoom)
    print(f"14. Allowed Zoom is actually open: {quiet_zoom['disposition']}. Closed nothing: {calls}")
    zoom_gone = observation_from_camera(
        {"app_name": "Zoom.exe", "pid": 77, "device": "/dev/video0", "app_open": False}
    )
    assert zoom_gone is not None
    zoom_ticket = engine.evaluate(zoom_gone)
    print(f"15. Camera on but Zoom is not open: {zoom_ticket['keep_on_match']}. Closed nothing: {calls}")
    odd = observation_from_camera(
        {"app_name": "OddCam.exe", "pid": 99, "device": "/dev/video0", "app_open": True, "path": "/opt/oddcam/OddCam.exe"}
    )
    assert odd is not None
    odd_card = engine.evaluate(odd)
    stopped = engine.select(odd_card["finding"]["id"], "stop_camera")
    print(f"16. Stop camera after the choice: {stopped['resolution_status']} calls={calls}")
    cover = engine.select(zoom_ticket["finding"]["id"], "system_off")
    print(f"17. System camera settings: {cover['last_result']}")
    print(f"    Settings asked: {opened_settings}. Still no Zoom close: {calls}")
    learn = (root / "learn" / "keep_on.txt").read_text(encoding="utf-8")
    print(f"18. Keep-on has privacy={('privacy|egress:chatty.exe|allow' in learn)} camera={('camera|camera:zoom.exe|allow' in learn)}")

    local = observation_from_footprint({"kind": "local_residue", "label": "this-pc", "target": "self"})
    assert local is not None
    foot = engine.evaluate(local)
    labels = [item["label"] for item in foot["finding"]["options"]]
    print(f"19. Footprint ticket options: {', '.join(labels)}")
    try:
        engine.mutate(foot["finding"]["id"], "footprint.breach_check")
    except PolicyDenied as exc:
        print(f"20. Breach check without a choice refused: {exc}")
    steps = engine.select(foot["finding"]["id"], "lockdown")
    print(f"21. Local lockdown: {steps['resolution_status']}. {steps['last_result'].split('.')[0]}.")
    quiet_check = engine.select(foot["finding"]["id"], "breach_check")
    print(f"22. No email enrolled: {quiet_check['last_result']}")
    sent: list[str] = []

    def _checker(email: str) -> list[str]:
        sent.append(email)
        return ["SyntheticDrill"]

    engine.handler_ctx.breach_check = _checker
    engine.handler_ctx.breach_email = "drill-user@example.com"
    broker = observation_from_footprint(
        {"kind": "broker_listing", "label": "people-search", "target": "self", "synthetic": True}
    )
    assert broker is not None
    broker_card = engine.evaluate(broker)
    checked = engine.select(broker_card["finding"]["id"], "breach_check")
    print(f"23. Opt-in check ran={len(sent)==1} status={checked['resolution_status']}")
    print(f"    {checked['last_result']}")
    partner = engine.select(broker_card["finding"]["id"], "partner")
    print(f"24. Partner playbook status={partner['resolution_status']}")
    print("    " + partner["last_result"].splitlines()[1])
    done = engine.select(broker_card["finding"]["id"], "mark_resolved")
    print(f"25. {done['resolution_status']}: {done['last_result']}")
    progress = (root / "learn" / "baseline_footprint.txt").read_text(encoding="utf-8")
    print(f"26. Progress file has no email address: {'@' not in progress}")
    print(f"Drill files are under {root}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

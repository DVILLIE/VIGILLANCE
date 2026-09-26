"""Privacy, AI data, and Camera stay on the options loop."""

from __future__ import annotations

from pathlib import Path

import pytest

from agent.engine.handlers import HandlerContext
from agent.engine.loop import ResolutionEngine
from agent.engine.models import PolicyDenied
from agent.engine.net_block import block_app_network
from agent.engine.service import ingest_monitors
from agent.engine.watch import observation_from_camera, observation_from_egress
from agent.modules.camera_guard import holders_from_links
from agent.modules.egress_watch import facts_from_connections
from agent.store.db import AgentStore

NOW = "2026-09-26T12:00:00+00:00"


def _engine(tmp_path: Path, **kwargs) -> ResolutionEngine:
    store = kwargs.pop("store", None) or AgentStore(tmp_path / "agent.db")
    return ResolutionEngine(
        store,
        learn_dir=tmp_path / "learn",
        log_dir=tmp_path / "logs",
        now=lambda: NOW,
        auto_enabled=kwargs.pop("auto_enabled", False),
        **kwargs,
    )


def _ctx(lookup, close, **kwargs) -> HandlerContext:
    return HandlerContext(lookup=lookup, close=close, **kwargs)


def test_privacy_allow_is_quiet_until_the_app_is_gone(tmp_path: Path) -> None:
    blocks: list[str] = []
    engine = _engine(
        tmp_path,
        handler_ctx=_ctx(
            lambda pid: ("Chatty.exe", "/apps/Chatty.exe") if pid == 88 else None,
            lambda pid, name: (_ for _ in ()).throw(AssertionError("close")),
            block_app=lambda name, path: blocks.append(name) or (True, "nope"),
        ),
    )
    open_app = observation_from_egress(
        {"pillar": "privacy", "app_name": "Chatty.exe", "pid": 88, "remote_ip": "203.0.113.10", "app_open": True}
    )
    assert open_app is not None
    first = engine.evaluate(open_app)
    assert first["disposition"] == "ticket"
    assert first["mutated"] is False
    assert blocks == []
    ids = [item["id"] for item in first["finding"]["options"]]
    assert "keep_on" in ids and "block_network" in ids and "open_settings" in ids
    with pytest.raises(PolicyDenied, match="options required"):
        engine.mutate(first["finding"]["id"], "privacy.block_network")
    engine.select(first["finding"]["id"], "keep_on")
    quiet = engine.evaluate(open_app)
    assert quiet["disposition"] == "quiet"
    assert quiet["keep_on_match"] == "allowed_and_expected"
    gone = observation_from_egress(
        {"pillar": "privacy", "app_name": "Chatty.exe", "pid": 88, "remote_ip": "203.0.113.10", "app_open": False}
    )
    mismatch = engine.evaluate(gone)
    assert mismatch["keep_on_match"] == "suspicious_mismatch"
    assert mismatch["disposition"] == "ticket"
    assert blocks == []


def test_block_runs_only_after_select_and_does_not_claim_proof(tmp_path: Path) -> None:
    blocks: list[tuple[str, str]] = []

    def block_app(name: str, path: str):
        blocks.append((name, path))
        return False, "Helper refused."

    engine = _engine(
        tmp_path,
        handler_ctx=_ctx(
            lambda pid: ("Chatty.exe", "/apps/Chatty.exe"),
            lambda pid, name: (False, "unused"),
            block_app=block_app,
        ),
    )
    obs = observation_from_egress(
        {
            "pillar": "privacy",
            "app_name": "Chatty.exe",
            "pid": 88,
            "path": "/apps/Chatty.exe",
            "remote_ip": "203.0.113.10",
            "app_open": True,
        }
    )
    opened = engine.evaluate(obs)
    assert blocks == []
    chosen = engine.select(opened["finding"]["id"], "block_network")
    assert blocks == [("Chatty.exe", "/apps/Chatty.exe")]
    assert chosen["resolution_status"] == "found"
    assert "not stopped" in chosen["last_result"].lower()
    assert "traffic stopped" not in chosen["last_result"].lower() or "not" in chosen["last_result"].lower()


def test_ai_mismatch_does_not_claim_training_and_auto_protect_does_not_block(tmp_path: Path) -> None:
    blocks: list[str] = []
    engine = _engine(
        tmp_path,
        auto_enabled=True,
        handler_ctx=_ctx(
            lambda pid: None,
            lambda pid, name: (_ for _ in ()).throw(AssertionError("close")),
            block_app=lambda name, path: blocks.append(name) or (True, "blocked"),
        ),
    )
    obs = observation_from_egress(
        {
            "pillar": "ai_data",
            "app_name": "Claude.exe",
            "pid": 91,
            "host": "api.anthropic.com",
            "remote_ip": "203.0.113.20",
            "app_open": False,
        }
    )
    assert obs is not None
    obs.action_class = "auto_protect_eligible"
    result = engine.evaluate(obs)
    assert result["disposition"] == "ticket"
    assert result["mutated"] is False
    assert result["keep_on_match"] == "suspicious_mismatch"
    assert "not proof" in result["finding"]["why_it_matters"].lower()
    assert "trained a model on your" not in result["finding"]["title_simple"].lower()
    assert blocks == []
    text = (tmp_path / "learn" / "keep_on.txt").read_text(encoding="utf-8") if (tmp_path / "learn" / "keep_on.txt").exists() else ""
    assert "allow" not in text


def test_ai_allow_is_quiet_only_while_the_app_is_open(tmp_path: Path) -> None:
    engine = _engine(tmp_path)
    open_app = observation_from_egress(
        {"pillar": "ai_data", "app_name": "Claude.exe", "pid": 91, "host": "claude.ai", "remote_ip": "203.0.113.20", "app_open": True}
    )
    first = engine.evaluate(open_app)
    engine.select(first["finding"]["id"], "keep_on")
    assert engine.evaluate(open_app)["disposition"] == "quiet"
    closed = observation_from_egress(
        {"pillar": "ai_data", "app_name": "Claude.exe", "pid": 91, "host": "claude.ai", "remote_ip": "203.0.113.20", "app_open": False}
    )
    again = engine.evaluate(closed)
    assert again["keep_on_match"] == "suspicious_mismatch"
    line = (tmp_path / "learn" / "ai_allow.txt").read_text(encoding="utf-8")
    assert "ai_data|ai:claude.exe|allow" in line


def test_camera_allow_is_quiet_and_mismatch_does_not_kill_zoom(tmp_path: Path) -> None:
    calls: list[str] = []
    engine = _engine(
        tmp_path,
        auto_enabled=True,
        handler_ctx=_ctx(
            lambda pid: ("Zoom.exe", "/opt/zoom/Zoom.exe") if pid == 77 else None,
            lambda pid, name: calls.append(name) or (True, f"closed {name}"),
        ),
    )
    engine.memory.set("camera", "camera:zoom.exe", "allow", NOW)
    live = observation_from_camera(
        {"app_name": "Zoom.exe", "pid": 77, "device": "/dev/video0", "app_open": True, "path": "/opt/zoom/Zoom.exe"}
    )
    quiet = engine.evaluate(live)
    assert quiet["disposition"] == "quiet"
    assert calls == []
    gone = observation_from_camera({"app_name": "Zoom.exe", "pid": 77, "device": "/dev/video0", "app_open": False})
    gone.action_class = "auto_protect_eligible"
    ticket = engine.evaluate(gone)
    assert ticket["keep_on_match"] == "suspicious_mismatch"
    assert ticket["mutated"] is False
    assert calls == []
    assert ticket["finding"]["signals"]["frames_stored"] is False
    assert "No image" in " ".join(ticket["finding"]["evidence_refs"])


def test_camera_stop_and_settings_need_a_choice(tmp_path: Path) -> None:
    calls: list[str] = []
    opened: list[str] = []
    engine = _engine(
        tmp_path,
        handler_ctx=_ctx(
            lambda pid: ("OddCam.exe", "/opt/oddcam") if pid == 99 else None,
            lambda pid, name: calls.append(f"{pid}:{name}") or (True, f"closed {name}"),
            open_os=lambda target: opened.append(target) or (True, target),
        ),
    )
    obs = observation_from_camera(
        {"app_name": "OddCam.exe", "pid": 99, "device": "/dev/video0", "app_open": True, "path": "/opt/oddcam"}
    )
    card = engine.evaluate(obs)
    labels = [item["label"] for item in card["finding"]["options"]]
    assert "Stop this app's camera use" in labels
    assert "Remind me to cover the lens" in labels
    assert calls == []
    with pytest.raises(PolicyDenied):
        engine.mutate(card["finding"]["id"], "camera.stop_use")
    stopped = engine.select(card["finding"]["id"], "stop_camera")
    assert calls == ["99:OddCam.exe"]
    assert stopped["resolution_status"] == "resolved"
    fresh = engine.evaluate(
        observation_from_camera({"app_name": "Zoom.exe", "pid": 77, "device": "/dev/video0", "app_open": True})
    )
    settings = engine.select(fresh["finding"]["id"], "system_off")
    assert opened == ["camera_system"]
    assert settings["resolution_status"] != "resolved"
    assert "did not turn the camera off" in settings["last_result"]
    assert calls == ["99:OddCam.exe"]
    cover = engine.select(fresh["finding"]["id"], "cover_reminder")
    assert "cover or shutter" in cover["last_result"].lower()
    assert "stored no picture" in cover["last_result"]


def test_settings_for_ai_do_not_invent_a_vendor_page(tmp_path: Path) -> None:
    engine = _engine(
        tmp_path,
        handler_ctx=_ctx(lambda pid: ("Claude.exe", "/opt/claude"), lambda pid, name: (False, "no"), open_os=lambda target: (False, "")),
    )
    obs = observation_from_egress(
        {"pillar": "ai_data", "app_name": "Claude.exe", "pid": 91, "host": "api.anthropic.com", "remote_ip": "203.0.113.20", "app_open": True}
    )
    card = engine.evaluate(obs)
    chosen = engine.select(card["finding"]["id"], "open_settings")
    assert "not" in chosen["last_result"].lower()
    assert "improve-the-model" in chosen["last_result"].lower()
    assert chosen["resolution_status"] != "resolved"


def test_facts_skip_lan_browsers_and_updates_and_flag_ai(tmp_path: Path) -> None:
    facts = facts_from_connections(
        [
            {"app_name": "Chatty.exe", "pid": 4, "remote_ip": "192.168.1.20", "host": "", "app_open": True},
            {"app_name": "chrome.exe", "pid": 5, "remote_ip": "203.0.113.5", "host": "news.example", "app_open": True},
            {"app_name": "svchost.exe", "pid": 6, "remote_ip": "203.0.113.6", "host": "", "app_open": True},
            {"app_name": "OneDrive.exe", "pid": 7, "remote_ip": "203.0.113.7", "host": "download.microsoft.com", "app_open": True},
            {"app_name": "Claude.exe", "pid": 8, "remote_ip": "203.0.113.8", "host": "api.anthropic.com", "app_open": False},
            {"app_name": "Widget.exe", "pid": 9, "remote_ip": "93.184.216.34", "host": "telemetry.example", "app_open": True},
        ]
    )
    subjects = {(item["pillar"], item["app_name"], item["app_open"]) for item in facts}
    assert ("privacy", "Chatty.exe", True) not in subjects
    assert ("privacy", "chrome.exe", True) not in subjects
    assert ("privacy", "svchost.exe", True) not in subjects
    assert ("privacy", "OneDrive.exe", True) not in subjects
    assert ("ai_data", "Claude.exe", False) in subjects
    assert ("privacy", "Widget.exe", True) in subjects


def test_camera_links_do_not_invent_frames() -> None:
    holders = holders_from_links(
        [(77, "zoom", "/dev/video0"), (77, "zoom", "/dev/video0"), (3, "", "/tmp/frame.png")],
        {"/dev/video0"},
    )
    assert holders == [
        {"app_name": "zoom", "pid": 77, "path": "", "device": "/dev/video0", "app_open": True, "suspicious_mismatch": False}
    ]
    obs = observation_from_camera({"app_name": "zoom", "pid": 77, "device": "/tmp/shot.png", "app_open": True})
    assert obs is None


def test_block_helper_refuses_a_quoted_path_without_killing(tmp_path: Path) -> None:
    ran: list[str] = []
    ok, message = block_app_network("Chatty.exe", "/tmp/bad'path", runner=lambda name, path: ran.append(path) or (True, "added"))
    assert ok is False
    assert ran == []
    assert "not stopped" in message.lower()
    missing, text = block_app_network("Chatty.exe", str(tmp_path / "missing.exe"))
    assert missing is False
    assert "not stopped" in text.lower()


def test_live_egress_uses_hostname_and_does_not_invent_one(monkeypatch: pytest.MonkeyPatch) -> None:
    class Addr:
        def __init__(self, ip: str) -> None:
            self.ip = ip

    class Conn:
        def __init__(self, pid: int, ip: str) -> None:
            self.status = "ESTABLISHED"
            self.raddr = Addr(ip)
            self.pid = pid

    class Proc:
        def __init__(self, name: str) -> None:
            self._name = name

        def name(self) -> str:
            return self._name

        def exe(self) -> str:
            return f"/opt/{self._name}"

    names = {4: "chrome.exe", 5: "Notes.exe"}

    monkeypatch.setattr(
        "agent.modules.egress_watch.psutil.net_connections",
        lambda kind="inet": [Conn(4, "93.184.216.34"), Conn(5, "1.2.3.4")],
    )
    monkeypatch.setattr(
        "agent.modules.egress_watch.psutil.process_iter",
        lambda attrs=None: [type("P", (), {"info": {"name": name}})() for name in ("chrome.exe", "Notes.exe")],
    )
    monkeypatch.setattr("agent.modules.egress_watch.psutil.Process", lambda pid: Proc(names[pid]))
    monkeypatch.setattr("agent.modules.egress_watch.psutil.CONN_ESTABLISHED", "ESTABLISHED")
    monkeypatch.setattr(
        "agent.modules.connections._reverse_dns",
        lambda ip, timeout=0.8: "api.openai.com" if ip == "93.184.216.34" else "",
    )
    from agent.modules.egress_watch import collect_egress_facts

    facts = collect_egress_facts()
    assert facts is not None
    by_name = {item["app_name"]: item for item in facts}
    assert by_name["chrome.exe"]["pillar"] == "ai_data"
    assert by_name["chrome.exe"]["host"] == "api.openai.com"
    assert by_name["Notes.exe"]["pillar"] == "privacy"
    assert by_name["Notes.exe"]["host"] == ""


def test_ingest_camera_and_privacy_do_not_mutate(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*_args, **_kwargs):
        raise AssertionError("mutate")

    monkeypatch.setattr("agent.engine.handlers.close_process", boom)
    monkeypatch.setattr("agent.engine.net_block.block_app_network", boom)
    store = AgentStore(tmp_path / "agent.db")
    results = ingest_monitors(
        store,
        egress_facts=[{"pillar": "privacy", "app_name": "Widget.exe", "pid": 9, "remote_ip": "203.0.113.9", "app_open": True}],
        camera_facts=[{"app_name": "Zoom.exe", "pid": 77, "device": "/dev/video0", "app_open": False}],
        collect_live=False,
    )
    assert [item["disposition"] for item in results] == ["ticket", "ticket"]
    assert all(item["mutated"] is False for item in results)
    assert results[1]["keep_on_match"] == "suspicious_mismatch"

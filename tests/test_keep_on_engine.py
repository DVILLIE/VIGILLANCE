"""Keep-on match, options-before-mutate, and the three wired pillars."""

from __future__ import annotations

from pathlib import Path

import pytest

from agent.engine.handlers import HandlerContext
from agent.engine.keep_on import match_keep_on
from agent.engine.loop import ResolutionEngine
from agent.engine.models import AuthToken, Observation, PolicyDenied
from agent.engine.observations import from_disk_status, from_security, from_speed_sample, startup_observations
from agent.engine.service import choose_for_app_group
from agent.learn.memory import KeepOnMemory, KeepOnRecord, SafetyBaseline
from agent.modules.disk import DiskMonitor, DiskStatus
from agent.modules.resource_advisor import AppGroup
from agent.modules.security import SecurityStatus
from agent.store.db import AgentStore


NOW = "2026-09-25T12:00:00+00:00"


def _engine(tmp_path: Path, **kwargs) -> ResolutionEngine:
    store = AgentStore(tmp_path / "agent.db")
    return ResolutionEngine(
        store,
        learn_dir=tmp_path / "learn",
        log_dir=tmp_path / "logs",
        now=lambda: NOW,
        auto_enabled=kwargs.pop("auto_enabled", False),
        **kwargs,
    )


def _hog(name: str = "VideoConverter.exe", **kwargs) -> Observation:
    obs = from_speed_sample(name=name, pid=4242, cpu_percent=90, memory_mb=800, **kwargs)
    assert obs is not None
    return obs


def _record(decision: str, pillar: str = "speed", subject: str = "procname:videoconverter.exe") -> KeepOnRecord:
    return KeepOnRecord(pillar, subject, decision, NOW, "")


def test_allow_expected_is_quiet() -> None:
    obs = _hog()
    match = match_keep_on(_record("allow"), obs)
    assert match.code == "allowed_and_expected"
    assert match.disposition == "quiet"


def test_unknown_deny_ask_always_and_storage_allow() -> None:
    obs = _hog()
    assert match_keep_on(None, obs).code == "unknown"
    assert match_keep_on(_record("deny"), obs).code == "denied"
    assert match_keep_on(_record("ask_always"), obs).code == "unknown"
    storage = Observation(
        pillar="storage",
        kind="safe_temp",
        subject_identity="cleanup:safe_temp:C:",
        title_simple="temp",
        why_it_matters="low",
        if_ignored="full",
        evidence_refs=[],
        severity="medium",
        confidence="high",
        recommended_action="preview",
        resolution_steps=[],
        reversible="no",
        identity_ok=True,
        expected=True,
        suspicious_mismatch=False,
        quiet_on_allow=False,
    )
    assert match_keep_on(_record("allow", "storage", storage.subject_identity), storage).disposition == "ticket"


def test_never_warn_is_quiet_until_mismatch() -> None:
    obs = _hog()
    assert match_keep_on(_record("never_warn"), obs).disposition == "quiet_never_warn"
    wrong = _hog(suspicious_mismatch=True, identity_ok=True)
    assert match_keep_on(_record("never_warn"), wrong).code == "suspicious_mismatch"


def test_suspicious_mismatch_never_quiet_even_when_flags_say_ok() -> None:
    obs = _hog()
    obs.identity_ok = True
    obs.expected = True
    obs.suspicious_mismatch = True
    for decision in ("allow", "never_warn", "deny", "ask_always"):
        match = match_keep_on(_record(decision), obs)
        assert match.code == "suspicious_mismatch"
        assert match.disposition == "ticket"
    assert match_keep_on(None, obs).code == "suspicious_mismatch"


def test_invalid_keep_on_line_is_not_an_allow(tmp_path: Path) -> None:
    learn = tmp_path / "learn"
    learn.mkdir()
    (learn / "keep_on.txt").write_text(
        "# comment\nbad line\nspeed|procname:videoconverter.exe|permit|t|\n",
        encoding="utf-8",
    )
    memory = KeepOnMemory(learn)
    assert memory.skipped_lines == 2
    assert memory.get("speed", "procname:videoconverter.exe") is None


def test_evaluate_does_not_close_and_mutate_needs_a_real_token(tmp_path: Path) -> None:
    calls: list[tuple[int, str]] = []

    def lookup(pid: int):
        return ("VideoConverter.exe", "")

    def close(pid: int, name: str):
        calls.append((pid, name))
        return True, f"closed {name}"

    engine = _engine(tmp_path, handler_ctx=HandlerContext(lookup=lookup, close=close))
    result = engine.evaluate(_hog())
    assert result["disposition"] == "ticket"
    assert calls == []
    finding = result["finding"]
    with pytest.raises(PolicyDenied, match="options required"):
        engine.mutate(finding["id"], "speed.pause_process")
    forged = AuthToken(finding["id"], "speed.pause_process", "not-issued")
    with pytest.raises(PolicyDenied, match="options required"):
        engine.mutate(finding["id"], "speed.pause_process", forged)


def test_selected_pause_close_calls_closer_once(tmp_path: Path) -> None:
    calls: list[tuple[int, str]] = []

    def lookup(pid: int):
        return ("notepad.exe", "")

    def close(pid: int, name: str):
        calls.append((pid, name))
        return True, "closed notepad.exe"

    store = AgentStore(tmp_path / "agent.db")
    group = AppGroup(
        key="notepad",
        display_name="Notepad",
        process_names=["notepad.exe"],
        pids=[4242],
        memory_mb=200,
        cpu_percent=40,
        is_active_work=False,
        role="main",
        related_to=None,
        close_advice="Notepad is using memory you may want back.",
        voice_line="Notepad is heavy.",
        risk="safe",
        primary_pid=4242,
        primary_name="notepad.exe",
    )
    finding = choose_for_app_group(
        store,
        group,
        "pause_close",
        learn_dir=tmp_path / "learn",
        log_dir=tmp_path / "logs",
        now=lambda: NOW,
        auto_enabled=False,
        handler_ctx=HandlerContext(lookup=lookup, close=close),
    )
    assert calls == [(4242, "notepad.exe")]
    assert finding["resolution_status"] == "resolved"


def test_keep_on_then_mismatch_reopens(tmp_path: Path) -> None:
    engine = _engine(tmp_path)
    first = engine.evaluate(_hog())
    engine.select(first["finding"]["id"], "keep_on")
    quiet = engine.evaluate(_hog())
    assert quiet["disposition"] == "quiet"
    mismatch = engine.evaluate(_hog(suspicious_mismatch=True, identity_ok=True))
    assert mismatch["disposition"] == "ticket"
    assert mismatch["keep_on_match"] == "suspicious_mismatch"
    assert mismatch["finding"]["resolution_status"] == "found"


def test_disk_monitor_does_not_delete(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    called = {"n": 0}

    def boom(*_args, **_kwargs):
        called["n"] += 1
        raise AssertionError("cleanup must not run from the monitor")

    class Part:
        fstype = "ext4"
        mountpoint = "/tmp"

    class Usage:
        free = 100
        total = 1000
        percent = 90.0

    monkeypatch.setattr("agent.modules.disk._cleanup_temp", boom)
    monkeypatch.setattr("agent.modules.disk.psutil.disk_partitions", lambda all=False: [Part()])
    monkeypatch.setattr("agent.modules.disk.psutil.disk_usage", lambda _mount: Usage())
    monkeypatch.setattr("agent.modules.disk._smart_status", lambda: None)
    store = AgentStore(tmp_path / "agent.db")
    results = DiskMonitor(store, {"thresholds": {"disk_low_percent": 50}}).run(enable_cleanup=True)
    assert called["n"] == 0
    assert results[0].cleaned_mb == 0.0
    assert results[0].low_space is True


def test_startup_baseline_then_path_mismatch(tmp_path: Path) -> None:
    baseline = SafetyBaseline(tmp_path / "baseline_safety.txt")
    memory = KeepOnMemory(tmp_path / "learn")
    item = {
        "subject": "startup:Foo",
        "display_name": "Foo",
        "path": r"C:\apps\foo.exe",
        "source": "HKCU\\Run\\Foo",
    }
    assert startup_observations([item], baseline, memory, NOW) == []
    assert startup_observations([item], baseline, memory, NOW) == []
    changed = dict(item, path=r"C:\other\foo.exe")
    mismatch = startup_observations([changed], baseline, memory, NOW)
    assert mismatch[0].suspicious_mismatch is True
    assert mismatch[0].kind == "suspicious_startup"
    memory.set("safety", "startup:Foo", "allow", NOW)
    still = startup_observations([changed], baseline, memory, NOW)
    engine = _engine(tmp_path)
    engine.memory = memory
    result = engine.evaluate(still[0])
    assert result["keep_on_match"] == "suspicious_mismatch"
    assert result["disposition"] == "ticket"


def test_unknown_protection_is_not_off_and_turn_on_is_honest(tmp_path: Path) -> None:
    unknown = SecurityStatus(None, None, None, {}, [])
    assert from_security(unknown) == []
    off = SecurityStatus(False, None, None, {}, ["defender off"])
    obs = from_security(off)
    assert len(obs) == 1
    engine = _engine(tmp_path, auto_enabled=True)
    result = engine.evaluate(obs[0])
    assert result["disposition"] == "ticket"
    assert result["mutated"] is False
    finding = result["finding"]
    assert finding["resolution_status"] == "found"
    chosen = engine.select(finding["id"], "turn_on")
    assert chosen["resolution_status"] == "found"
    assert "did not change protection" in chosen["last_result"]


def test_preview_does_not_delete_and_free_skips_locked(tmp_path: Path) -> None:
    root = tmp_path / "temp"
    docs = root / "documents"
    docs.mkdir(parents=True)
    old = root / "old-cache.tmp"
    busy = root / "busy.tmp"
    secret = docs / "notes.txt"
    old.write_bytes(b"abc")
    busy.write_bytes(b"zzzz")
    secret.write_bytes(b"keep")
    ctx = HandlerContext(
        lookup=lambda _pid: None,
        close=lambda _pid, _name: (False, "unused"),
        temp_roots=[root],
        locked_paths={str(busy.resolve())},
    )
    engine = _engine(tmp_path, handler_ctx=ctx)
    status = DiskStatus(mount=str(root), percent_used=80, free_gb=2, total_gb=10, low_space=True)
    opened = engine.evaluate(from_disk_status(status))
    preview = engine.select(opened["finding"]["id"], "preview")
    assert "Nothing was deleted" in preview["last_result"]
    assert old.exists() and busy.exists() and secret.exists()
    freed = engine.select(opened["finding"]["id"], "free_now")
    assert freed["resolution_status"] == "resolved"
    assert not old.exists()
    assert busy.exists()
    assert secret.exists()


def test_auto_protect_off_by_default_and_never_warn_blocks_clean(tmp_path: Path) -> None:
    root = tmp_path / "temp"
    root.mkdir()
    cache = root / "old-cache.tmp"
    cache.write_bytes(b"abc")
    ctx = HandlerContext(
        lookup=lambda _pid: None,
        close=lambda _pid, _name: (False, "unused"),
        temp_roots=[root],
    )
    critical = DiskStatus(mount="C:", percent_used=96, free_gb=0.4, total_gb=10, low_space=True)
    obs = from_disk_status(critical)
    assert obs is not None and obs.signals["critical_free"] is True
    quiet_engine = _engine(tmp_path, handler_ctx=ctx, auto_enabled=False)
    held = quiet_engine.evaluate(obs)
    assert held["mutated"] is False
    assert cache.exists()
    quiet_engine.select(held["finding"]["id"], "never_warn")
    auto = ResolutionEngine(
        quiet_engine.store,
        learn_dir=quiet_engine.memory.learn_dir,
        log_dir=tmp_path / "logs",
        handler_ctx=ctx,
        now=lambda: NOW,
        auto_enabled=True,
    )
    again = auto.evaluate(obs)
    assert again["disposition"] == "quiet_never_warn"
    assert again["mutated"] is False
    assert cache.exists()


def test_auto_protect_frees_critical_temp_only(tmp_path: Path) -> None:
    root = tmp_path / "temp"
    root.mkdir()
    cache = root / "old-cache.tmp"
    cache.write_bytes(b"abcdef")
    ctx = HandlerContext(
        lookup=lambda _pid: None,
        close=lambda _pid, _name: (False, "unused"),
        temp_roots=[root],
    )
    engine = _engine(tmp_path, handler_ctx=ctx, auto_enabled=True)
    obs = from_disk_status(DiskStatus(mount="C:", percent_used=96, free_gb=0.2, total_gb=10, low_space=True))
    result = engine.evaluate(obs)
    assert result["disposition"] == "auto_protect"
    assert result["mutated"] is True
    assert not cache.exists()
    assert result["finding"]["resolution_status"] == "resolved"

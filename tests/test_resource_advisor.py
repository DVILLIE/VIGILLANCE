"""Audit #3a: ResourceAdvisor fires on PRESSURE (available/commit), not raw used%,
protects the foreground workload, and recommends via cortex at L2. Also covers the
shared memory_under_pressure predicate."""

from __future__ import annotations

import pytest

from agent.modules import resource_advisor as ra
from agent.modules.resource_advisor import (
    ProcessFootprint,
    ResourceAdvisor,
    _build_cpu_advice,
    _build_ram_advice,
    _score_closability,
)
from agent.store.db import AgentStore
from agent.win_memory import MemorySnapshot, memory_under_pressure


def _snap(*, avail_gb: float, total_gb: float = 16.0, load: float = 50.0, commit=None) -> MemorySnapshot:
    return MemorySnapshot(
        total_phys_bytes=int(total_gb * 1024 ** 3),
        avail_phys_bytes=int(avail_gb * 1024 ** 3),
        memory_load_percent=load,
        commit_total_bytes=None,
        commit_limit_bytes=None,
        commit_percent=commit,
        process_count=None,
        thread_count=None,
        source="test",
    )


class _FakeCortex:
    def __init__(self) -> None:
        self.issued: list[dict] = []

    def issue(self, **kwargs):
        self.issued.append(kwargs)
        return None


@pytest.fixture()
def store(tmp_path):
    return AgentStore(tmp_path / "agent.db")


@pytest.fixture(autouse=True)
def _reset_globals():
    ra._cpu_high_streak = 0
    ra._advisor_active = False
    ra._last_ram_toast = 0.0
    ra._last_cpu_toast = 0.0
    ra._last_measured_cpu = None
    yield


# ---- shared predicate (the crux: raw used% must NOT trigger) --------------

def test_pressure_low_available():
    assert memory_under_pressure(_snap(avail_gb=0.2)) is True  # 200 MB < 5% of 16 GB


def test_pressure_high_commit():
    assert memory_under_pressure(_snap(avail_gb=8.0, commit=90.0)) is True


def test_high_used_pct_alone_is_not_pressure():
    # memory_load 96% (standby-inflated) but 8 GB available + commit 40% → NOT pressure.
    assert memory_under_pressure(_snap(avail_gb=8.0, load=96.0, commit=40.0)) is False


def test_commit_none_falls_back_to_available_only():
    assert memory_under_pressure(_snap(avail_gb=8.0, load=99.0, commit=None)) is False
    assert memory_under_pressure(_snap(avail_gb=0.1, commit=None)) is True


# ---- advice builders (pressure/contention headlines) ----------------------

def test_build_ram_advice_pressure_language():
    advice = _build_ram_advice(
        _snap(avail_gb=0.3, commit=88.0),
        [ProcessFootprint(2, "Discord.exe", 1, 800, closability=60)],
    )
    assert "Memory pressure" in advice.headline
    assert "commit 88%" in advice.headline
    assert "Discord.exe" in advice.suggestion
    assert "%" not in advice.headline.split("commit")[0]  # no raw used-% before commit


def test_build_cpu_advice_names_background_driver():
    top = ProcessFootprint(2, "handbrake.exe", 70, 500)
    advice = _build_cpu_advice(95.0, top, [ProcessFootprint(2, "handbrake.exe", 70, 500, closability=50)])
    assert advice.resource == "CPU"
    assert "Sustained CPU 95%" in advice.headline
    assert "handbrake.exe" in advice.headline


def test_score_closability_foreground_zero():
    assert _score_closability("chrome.exe", is_foreground=True, cpu=50, mem_mb=1000) == 0.0


def test_score_closability_background_discord():
    assert _score_closability("discord.exe", is_foreground=False, cpu=5, mem_mb=800) > 40


# ---- run(): pressure gate + workload protection + L2 recommendation -------

def _measured(cpu: float | None, *, primed: bool = True) -> dict:
    body: dict = {"cpu_percent": cpu}
    if primed:
        body["cpu_sampled_at"] = "2026-09-28T18:00:00+00:00"
    return body


def _wire(monkeypatch, *, snap, cpu, processes, fg=(1234, "notepad.exe")):
    monkeypatch.setattr(ra, "sample_memory", lambda: snap)
    monkeypatch.setattr(ra, "get_foreground_process", lambda: fg)
    monkeypatch.setattr(ra, "_collect_processes", lambda fg_pid, never_close=frozenset(): processes)
    return _measured(cpu)


def test_no_pressure_returns_nothing_and_does_not_enumerate(store, monkeypatch):
    called = {"enum": False}
    monkeypatch.setattr(ra, "sample_memory", lambda: _snap(avail_gb=8.0, commit=40.0))
    monkeypatch.setattr(ra, "_collect_processes", lambda fg_pid: called.__setitem__("enum", True) or [])
    cortex = _FakeCortex()
    out = ResourceAdvisor(store, {"resource_advisor": {"toast_cooldown_seconds": 0}}, cortex=cortex).run(
        system=_measured(5.0)
    )
    assert out == []
    assert called["enum"] is False  # efficiency gate: no enumeration without pressure
    assert cortex.issued == []


def test_memory_pressure_recommends_background_offenders(store, monkeypatch):
    procs = [
        ProcessFootprint(1234, "notepad.exe", 3, 2000, is_foreground=True),  # protected
        ProcessFootprint(2, "discord.exe", 1, 800, closability=60),
        ProcessFootprint(3, "steam.exe", 0.5, 400, closability=55),
    ]
    system = _wire(monkeypatch, snap=_snap(avail_gb=0.3, commit=88.0), cpu=5.0, processes=procs)
    cortex = _FakeCortex()
    ResourceAdvisor(store, {"resource_advisor": {"toast_cooldown_seconds": 0}}, cortex=cortex).run(system=system)
    assert len(cortex.issued) == 1
    kw = cortex.issued[0]
    assert kw["target"] == "reduce_background_contention"
    assert kw["initiator"] == "resource_advisor"
    assert "notepad.exe" not in kw["details"]["offenders"]  # foreground never an offender
    assert "discord.exe" in kw["details"]["offenders"]


def test_cpu_contention_requires_two_pulses_and_nonforeground(store, monkeypatch):
    # foreground is the CPU driver -> intentional load -> never CPU contention.
    procs = [ProcessFootprint(1234, "notepad.exe", 95, 2000, is_foreground=True)]
    system = _wire(monkeypatch, snap=_snap(avail_gb=8.0, commit=40.0), cpu=95.0, processes=procs)
    cortex = _FakeCortex()
    adv = ResourceAdvisor(store, {"resource_advisor": {"toast_cooldown_seconds": 0}}, cortex=cortex)
    adv.run(system=system)  # streak=1
    adv.run(system=system)  # streak=2 (sustained) but top consumer is foreground -> no contention
    assert cortex.issued == []  # intentional workload protected


def test_cpu_contention_background_driver_after_two_pulses(store, monkeypatch):
    procs = [
        ProcessFootprint(1234, "notepad.exe", 2, 2000, is_foreground=True),
        ProcessFootprint(9, "backup.exe", 95, 300, closability=50),  # background hog
    ]
    system = _wire(monkeypatch, snap=_snap(avail_gb=8.0, commit=40.0), cpu=95.0, processes=procs)
    cortex = _FakeCortex()
    adv = ResourceAdvisor(store, {"resource_advisor": {"toast_cooldown_seconds": 0}}, cortex=cortex)
    adv.run(system=system)  # streak=1 -> no pressure yet -> nothing
    assert cortex.issued == []
    adv.run(system=system)  # streak=2 -> sustained, background driver -> recommend
    assert len(cortex.issued) == 1
    assert cortex.issued[0]["details"]["cpu_contention"] is True


def test_fg_family_helper_is_not_an_offender(store, monkeypatch):
    # Second chrome.exe (renderer) is not the FG PID but same APP_FAMILIES — protected.
    procs = [
        ProcessFootprint(1234, "chrome.exe", 3, 500, is_foreground=True),
        ProcessFootprint(1235, "chrome.exe", 80, 900, closability=60),  # family helper
        ProcessFootprint(9, "discord.exe", 1, 800, closability=55),
    ]
    system = _wire(
        monkeypatch,
        snap=_snap(avail_gb=0.3, commit=88.0),
        cpu=5.0,
        processes=procs,
        fg=(1234, "chrome.exe"),
    )
    cortex = _FakeCortex()
    ResourceAdvisor(store, {"resource_advisor": {"toast_cooldown_seconds": 0}}, cortex=cortex).run(system=system)
    assert len(cortex.issued) == 1
    offenders = cortex.issued[0]["details"]["offenders"]
    assert "chrome.exe" not in offenders
    assert "discord.exe" in offenders


def test_is_protected_workload_family_and_same_name():
    assert ra._is_protected_workload("chrome.exe", is_fg_pid=False, fg_name="chrome.exe") is True
    assert ra._is_protected_workload("backup.exe", is_fg_pid=False, fg_name="chrome.exe") is False
    assert ra._is_protected_workload("anything.exe", is_fg_pid=True, fg_name="chrome.exe") is True


# ---- #3b: never_close protect-list (panel + pulse share one predicate) -----

def test_never_close_from_config_lowercases_and_drops_empty():
    nc = ra.never_close_from_config(
        {"resource_advisor": {"never_close": ["Keeper.exe", "", None, "Notepad.exe"]}}
    )
    assert nc == frozenset({"keeper.exe", "notepad.exe"})
    assert ra.never_close_from_config({}) == frozenset()
    assert ra.never_close_from_config(None) == frozenset()


def test_is_protected_honours_never_close_case_insensitive():
    nc = frozenset({"keeper.exe"})
    assert ra._is_protected("Keeper.exe", is_fg_pid=False, fg_name="notepad.exe", never_close=nc) is True
    assert ra._is_protected("discord.exe", is_fg_pid=False, fg_name="notepad.exe", never_close=nc) is False
    # foreground family still wins with an empty never_close list
    assert ra._is_protected("chrome.exe", is_fg_pid=False, fg_name="chrome.exe", never_close=frozenset()) is True


def test_score_closability_never_close_zero():
    assert (
        _score_closability("steam.exe", is_foreground=False, cpu=5, mem_mb=800,
                           never_close=frozenset({"steam.exe"}))
        == 0.0
    )


def test_never_close_protects_named_background_offender(store, monkeypatch):
    # steam.exe is a heavy background app that WOULD be an offender, but the user put
    # it on never_close -> it must not be recommended for closing (and case-insensitive).
    procs = [
        ProcessFootprint(1234, "notepad.exe", 3, 2000, is_foreground=True),
        ProcessFootprint(2, "discord.exe", 1, 800, closability=60),
        ProcessFootprint(3, "steam.exe", 0.5, 400, closability=55),
    ]
    system = _wire(monkeypatch, snap=_snap(avail_gb=0.3, commit=88.0), cpu=5.0, processes=procs)
    cortex = _FakeCortex()
    cfg = {"resource_advisor": {"toast_cooldown_seconds": 0, "never_close": ["Steam.exe"]}}
    ResourceAdvisor(store, cfg, cortex=cortex).run(system=system)
    offenders = cortex.issued[0]["details"]["offenders"]
    assert "steam.exe" not in offenders
    assert "discord.exe" in offenders


def test_build_app_group_never_close_is_protected(monkeypatch):
    monkeypatch.setattr(ra, "_pids_with_visible_windows", lambda: set())
    fps = [ProcessFootprint(999999999, "steam.exe", 1, 800)]
    g = ra._build_app_group("steam.exe", fps, "notepad.exe", set(), frozenset({"steam.exe"}))
    assert g.risk == "protected"
    assert g.role == "protected"
    assert "protected directly or through its parent" in g.close_advice


def test_build_app_group_shell_is_caution_never_safe(monkeypatch):
    monkeypatch.setattr(ra, "_pids_with_visible_windows", lambda: set())
    fps = [ProcessFootprint(999999999, "powershell.exe", 1, 60)]
    g = ra._build_app_group("powershell.exe", fps, "notepad.exe", set(), frozenset())
    assert g.risk == "caution"  # a shell is never a one-tap SAFE close


def test_get_app_groups_ranks_protected_last(monkeypatch):
    procs = [
        ProcessFootprint(2, "discord.exe", 1, 800, closability=60),
        ProcessFootprint(3, "steam.exe", 0.5, 400),
    ]
    monkeypatch.setattr(ra, "get_foreground_process", lambda: (1234, "notepad.exe"))
    monkeypatch.setattr(ra, "_collect_processes", lambda fg_pid, never_close=frozenset(): procs)
    monkeypatch.setattr(ra, "_running_names", lambda: {"discord.exe", "steam.exe"})
    monkeypatch.setattr(ra, "_pids_with_visible_windows", lambda: set())
    groups = ra.get_app_groups(never_close=frozenset({"steam.exe"}))
    protected = [g for g in groups if g.risk == "protected"]
    assert len(protected) == 1  # never_close item is shown, not skipped
    assert "steam" in protected[0].display_name.lower()
    assert groups[-1].risk == "protected"  # protected sorts last (informational, not actionable)


def test_unprimed_cpu_does_not_clear_pressure_or_read_as_zero(store, monkeypatch):
    procs = [ProcessFootprint(9, "backup.exe", 90, 300, closability=50)]
    system = _wire(monkeypatch, snap=_snap(avail_gb=8.0, commit=40.0), cpu=95.0, processes=procs)
    called = {"n": 0}

    def forbid_fresh_sample(*_args, **_kwargs):
        raise AssertionError("advisor must not take a fresh cpu_percent sample")

    monkeypatch.setattr(ra.psutil, "cpu_percent", forbid_fresh_sample)
    adv = ResourceAdvisor(store, {"resource_advisor": {"toast_cooldown_seconds": 0}})
    adv.run(system=system)
    adv.run(system=system)
    assert ra._cpu_high_streak >= 2
    ra._collect_processes = lambda fg_pid, never_close=frozenset(): called.__setitem__("n", called["n"] + 1) or procs
    # No timestamp: the 0.0 in the dict is unprimed, not a measured idle sample.
    adv.run(system={"cpu_percent": 0.0})
    assert ra._cpu_high_streak >= 2
    assert called["n"] == 1  # held streak still analyzes; zero was not "no pressure"
    assert ra.host_cpu_percent({"cpu_percent": 0.0}) is None
    assert ra.host_cpu_percent({"cpu_percent": None, "cpu_sampled_at": "2026-09-28T18:00:00+00:00"}) is None
    assert ra.host_cpu_percent({"cpu_percent": "bad", "cpu_sampled_at": "2026-09-28T18:00:00+00:00"}) is None

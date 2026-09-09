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

def _wire(monkeypatch, *, snap, cpu, processes, fg=(1234, "cursor.exe")):
    monkeypatch.setattr(ra, "sample_memory", lambda: snap)
    monkeypatch.setattr(ra.psutil, "cpu_percent", lambda interval=0: cpu)
    monkeypatch.setattr(ra, "get_foreground_process", lambda: fg)
    monkeypatch.setattr(ra, "_collect_processes", lambda fg_pid: processes)


def test_no_pressure_returns_nothing_and_does_not_enumerate(store, monkeypatch):
    called = {"enum": False}
    monkeypatch.setattr(ra, "sample_memory", lambda: _snap(avail_gb=8.0, commit=40.0))
    monkeypatch.setattr(ra.psutil, "cpu_percent", lambda interval=0: 5.0)
    monkeypatch.setattr(ra, "_collect_processes", lambda fg_pid: called.__setitem__("enum", True) or [])
    cortex = _FakeCortex()
    out = ResourceAdvisor(store, {"resource_advisor": {"toast_cooldown_seconds": 0}}, cortex=cortex).run()
    assert out == []
    assert called["enum"] is False  # efficiency gate: no enumeration without pressure
    assert cortex.issued == []


def test_memory_pressure_recommends_background_offenders(store, monkeypatch):
    procs = [
        ProcessFootprint(1234, "cursor.exe", 3, 2000, is_foreground=True),  # protected
        ProcessFootprint(2, "discord.exe", 1, 800, closability=60),
        ProcessFootprint(3, "steam.exe", 0.5, 400, closability=55),
    ]
    _wire(monkeypatch, snap=_snap(avail_gb=0.3, commit=88.0), cpu=5.0, processes=procs)
    cortex = _FakeCortex()
    ResourceAdvisor(store, {"resource_advisor": {"toast_cooldown_seconds": 0}}, cortex=cortex).run()
    assert len(cortex.issued) == 1
    kw = cortex.issued[0]
    assert kw["target"] == "reduce_background_contention"
    assert kw["initiator"] == "resource_advisor"
    assert "cursor.exe" not in kw["details"]["offenders"]  # foreground never an offender
    assert "discord.exe" in kw["details"]["offenders"]


def test_cpu_contention_requires_two_pulses_and_nonforeground(store, monkeypatch):
    # foreground is the CPU driver -> intentional load -> never CPU contention.
    procs = [ProcessFootprint(1234, "cursor.exe", 95, 2000, is_foreground=True)]
    _wire(monkeypatch, snap=_snap(avail_gb=8.0, commit=40.0), cpu=95.0, processes=procs)
    cortex = _FakeCortex()
    adv = ResourceAdvisor(store, {"resource_advisor": {"toast_cooldown_seconds": 0}}, cortex=cortex)
    adv.run()  # streak=1
    adv.run()  # streak=2 (sustained) but top consumer is foreground -> no contention
    assert cortex.issued == []  # intentional workload protected


def test_cpu_contention_background_driver_after_two_pulses(store, monkeypatch):
    procs = [
        ProcessFootprint(1234, "cursor.exe", 2, 2000, is_foreground=True),
        ProcessFootprint(9, "backup.exe", 95, 300, closability=50),  # background hog
    ]
    _wire(monkeypatch, snap=_snap(avail_gb=8.0, commit=40.0), cpu=95.0, processes=procs)
    cortex = _FakeCortex()
    adv = ResourceAdvisor(store, {"resource_advisor": {"toast_cooldown_seconds": 0}}, cortex=cortex)
    adv.run()  # streak=1 -> no pressure yet -> nothing
    assert cortex.issued == []
    adv.run()  # streak=2 -> sustained, background driver -> recommend
    assert len(cortex.issued) == 1
    assert cortex.issued[0]["details"]["cpu_contention"] is True


def test_fg_family_helper_is_not_an_offender(store, monkeypatch):
    # Second chrome.exe (renderer) is not the FG PID but same APP_FAMILIES — protected.
    procs = [
        ProcessFootprint(1234, "chrome.exe", 3, 500, is_foreground=True),
        ProcessFootprint(1235, "chrome.exe", 80, 900, closability=60),  # family helper
        ProcessFootprint(9, "discord.exe", 1, 800, closability=55),
    ]
    _wire(
        monkeypatch,
        snap=_snap(avail_gb=0.3, commit=88.0),
        cpu=5.0,
        processes=procs,
        fg=(1234, "chrome.exe"),
    )
    cortex = _FakeCortex()
    ResourceAdvisor(store, {"resource_advisor": {"toast_cooldown_seconds": 0}}, cortex=cortex).run()
    assert len(cortex.issued) == 1
    offenders = cortex.issued[0]["details"]["offenders"]
    assert "chrome.exe" not in offenders
    assert "discord.exe" in offenders


def test_is_protected_workload_family_and_same_name():
    assert ra._is_protected_workload("chrome.exe", is_fg_pid=False, fg_name="chrome.exe") is True
    assert ra._is_protected_workload("backup.exe", is_fg_pid=False, fg_name="chrome.exe") is False
    assert ra._is_protected_workload("anything.exe", is_fg_pid=True, fg_name="chrome.exe") is True

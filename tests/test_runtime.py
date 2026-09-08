"""C3: shared runtime, per-module pulse isolation, non-blocking reverse-DNS."""

from __future__ import annotations

import time
from pathlib import Path

from agent import net_resolve, runtime
from agent.twin import TwinStore


class _FakeCaps:
    tier = "T1"
    is_admin = True
    overall_vision = "LIMITED"
    gaps: list = []
    ram_total_gb = 16.0
    cpu_count = 8
    battery_present = False
    os_caption = "Windows 11"
    os_build = "26200"
    edition_hint = "Home"
    notes: list = []

    def to_dict(self) -> dict:
        return {"tier": self.tier}


def _write_config(tmp_path: Path) -> Path:
    cfgdir = tmp_path / "config"
    cfgdir.mkdir()
    (cfgdir / "config.yaml").write_text(
        "agent:\n"
        f"  data_dir: {(tmp_path / 'data').as_posix()}\n"
        "modes: {monitor_only: true, enable_toasts: false}\n"
        "modules: {}\n"
        "nerve: {heartbeat_seconds: 5, pulse_seconds: 60, idle_deep_seconds: 900}\n"
        "logging: {level: INFO}\n",
        encoding="utf-8",
    )
    (cfgdir / "whitelists.yaml").write_text("{}\n", encoding="utf-8")
    (cfgdir / "telemetry-domains.txt").write_text("", encoding="utf-8")
    return cfgdir


def test_build_runtime_registers_collectors_and_is_fail_closed(tmp_path, monkeypatch):
    monkeypatch.setattr(runtime, "probe_capabilities", lambda deep=False: _FakeCaps())
    monkeypatch.setattr(runtime, "set_process_priority", lambda *a, **k: None)

    rt = runtime.build_runtime(config_dir=_write_config(tmp_path))

    assert {c.name for c in rt.nerve.collectors} == {"heartbeat", "pulse", "idle_deep"}
    # Autonomous gate stays fail-closed: no mutation handlers registered.
    assert rt.policy.executor.registry.registered() == frozenset()
    assert rt.twin is not None
    # prime() runs one heartbeat and populates memory + self-budget.
    rt.prime()
    data = rt.twin.as_dict()
    assert data["memory"]
    assert data["self_budget"]


def test_run_once_isolates_module_failures(tmp_path, monkeypatch):
    from agent.store.db import AgentStore

    ran = {"ram": False}

    class _Boom:
        def __init__(self, *a, **k):
            pass

        def run(self, *a, **k):
            raise RuntimeError("boom")

    class _FakeRam:
        def __init__(self, *a, **k):
            pass

        def run(self, *a, **k):
            ran["ram"] = True

            class _R:
                percent = 50.0
                available_mb = 1024.0

            return _R()

    monkeypatch.setattr(runtime, "ConnectionMonitor", _Boom)
    monkeypatch.setattr(runtime, "RamMonitor", _FakeRam)

    store = AgentStore(tmp_path / "agent.db")
    modules = {name: False for name in (
        "attacks", "browser_guard", "resource_advisor", "disk",
        "security", "privacy_guard", "network_info", "microsoft_guard",
    )}
    modules.update({"connections": True, "ram": True})

    # connections raises; run_once must still reach ram and return normally.
    runtime.run_once(
        store, {}, {}, tmp_path / "tele.txt", tmp_path,
        {"monitor_only": True, "enable_toasts": False}, modules,
    )
    assert ran["ram"] is True


def test_net_resolve_lookup_is_nonblocking_and_cached():
    t0 = time.monotonic()
    assert net_resolve.lookup("203.0.113.201") is None  # miss -> None immediately
    assert (time.monotonic() - t0) < 0.5  # never blocks the caller

    net_resolve._cache["198.51.100.9"] = ("host.example.", time.monotonic() + 100)
    assert net_resolve.lookup("198.51.100.9") == "host.example."
    assert net_resolve.lookup("") is None


def test_twin_as_dict_is_a_copy(tmp_path):
    tw = TwinStore(tmp_path / "twin.jsonl")
    tw.patch(system={"cpu_percent": 42})
    snapshot = tw.as_dict()
    snapshot["system"]["cpu_percent"] = 0  # mutate the copy
    assert tw.as_dict()["system"]["cpu_percent"] == 42  # original unaffected

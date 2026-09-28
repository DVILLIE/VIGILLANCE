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

    specs = {c.name: c for c in rt.nerve.collectors}
    assert set(runtime.COLLECTOR_NAMES) <= specs.keys()
    assert specs["heartbeat"].background is False
    assert specs["attacks"].background and specs["attacks"].critical
    assert specs["connections"].defer_under_maximum_workload
    assert specs["resource_advisor"].pressure_response
    assert specs["resource_advisor"].background and not specs["resource_advisor"].critical
    assert not specs["resource_advisor"].defer_under_maximum_workload
    assert specs["capability"].cadence.value == "idle_deep"
    # Autonomous gate stays fail-closed: no mutation handlers registered.
    assert rt.policy.executor.registry.registered() == frozenset()
    assert rt.twin is not None
    # prime() runs one heartbeat and populates memory + self-budget.
    rt.prime()
    data = rt.twin.as_dict()
    assert data["memory"]
    assert data["self_budget"]
    assert data["runtime"]["owner_token"]
    assert (rt.lease.data_dir / "twin.json").exists()
    assert rt.close(timeout=1)


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


def test_failed_snapshot_write_does_not_leave_a_drained_runtime_locked(tmp_path, monkeypatch):
    from agent.ownership import RuntimeLease
    monkeypatch.setattr(runtime, "probe_capabilities", lambda deep=False: _FakeCaps())
    monkeypatch.setattr(runtime, "set_process_priority", lambda *a, **k: None)
    rt = runtime.build_runtime(config_dir=_write_config(tmp_path))
    def broken_publish():
        raise PermissionError('snapshot is temporarily unavailable')
    monkeypatch.setattr(rt.twin, 'publish', broken_publish)
    assert rt.close(timeout=1)
    with RuntimeLease(rt.lease.data_dir):
        pass


def test_takeover_rechecks_intentional_stop_inside_lease(tmp_path, monkeypatch):
    import pytest
    from agent.ownership import RuntimeIntentionallyStopped
    monkeypatch.setattr(runtime, "probe_capabilities", lambda deep=False: _FakeCaps())
    monkeypatch.setattr(runtime, "set_process_priority", lambda *a, **k: None)
    config = _write_config(tmp_path)
    owner = runtime.build_runtime(config)
    owner.prime()
    token = owner.lease.token
    assert owner.close(1)
    # Models stop/release between a follower's preliminary check and acquisition.
    with pytest.raises(RuntimeIntentionallyStopped):
        runtime.build_runtime(config, previous_owner_token=token)
    assert owner.twin.as_dict()['runtime']['state'] == 'stopped'
    # An explicit manual start is still allowed, and the rejected attempt released its lease.
    restarted = runtime.build_runtime(config)
    assert restarted.lease.token != token
    assert restarted.close(1)

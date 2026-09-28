"""Failed probes stay partial. They are not a fresh successful observation."""

from types import SimpleNamespace

import psutil
import pytest

from agent.modules.microsoft_guard import MicrosoftGuard
from agent.modules.network_info import NetworkMonitor, coverage_error
from agent.nerve import CollectionIncomplete
from agent.runtime import _collector_callbacks
from agent.store.db import AgentStore


def test_microsoft_access_denial_is_unavailable(tmp_path, monkeypatch):
    monkeypatch.setattr("agent.modules.microsoft_guard.IS_WINDOWS", True)

    def denied(**_kwargs):
        raise psutil.AccessDenied(pid=0)

    monkeypatch.setattr("agent.modules.microsoft_guard.psutil.net_connections", denied)
    guard = MicrosoftGuard(AgentStore(tmp_path / "agent.db"), {}, tmp_path / "domains.txt", tmp_path, [])
    assert guard.run() == []
    assert guard.collection_error
    assert "unavailable" in guard.collection_error


def test_runtime_publishes_microsoft_denial_as_partial(tmp_path, monkeypatch):
    class Guard:
        def __init__(self, *args, **kwargs):
            self.collection_error = "Microsoft connection visibility unavailable: AccessDenied"

        def run(self, **kwargs):
            return []

    monkeypatch.setattr("agent.runtime.MicrosoftGuard", Guard)
    store = AgentStore(tmp_path / "agent.db")
    callbacks = _collector_callbacks(
        store, {}, {}, tmp_path / "domains.txt", tmp_path,
        {"enable_toasts": False}, None, None,
    )
    with pytest.raises(CollectionIncomplete, match="unavailable"):
        callbacks["microsoft_guard"]()


def test_dns_timeout_is_not_an_empty_success(tmp_path, monkeypatch):
    monkeypatch.setattr("agent.modules.network_info.IS_WINDOWS", True)
    monkeypatch.setattr("agent.modules.network_info._collect_local_ips", lambda: ([], None, None, None, "timeout"))
    monkeypatch.setattr("agent.modules.network_info._fetch_dns_servers", lambda: ([], "timeout"))
    snap = NetworkMonitor(AgentStore(tmp_path / "agent.db"), {}).run()
    assert snap.dns_servers == []
    assert snap.dns_observation == "timeout"
    assert snap.gateway_observation == "timeout"
    assert coverage_error(snap)
    assert "timeout" in coverage_error(snap)


def test_runtime_network_partial_is_not_ok(tmp_path, monkeypatch):
    class Monitor:
        def __init__(self, *args, **kwargs):
            self.collection_error = "Network observation incomplete: dns timeout"

        def run(self):
            return SimpleNamespace(to_dict=lambda: {
                "hostname": "test",
                "dns_servers": [],
                "dns_observation": "timeout",
                "gateway_observation": "timeout",
            })

    monkeypatch.setattr("agent.runtime.NetworkMonitor", Monitor)
    store = AgentStore(tmp_path / "agent.db")
    callbacks = _collector_callbacks(
        store, {}, {}, tmp_path / "domains.txt", tmp_path,
        {"enable_toasts": False}, None, None,
    )
    with pytest.raises(CollectionIncomplete, match="timeout"):
        callbacks["network_info"]()

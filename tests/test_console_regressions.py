"""Fixture-based privacy and presentation regressions; no live UI or process mutations."""
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
import queue

import pytest

from agent.chat import assistant as assistant_module
from agent.chat.assistant import ChatAssistant
from agent.chat.local_explainer import local_answer
from agent.chat.personas import JARVIS
from dvielle.gui import notify_policy
from dvielle.gui.observations import chat_stats, collector_state, section_current, snapshot_fresh


def _snapshot(status="ok"):
    stamp = datetime.now(timezone.utc).isoformat()
    return {
        "runtime": {"state": "running", "heartbeat_at": stamp},
        "collectors": {
            "heartbeat": {"status": "ok", "interval_seconds": 5, "last_success_at": stamp},
            "disk": {"status": status, "interval_seconds": 60, "last_success_at": stamp},
            "network_info": {"status": status, "interval_seconds": 60, "last_success_at": stamp},
        },
        "memory": {"memory_load_percent": 60, "avail_phys_mb": 2048, "sampled_at": stamp},
        "system": {"cpu_percent": 30, "cpu_sampled_at": stamp, "disk_percent": 70},
        "network": {"vpn_active": False},
    }


@pytest.mark.parametrize("state", ["pending", "partial", "deferred", "error", "disabled"])
def test_incomplete_collector_never_yields_current_stats(state):
    data = _snapshot(state)
    assert collector_state(data, "disk") == state
    assert not section_current(data, "disk")
    stats = chat_stats(data, True, 3)
    assert stats["disk_percent_used"] is None
    assert stats["vpn_active"] is None
    assert stats["cpu_percent"] == 30


def test_old_or_future_heartbeat_invalidates_all_stats():
    for delta in [timedelta(minutes=-10), timedelta(minutes=10)]:
        data = _snapshot()
        data["runtime"]["heartbeat_at"] = (datetime.now(timezone.utc) + delta).isoformat()
        assert not snapshot_fresh(data)
        stats = chat_stats(data, True, 3)
        assert not stats["agent_started"]
        assert all(stats[k] is None for k in ["cpu_percent", "ram_percent", "disk_percent_used", "vpn_active"])


def test_missing_stats_cannot_claim_zero_usage_or_vpn_safety():
    answer = local_answer("cpu status", {}, JARVIS)
    assert "unavailable" in answer and "0%" not in answer
    answer = local_answer("vpn status", {"vpn_active": True}, JARVIS)
    assert "unverified" in answer


def test_disabled_chat_never_collects_or_contacts_backends(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("Disabled chat reached a collector or external backend")
    monkeypatch.setattr(assistant_module, "gather_stats_context", forbidden)
    monkeypatch.setattr(assistant_module, "search_web", forbidden)
    monkeypatch.setattr(assistant_module, "chat_completion", forbidden)
    response = ChatAssistant(allow_cloud=True, allow_web_search=True).ask("search weather", from_voice=True)
    assert "disabled" in response.text


def test_web_opt_in_and_historical_identity_redaction(monkeypatch):
    queries = []
    monkeypatch.setattr(assistant_module, "search_web", lambda q: queries.append(q) or "")
    monkeypatch.setattr(assistant_module, "chat_completion", lambda *a, **k: (None, None))
    bot = ChatAssistant(enabled=True)
    bot.ask("cpu", stats_override={"hostname": "OLD-LAPTOP"})
    bot.ask("weather OLD-LAPTOP", from_voice=True, stats_override={})
    assert not queries
    bot.allow_web_search = True
    bot.ask("weather OLD-LAPTOP", from_voice=True, stats_override={})
    assert len(queries) == 1 and "OLD-LAPTOP" not in queries[0]


@pytest.mark.parametrize("mode,critical", [("headless", True), ("tray", True), ("visible", False)])
def test_notification_delivery_is_explicit(mode, critical):
    previous = notify_policy._mode
    try:
        notify_policy.set_notification_mode(mode)
        assert notify_policy.should_popup("CRITICAL") is critical
        assert not notify_policy.should_popup("INFO")
    finally:
        notify_policy.set_notification_mode(previous)


@pytest.mark.parametrize("backend,opt_in,allowed", [
    ("disabled", False, False), ("google", False, False),
    ("google", True, True), ("local", False, True),
])
def test_microphone_backend_requires_explicit_configuration(backend, opt_in, allowed):
    pytest.importorskip("customtkinter")
    from dvielle.gui.chat_window import ChatWindow
    view = SimpleNamespace(assistant=ChatAssistant(enabled=True, speech_backend=backend, allow_cloud_speech=opt_in))
    assert ChatWindow._speech_allowed(view) is allowed


def test_chat_worker_dispatch_does_not_touch_tk_or_closed_window():
    pytest.importorskip("customtkinter")
    from dvielle.gui.chat_window import ChatWindow
    events = queue.SimpleQueue()
    view = SimpleNamespace(_events=events, _closed=False)
    called = []
    ChatWindow._dispatch(view, lambda: called.append(True))
    assert not called
    events.get_nowait()()
    assert called == [True]
    view._closed = True
    ChatWindow._dispatch(view, lambda: called.append(False))
    assert events.empty()

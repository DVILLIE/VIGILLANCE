"""Fixture-based presentation regressions; no live UI or process mutations."""
from datetime import datetime, timedelta, timezone

import pytest

from dvielle.gui import notify_policy
from dvielle.gui.observations import collector_state, section_current, snapshot_fresh


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
    assert not section_current(data, "network_info")
    assert section_current(data, "heartbeat", data["system"]["cpu_sampled_at"])


def test_old_or_future_heartbeat_invalidates_all_stats():
    for delta in [timedelta(minutes=-10), timedelta(minutes=10)]:
        data = _snapshot()
        data["runtime"]["heartbeat_at"] = (datetime.now(timezone.utc) + delta).isoformat()
        assert not snapshot_fresh(data)
        assert not section_current(data, "heartbeat", data["system"]["cpu_sampled_at"])
        assert not section_current(data, "disk")


@pytest.mark.parametrize("mode,critical", [("headless", True), ("tray", True), ("visible", False)])
def test_notification_delivery_is_explicit(mode, critical):
    previous = notify_policy._mode
    try:
        notify_policy.set_notification_mode(mode)
        assert notify_policy.should_popup("CRITICAL") is critical
        assert not notify_policy.should_popup("INFO")
    finally:
        notify_policy.set_notification_mode(previous)

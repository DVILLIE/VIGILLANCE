"""Empty and stale evidence must not read as a current all-clear."""

from dvielle.gui.observations import failed_logon_copy, why_measurement_line


def test_empty_logons_never_claim_nobody_is_guessing():
    for coverage in ("ok", "unavailable", "stale", "partial", "error", "pending"):
        text = failed_logon_copy([], coverage)
        assert "nobody" not in text.lower()
        assert "guessing your password" not in text.lower()
    assert "not known" in failed_logon_copy([], "stale")
    assert "stored" in failed_logon_copy([], "ok")


def test_stale_logons_are_labeled_retained():
    rows = [{"source_ip": "203.0.113.8", "count": 3, "username": "sam", "event_id": 4625, "ts": "2026-09-01T00:00:00+00:00"}]
    text = failed_logon_copy(rows, "stale")
    assert "not a current reading" in text
    assert "203.0.113.8" in text
    assert "right now" not in text


def test_why_stopped_snapshot_is_not_labeled_now():
    retained = {
        "runtime": {"state": "stopped", "heartbeat_at": "2026-09-28T18:00:00+00:00"},
        "memory": {"commit_percent": 91, "avail_phys_mb": 400},
        "system": {"cpu_percent": 88, "cpu_sampled_at": "2026-09-28T18:00:00+00:00"},
        "collectors": {"heartbeat": {"interval_seconds": 5}},
    }
    text = why_measurement_line(retained)
    assert text.lower().startswith("measurements stale")
    assert not text.lower().startswith("now")
    assert "91" not in text
    assert why_measurement_line(None).startswith("Measurements unavailable")


def test_why_fresh_snapshot_names_the_heartbeat():
    from datetime import datetime, timezone

    stamp = datetime.now(timezone.utc).isoformat()
    fresh = {
        "runtime": {"state": "running", "heartbeat_at": stamp},
        "memory": {"commit_percent": 40, "avail_phys_mb": 8000},
        "system": {"cpu_percent": 12, "cpu_sampled_at": stamp},
        "collectors": {"heartbeat": {"interval_seconds": 5, "status": "ok", "last_success_at": stamp}},
    }
    text = why_measurement_line(fresh)
    assert text.startswith("Latest heartbeat:")
    assert "40" in text
    assert not text.lower().startswith("now")

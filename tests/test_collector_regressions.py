"""Collector boundary tests using explicit provider fixtures and temporary stores.

These verify code semantics, not this computer's Security log or protection state.
"""

from datetime import datetime, timedelta, timezone
import json
import sqlite3
import threading
import time
from types import SimpleNamespace

import pytest

from agent import net_resolve
from agent.modules import attacks, browser_guard, connection_intel, connections, disk, privacy_guard
from agent.policy import PolicyCortex
from agent.store.db import AgentStore


def _event(record_id=1, *, stamp=None, event_id=4625, status="0xc000006a", ip="203.0.113.50"):
    return {"record_id": record_id, "timestamp": stamp or datetime.now(timezone.utc).isoformat(),
            "event_id": event_id, "status": status, "ip": ip,
            "username": "operator|one", "workstation": "CLIENTBOX"}


def _parse(rows, **checkpoint):
    last = rows[-1] if rows else _event()
    payload = [*rows, {"checkpoint": True, "record_id": last["record_id"],
                      "timestamp": last["timestamp"], **checkpoint}]
    return attacks._parse_security_query_stdout("\n".join(json.dumps(row) for row in payload))


@pytest.fixture
def store(tmp_path):
    return AgentStore(tmp_path / "observations.db")


def test_4776_success_does_not_count_and_workstation_is_never_an_ip(store):
    events, degraded, error = _parse([_event(1, event_id=4776, status="0x0"),
                                      _event(2, event_id=4776)])
    assert not degraded and error is None
    assert events[0]["is_failure"] is False
    assert events[1]["source_ip"] is None
    inserted = store.ingest_security_events(events, cursor_key="test", next_record_id=2,
                                           next_timestamp=events.next_timestamp)
    assert len(inserted) == 1
    assert store.get_failed_logon_count("host:CLIENTBOX") == 1
    assert store.get_failed_logon_count("203.0.113.50") == 0
    assert store.get_cursor("test") == 2


def test_equivalent_ipv4_and_mapped_ipv6_clients_share_rolling_count(store):
    events, _, _ = _parse([_event(1, ip="203.0.113.50"), _event(2, ip="::ffff:203.0.113.50")])
    assert {event["source_ip"] for event in events} == {"203.0.113.50"}
    store.ingest_security_events(events, cursor_key="test", next_record_id=2,
                                 next_timestamp=events.next_timestamp)
    assert store.get_failed_logon_count("203.0.113.50") == 2


def test_backfill_uses_source_time_future_excluded_retry_idempotent_record_id_reusable(store):
    now = datetime.now(timezone.utc)
    rows = [_event(1, stamp=(now - timedelta(days=1)).isoformat()),
            _event(2, stamp=(now - timedelta(minutes=1)).isoformat()),
            _event(3, stamp=(now + timedelta(days=1)).isoformat())]
    events, _, _ = _parse(rows)
    for _ in range(2):
        store.ingest_security_events(events, cursor_key="test", next_record_id=3,
                                     next_timestamp=events.next_timestamp)
    assert store.get_failed_logon_count("203.0.113.50") == 1
    reused, _, _ = _parse([_event(1, stamp=(now - timedelta(seconds=10)).isoformat())], reset=True)
    store.ingest_security_events(reused, cursor_key="test", next_record_id=1,
                                 next_timestamp=reused.next_timestamp)
    assert store.get_failed_logon_count("203.0.113.50") == 2
    assert store.get_cursor("test") == 1
    assert store.attack_summary()["failed_logon_attempts"] == 3
    with store._conn() as conn:
        assert conn.execute("SELECT COUNT(*) FROM failed_logons").fetchone()[0] == 4


def test_failed_batch_rolls_back_evidence_and_checkpoint(store):
    rows, _, _ = _parse([_event()])
    malformed = dict(rows[0], timestamp="invalid")
    with pytest.raises(ValueError):
        store.ingest_security_events([rows[0], malformed], cursor_key="test", next_record_id=2,
                                     next_timestamp=rows.next_timestamp)
    assert store.get_cursor("test") == 0
    assert store.get_failed_logon_count("203.0.113.50") == 0


def test_malformed_or_missing_timestamp_cannot_acknowledge_source():
    events, degraded, error = _parse([_event(stamp="2026-09-13T00:00:00")])
    assert not events and degraded and error == "invalid_security_event_payload"
    events, degraded, error = attacks._parse_security_query_stdout(json.dumps(_event()))
    assert not events and degraded and error == "missing_security_checkpoint"


def test_gap_without_new_failures_still_reports_degradation(store, tmp_path, monkeypatch):
    events, degraded, _ = _parse([_event(event_id=4776, status="0x0")], gap=True)
    monkeypatch.setattr(attacks, "IS_WINDOWS", True)
    monkeypatch.setattr(attacks, "_query_security_events", lambda **kwargs: (events, degraded, None))
    monitor = attacks.AttackMonitor(store, {}, tmp_path)
    result = monitor.run()
    assert result and all(item.collection_degraded for item in result)
    assert monitor.collection_degraded and monitor.collection_error is None
    assert store.get_failed_logon_count("host:CLIENTBOX") == 0


def test_attack_provider_failure_metadata_clears_after_recovery(store, tmp_path, monkeypatch):
    monkeypatch.setattr(attacks, "IS_WINDOWS", True)
    monkeypatch.setattr(attacks, "_query_security_events", lambda **kwargs: ([], True, "query_failed"))
    monitor = attacks.AttackMonitor(store, {}, tmp_path)
    assert monitor.run()[0].collection_degraded
    assert monitor.collection_error == "query_failed"
    monkeypatch.setattr(attacks, "_query_security_events", lambda **kwargs: ([], False, None))
    assert monitor.run() == []
    assert monitor.collection_error is None and not monitor.collection_degraded


def test_backfill_does_not_recommend_current_attack(store, tmp_path, monkeypatch):
    stamp = (datetime.now(timezone.utc) - timedelta(hours=5)).isoformat()
    events, _, _ = _parse([_event(i, stamp=stamp) for i in range(1, 7)])
    monkeypatch.setattr(attacks, "IS_WINDOWS", True)
    monkeypatch.setattr(attacks, "_query_security_events", lambda **kwargs: (events, False, None))
    result = attacks.AttackMonitor(store, {}, tmp_path, cortex=PolicyCortex(store=store)).run(True)
    assert len(result) == 6 and all(item.attempt_count == 0 and not item.should_block for item in result)
    assert store.recent_decisions() == []


@pytest.mark.parametrize("path", [r"C:\Users\Test\AppData\Local\Google\Chrome\Application\chrome.exe",
                                   r"C:\Program Files\Google\Chrome\Application\chrome.exe",
                                   r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"])
def test_standard_browser_locations_are_recognized(path):
    assert browser_guard._is_legit_browser_path(path)


def test_browser_impostor_path_is_not_canonical():
    assert not browser_guard._is_legit_browser_path(r"C:\Users\Test\Downloads\chrome.exe")
    assert not browser_guard._is_legit_browser_path(r"C:\Program Files\Google\Chrome\Application\evil\chrome.exe")


def test_domain_and_organization_hints_require_boundaries():
    assert connections._domain_whitelisted("api.example.com", ["example.com"])
    assert not connections._domain_whitelisted("example.com.attacker.test", ["example.com"])
    assert not connections._domain_whitelisted("example.com..", ["example.com"])
    assert connection_intel._org_from_host("openai.com.attacker.test") is None
    assert connection_intel._org_from_host("attacker-google.com") is None
    assert "Unverified" in connection_intel._org_from_host("api.openai.com")


def test_explicit_review_rule_survives_allowlisted_name_ptr_and_cloud(store, monkeypatch):
    monkeypatch.setattr(connections, "_default_gateway", lambda: None)
    monkeypatch.setattr(connections, "_local_ipv4s", lambda: [])
    monkeypatch.setattr(connections, "_reverse_dns", lambda _: "api.example.com")
    monkeypatch.setattr(connections, "_process_info", lambda _: ("chrome.exe", "C:/unknown/chrome.exe", None))
    conn = SimpleNamespace(status="ESTABLISHED", pid=42,
                           raddr=SimpleNamespace(ip="104.16.2.34", port=443),
                           laddr=SimpleNamespace(ip="192.168.1.2", port=12345))
    monkeypatch.setattr(connections.psutil, "net_connections", lambda **kwargs: [conn])
    connections._alerted_at.clear()
    monitor = connections.ConnectionMonitor(store, {"network": {"review_ips": ["104.16.2.34"]}},
                                            {"ips": ["104.16.2.34"], "processes": ["chrome.exe"],
                                             "domains": ["example.com"]})
    alerts = monitor.run()
    assert len(alerts) == 1 and "review requested" in alerts[0].reason
    assert monitor.collection_error is None


def test_connection_access_denied_is_unavailable_not_clean(store, monkeypatch):
    monkeypatch.setattr(connections, "_default_gateway", lambda: None)
    monkeypatch.setattr(connections, "_local_ipv4s", lambda: [])
    def denied(**kwargs):
        raise connections.psutil.AccessDenied()
    monkeypatch.setattr(connections.psutil, "net_connections", denied)
    monitor = connections.ConnectionMonitor(store, {}, {})
    assert monitor.run() == []
    assert "unavailable" in monitor.collection_error


def test_disk_cleanup_flag_cannot_delete_files(store, tmp_path, monkeypatch):
    target = tmp_path / "valuable.tmp"
    target.write_text("must survive")
    monkeypatch.setattr(disk, "_smart_status", lambda: None)
    monkeypatch.setattr(disk.psutil, "disk_partitions", lambda **kwargs:
                        [SimpleNamespace(fstype="NTFS", mountpoint=str(tmp_path))])
    monkeypatch.setattr(disk.psutil, "disk_usage", lambda _: SimpleNamespace(total=1000, free=1, percent=99.9))
    statuses = disk.DiskMonitor(store, {}).run(enable_cleanup=True)
    assert statuses[0].low_space and statuses[0].cleaned_mb == 0
    assert target.read_text() == "must survive"


@pytest.mark.parametrize("usage", [SimpleNamespace(total=0, free=0, percent=0),
                                  SimpleNamespace(total=100, free=101, percent=0),
                                  SimpleNamespace(total=100, free=10, percent=float("nan"))])
def test_invalid_disk_capacity_is_unavailable_not_zero_or_low_space(store, tmp_path, monkeypatch, usage):
    monkeypatch.setattr(disk, "_smart_status", lambda: None)
    monkeypatch.setattr(disk.psutil, "disk_partitions", lambda **kwargs:
                        [SimpleNamespace(fstype="NTFS", mountpoint=str(tmp_path))])
    monkeypatch.setattr(disk.psutil, "disk_usage", lambda _: usage)
    monitor = disk.DiskMonitor(store, {})
    assert monitor.run() == []
    assert monitor.collection_error and store.recent_events() == []


@pytest.mark.parametrize("edition,expected", [("Core", 1), ("Professional", 1),
                                               ("ProfessionalEducation", 1), ("EnterpriseS", 0),
                                               ("Education", 0), ("ServerStandard", 0), (None, None)])
def test_privacy_supported_diagnostic_floor(edition, expected):
    assert privacy_guard._diagnostic_floor(edition) == expected


def test_missing_policy_remains_null_and_supported_pro_floor_is_one(store, tmp_path, monkeypatch):
    monkeypatch.setattr(privacy_guard, "IS_WINDOWS", True)
    monkeypatch.setattr(privacy_guard, "winreg", object())
    monkeypatch.setattr(privacy_guard, "_windows_edition", lambda: "Professional")
    monkeypatch.setattr(privacy_guard, "_privacy_checks", lambda: [
        {"name": "AllowTelemetry", "hive": None, "path": "", "value": "telemetry", "expected": 0},
        {"name": "Advertising", "hive": None, "path": "", "value": "missing", "expected": 0}])
    monkeypatch.setattr(privacy_guard, "_read_reg_dword", lambda _, __, name: 0 if name == "telemetry" else None)
    monkeypatch.setattr(privacy_guard.PrivacyGuard, "_check_hosts_entries", lambda _: [])
    guard = privacy_guard.PrivacyGuard(store, {}, tmp_path / "domains")
    results = guard.run()
    assert results[0].passed is True and "minimum 1" in results[0].expected
    assert "does not turn diagnostics off" in results[0].detail
    assert results[1].passed is None and guard.collection_error
    with store._conn() as conn:
        rows = list(conn.execute("SELECT passed FROM privacy_checks ORDER BY id"))
    assert rows[1]["passed"] is None


def test_hosts_comments_substrings_and_aliases_are_distinguished():
    endpoint = privacy_guard.SETTINGS_ENDPOINT
    entries = privacy_guard._hosts_overrides(f"# 0.0.0.0 {endpoint}\n0.0.0.0 {endpoint}.attacker.test\n"
                                             f"127.0.0.1 other.example {endpoint.upper()} # active alias\n")
    assert entries[endpoint] == {"127.0.0.1"}


def test_sqlite_unknown_migration_preserves_existing_privacy_history(tmp_path):
    path = tmp_path / "legacy.db"
    with sqlite3.connect(path) as conn:
        conn.execute("CREATE TABLE privacy_checks (id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, "
                     "check_name TEXT NOT NULL, expected TEXT, actual TEXT, passed INTEGER NOT NULL)")
        conn.execute("INSERT INTO privacy_checks VALUES(1, '2025-01-01', 'old', '0', '1', 0)")
    store = AgentStore(path)
    store.log_privacy_check("new", "0", "unavailable", None)
    with store._conn() as conn:
        rows = list(conn.execute("SELECT * FROM privacy_checks ORDER BY id"))
    assert rows[0]["passed"] == 0 and rows[0]["id"] == 1
    assert rows[1]["passed"] is None


def test_privacy_migration_failure_rolls_back_temporary_table_and_retries(tmp_path, monkeypatch):
    path = tmp_path / "interrupted-migration.db"
    connect = sqlite3.connect
    with connect(path) as conn:
        conn.execute("CREATE TABLE privacy_checks (id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, "
                     "check_name TEXT NOT NULL, expected TEXT, actual TEXT, passed INTEGER NOT NULL)")
        conn.execute("INSERT INTO privacy_checks VALUES(1, '2025-01-01', 'old', '0', '1', 0)")

    class FailedMigrationConnection(sqlite3.Connection):
        def execute(self, sql, *args, **kwargs):
            if sql.startswith("INSERT INTO privacy_checks_nullable"):
                raise sqlite3.OperationalError("Injected migration failure")
            return super().execute(sql, *args, **kwargs)

    with monkeypatch.context() as patch:
        patch.setattr(sqlite3, "connect", lambda *args, **kwargs:
                      connect(*args, **kwargs, factory=FailedMigrationConnection))
        with pytest.raises(sqlite3.OperationalError, match="Injected migration failure"):
            AgentStore(path)
    with connect(path) as conn:
        assert conn.execute("SELECT name FROM sqlite_master WHERE name='privacy_checks_nullable'").fetchone() is None
        assert conn.execute("SELECT passed FROM privacy_checks").fetchone()[0] == 0
    AgentStore(path).log_privacy_check("recovered", "0", "unavailable", None)


def test_attached_store_does_not_run_schema_migrations(tmp_path, monkeypatch):
    def forbidden(_):
        raise AssertionError("attached reader must not initialize the owner schema")
    monkeypatch.setattr(AgentStore, "_init_schema", forbidden)
    path = tmp_path / "not-created" / "reader.db"
    reader = AgentStore(path, initialize=False)
    with pytest.raises(sqlite3.OperationalError):
        reader.recent_events()
    assert not path.exists() and not path.parent.exists()


def test_latest_work_log_and_retention_include_mirrors_and_privacy(store):
    for i in range(5):
        store.log_work("test", str(i))
    assert [row["message"] for row in store.get_work_log(2)] == ["3", "4"]
    store.log_privacy_check("unknown", "0", "unavailable", None)
    with store._conn() as conn:
        conn.execute("UPDATE work_log SET ts='2000-01-01T00:00:00+00:00'")
        conn.execute("UPDATE privacy_checks SET ts='2000-01-01T00:00:00+00:00'")
    deleted = store.prune_old()
    assert deleted["work_log"] == 5 and deleted["privacy_checks"] == 1


def test_bounded_resolver_does_not_change_global_socket_timeout(monkeypatch):
    started = threading.Event()
    release = threading.Event()
    completed = threading.Event()
    original_timeout = net_resolve.socket.getdefaulttimeout()
    def slow_lookup(ip):
        started.set()
        release.wait(3)
        completed.set()
        return ("ptr.example", [], [ip])
    monkeypatch.setattr(net_resolve.socket, "gethostbyaddr", slow_lookup)
    monkeypatch.setattr(net_resolve, "_MAX_INFLIGHT", 1)
    with net_resolve._lock:
        net_resolve._cache.clear()
    try:
        begin = time.monotonic()
        assert net_resolve.resolve_blocking("203.0.113.99", timeout=0.01) is None
        assert started.wait(1)
        assert time.monotonic() - begin < 0.5
        assert net_resolve.lookup("203.0.113.100") is None
        with net_resolve._lock:
            assert len(net_resolve._inflight) == 1
        assert net_resolve.socket.getdefaulttimeout() == original_timeout
    finally:
        release.set()
        assert completed.wait(1)

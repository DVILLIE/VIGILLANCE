"""Audit #2.2: peer-deduped FLAGGED report, windowed attack_summary, prune_old."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from agent.store.db import AgentStore, cutoff_iso


@pytest.fixture
def store(tmp_path: Path) -> AgentStore:
    return AgentStore(tmp_path / "ret.db")


def _insert_conn(
    store: AgentStore,
    *,
    ts: str,
    process: str,
    ip: str,
    suspicious: int = 1,
    reason: str = "old",
    port: int = 443,
) -> None:
    with store._conn() as conn:
        conn.execute(
            """
            INSERT INTO connections
            (ts, pid, process_name, local_addr, remote_addr, remote_ip,
             remote_port, status, suspicious, reason)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                ts,
                1,
                process,
                "127.0.0.1:1",
                f"{ip}:{port}",
                ip,
                port,
                "ESTABLISHED",
                suspicious,
                reason,
            ),
        )


def test_flagged_peer_dedup_and_latest_reason(store: AgentStore) -> None:
    now = datetime.now(timezone.utc)
    # Same peer, many pulses — must collapse to one row with hits and newest reason.
    for i in range(5):
        _insert_conn(
            store,
            ts=(now - timedelta(minutes=10 - i)).isoformat(),
            process="sample.exe",
            ip="160.79.104.10",
            reason=f"reason-{i}",
        )
    # Different peer in-window.
    _insert_conn(
        store,
        ts=now.isoformat(),
        process="evil.exe",
        ip="203.0.113.9",
        reason="review",
    )
    # Outside window — ignored.
    _insert_conn(
        store,
        ts=(now - timedelta(hours=48)).isoformat(),
        process="old.exe",
        ip="198.51.100.1",
        reason="stale",
    )

    rows = store.recent_suspicious_connections(50, window_hours=24)
    assert len(rows) == 2
    by_proc = {r["process_name"]: r for r in rows}
    assert by_proc["sample.exe"]["hits"] == 5
    assert by_proc["sample.exe"]["reason"] == "reason-4"  # MAX(id) / latest
    assert by_proc["evil.exe"]["hits"] == 1
    assert "old.exe" not in by_proc


def test_attack_summary_window_vs_blocked_live(store: AgentStore) -> None:
    now = datetime.now(timezone.utc)
    with store._conn() as conn:
        conn.execute(
            "INSERT INTO failed_logons (ts, event_id, source_ip, username, workstation, count) "
            "VALUES (?, 4625, '1.2.3.4', 'u', 'w', 3)",
            ((now - timedelta(days=2)).isoformat(),),
        )
        conn.execute(
            "INSERT INTO failed_logons (ts, event_id, source_ip, username, workstation, count) "
            "VALUES (?, 4625, '1.2.3.4', 'u', 'w', 7)",
            ((now - timedelta(days=20)).isoformat(),),  # outside 14d
        )
        conn.execute(
            "INSERT INTO events (ts, module, severity, message) VALUES (?, 'attacks', 'WARNING', 'x')",
            ((now - timedelta(days=1)).isoformat(),),
        )
        conn.execute(
            "INSERT INTO events (ts, module, severity, message) VALUES (?, 'attacks', 'WARNING', 'old')",
            ((now - timedelta(days=40)).isoformat(),),
        )
        conn.execute(
            "INSERT INTO events (ts, module, severity, message) VALUES (?, 'browser_guard', 'CRITICAL', 'b')",
            (now.isoformat(),),
        )
    store.block_ip("198.51.100.50", "test")

    s = store.attack_summary(window_days=14)
    assert s["failed_logon_attempts"] == 3  # not 10
    assert s["attack_events"] == 1
    assert s["browser_threat_events"] == 1
    assert s["blocked_ips"] == 1  # live, unwindowed
    assert s["summary_window_days"] == 14.0


def test_prune_old_ages_tables_spares_ledger(store: AgentStore) -> None:
    old = cutoff_iso(days=40)
    recent = datetime.now(timezone.utc).isoformat()
    with store._conn() as conn:
        conn.execute(
            "INSERT INTO connections (ts, pid, process_name, local_addr, remote_addr, "
            "remote_ip, remote_port, status, suspicious, reason) "
            "VALUES (?, 1, 'a.exe', '', '1.1.1.1:443', '1.1.1.1', 443, 'E', 0, '')",
            (old,),
        )
        conn.execute(
            "INSERT INTO connections (ts, pid, process_name, local_addr, remote_addr, "
            "remote_ip, remote_port, status, suspicious, reason) "
            "VALUES (?, 1, 'b.exe', '', '1.1.1.1:443', '1.1.1.1', 443, 'E', 0, '')",
            (recent,),
        )
        conn.execute(
            "INSERT INTO events (ts, module, severity, message) VALUES (?, 'x', 'INFO', 'old')",
            (old,),
        )
        conn.execute(
            "INSERT INTO decisions (decision_id, ts, action, action_level) VALUES ('d1', ?, 'RECOMMEND', 2)",
            (old,),
        )
        conn.execute(
            "INSERT INTO action_audit (ts, payload) VALUES (?, '{}')",
            (old,),
        )
        conn.execute(
            "INSERT INTO action_decisions (decision_id, claimed_at, status) VALUES ('c1', ?, 'claimed')",
            (old,),
        )

    deleted = store.prune_old(
        {
            "connections_days": 7,
            "events_days": 14,
            "health_snapshots_days": 14,
            "failed_logons_days": 30,
        }
    )
    assert deleted["connections"] == 1
    assert deleted["events"] == 1
    with store._conn() as conn:
        assert conn.execute("SELECT COUNT(*) AS n FROM connections").fetchone()["n"] == 1
        assert conn.execute("SELECT COUNT(*) AS n FROM decisions").fetchone()["n"] == 1
        assert conn.execute("SELECT COUNT(*) AS n FROM action_audit").fetchone()["n"] == 1
        assert conn.execute("SELECT COUNT(*) AS n FROM action_decisions").fetchone()["n"] == 1

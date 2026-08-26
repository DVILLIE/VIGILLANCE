"""SQLite persistence for DVielle Agent."""

from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Generator, Iterable


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


class AgentStore:
    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    @contextmanager
    def _conn(self) -> Generator[sqlite3.Connection, None, None]:
        conn = sqlite3.connect(self.db_path, timeout=30)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def _init_schema(self) -> None:
        with self._conn() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts TEXT NOT NULL,
                    module TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    message TEXT NOT NULL,
                    details TEXT
                );

                CREATE TABLE IF NOT EXISTS connections (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts TEXT NOT NULL,
                    pid INTEGER,
                    process_name TEXT,
                    local_addr TEXT,
                    remote_addr TEXT,
                    remote_ip TEXT,
                    remote_port INTEGER,
                    status TEXT,
                    suspicious INTEGER DEFAULT 0,
                    reason TEXT
                );

                CREATE TABLE IF NOT EXISTS failed_logons (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts TEXT NOT NULL,
                    event_id INTEGER,
                    source_ip TEXT,
                    username TEXT,
                    workstation TEXT,
                    count INTEGER DEFAULT 1
                );

                CREATE TABLE IF NOT EXISTS blocked_ips (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts TEXT NOT NULL,
                    ip TEXT NOT NULL UNIQUE,
                    reason TEXT,
                    active INTEGER DEFAULT 1
                );

                CREATE TABLE IF NOT EXISTS health_snapshots (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts TEXT NOT NULL,
                    ram_percent REAL,
                    ram_available_mb REAL,
                    disk_percent_used REAL,
                    disk_free_gb REAL,
                    defender_enabled INTEGER,
                    firewall_enabled INTEGER,
                    details TEXT
                );

                CREATE TABLE IF NOT EXISTS baseline_processes (
                    process_name TEXT PRIMARY KEY,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    connection_count INTEGER DEFAULT 1
                );

                CREATE TABLE IF NOT EXISTS privacy_checks (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts TEXT NOT NULL,
                    check_name TEXT NOT NULL,
                    expected TEXT,
                    actual TEXT,
                    passed INTEGER NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
                CREATE INDEX IF NOT EXISTS idx_connections_ts ON connections(ts);
                CREATE INDEX IF NOT EXISTS idx_failed_logons_ip ON failed_logons(source_ip);

                CREATE TABLE IF NOT EXISTS work_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts TEXT NOT NULL,
                    action TEXT NOT NULL,
                    message TEXT NOT NULL,
                    details TEXT
                );

                CREATE INDEX IF NOT EXISTS idx_work_log_ts ON work_log(ts);

                CREATE TABLE IF NOT EXISTS agent_cursors (
                    key TEXT PRIMARY KEY,
                    value INTEGER NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS action_audit (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts TEXT NOT NULL,
                    payload TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS action_decisions (
                    decision_id TEXT PRIMARY KEY,
                    claimed_at TEXT NOT NULL,
                    status TEXT NOT NULL,
                    payload TEXT,
                    result TEXT
                );
                """
            )

    def log_event(
        self,
        module: str,
        severity: str,
        message: str,
        details: dict[str, Any] | None = None,
    ) -> None:
        with self._conn() as conn:
            conn.execute(
                """
                INSERT INTO events (ts, module, severity, message, details)
                VALUES (?, ?, ?, ?, ?)
                """,
                (utc_now(), module, severity, message, json.dumps(details) if details else None),
            )
        if severity in ("INFO", "WARNING", "CRITICAL"):
            self.log_work(module.upper(), message, details)

    def log_work(
        self,
        action: str,
        message: str,
        details: dict[str, Any] | None = None,
    ) -> None:
        with self._conn() as conn:
            conn.execute(
                """
                INSERT INTO work_log (ts, action, message, details)
                VALUES (?, ?, ?, ?)
                """,
                (utc_now(), action, message, json.dumps(details) if details else None),
            )

    def get_work_log(self, limit: int = 500) -> list[sqlite3.Row]:
        with self._conn() as conn:
            return list(
                conn.execute(
                    "SELECT id, ts, action, message, details FROM work_log ORDER BY id ASC LIMIT ?",
                    (limit,),
                ).fetchall()
            )

    def clear_work_log(self) -> int:
        with self._conn() as conn:
            cur = conn.execute("DELETE FROM work_log")
            return cur.rowcount

    def get_cursor(self, key: str, default: int = 0) -> int:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT value FROM agent_cursors WHERE key = ?",
                (key,),
            ).fetchone()
            return int(row["value"]) if row else default

    def set_cursor(self, key: str, value: int) -> None:
        with self._conn() as conn:
            conn.execute(
                """
                INSERT INTO agent_cursors (key, value, updated_at)
                VALUES (?, ?, ?)
                ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at
                """,
                (key, int(value), utc_now()),
            )

    def log_action_audit(self, payload: dict[str, Any]) -> None:
        with self._conn() as conn:
            conn.execute(
                "INSERT INTO action_audit (ts, payload) VALUES (?, ?)",
                (utc_now(), json.dumps(payload)),
            )

    def claim_decision_id(
        self,
        decision_id: str,
        payload: dict[str, Any] | None = None,
    ) -> bool:
        """Atomically claim a Decision ID. False if already claimed (replay protection)."""
        if not decision_id:
            return False
        with self._conn() as conn:
            try:
                conn.execute(
                    """
                    INSERT INTO action_decisions (decision_id, claimed_at, status, payload)
                    VALUES (?, ?, ?, ?)
                    """,
                    (
                        decision_id,
                        utc_now(),
                        "CLAIMED",
                        json.dumps(payload) if payload else None,
                    ),
                )
                return True
            except sqlite3.IntegrityError:
                return False

    def finalize_decision(
        self,
        decision_id: str,
        *,
        status: str,
        result: str | None = None,
    ) -> None:
        with self._conn() as conn:
            conn.execute(
                """
                UPDATE action_decisions
                SET status = ?, result = ?
                WHERE decision_id = ?
                """,
                (status, result, decision_id),
            )

    def log_connection(
        self,
        *,
        pid: int | None,
        process_name: str | None,
        local_addr: str,
        remote_addr: str,
        remote_ip: str,
        remote_port: int | None,
        status: str,
        suspicious: bool,
        reason: str | None = None,
    ) -> None:
        with self._conn() as conn:
            conn.execute(
                """
                INSERT INTO connections
                (ts, pid, process_name, local_addr, remote_addr, remote_ip,
                 remote_port, status, suspicious, reason)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    utc_now(),
                    pid,
                    process_name,
                    local_addr,
                    remote_addr,
                    remote_ip,
                    remote_port,
                    status,
                    1 if suspicious else 0,
                    reason,
                ),
            )

    def record_failed_logon(
        self,
        event_id: int,
        source_ip: str | None,
        username: str | None,
        workstation: str | None,
        *,
        window_minutes: int = 15,
    ) -> int:
        """Insert one failed-logon observation; return count inside rolling window.

        Lifetime cumulative counters were incorrect for brute-force thresholds
        (Architecture P0). Each event is a row; ``count`` column stores 1.
        """
        ip = source_ip or "unknown"
        now = utc_now()
        with self._conn() as conn:
            conn.execute(
                """
                INSERT INTO failed_logons (ts, event_id, source_ip, username, workstation, count)
                VALUES (?, ?, ?, ?, ?, 1)
                """,
                (now, event_id, ip, username, workstation),
            )
            return self._failed_logon_count_locked(conn, ip, window_minutes)

    def _failed_logon_count_locked(
        self, conn: sqlite3.Connection, source_ip: str, window_minutes: int
    ) -> int:
        cutoff = datetime.now(timezone.utc) - timedelta(minutes=window_minutes)
        rows = conn.execute(
            "SELECT ts FROM failed_logons WHERE source_ip = ?",
            (source_ip,),
        ).fetchall()
        n = 0
        for row in rows:
            try:
                ts = datetime.fromisoformat(str(row["ts"]))
                if ts.tzinfo is None:
                    ts = ts.replace(tzinfo=timezone.utc)
                if ts >= cutoff:
                    n += 1
            except ValueError:
                continue
        return n

    def get_failed_logon_count(self, source_ip: str, window_minutes: int = 15) -> int:
        with self._conn() as conn:
            return self._failed_logon_count_locked(conn, source_ip, window_minutes)

    def is_ip_blocked(self, ip: str) -> bool:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT 1 FROM blocked_ips WHERE ip = ? AND active = 1",
                (ip,),
            ).fetchone()
            return row is not None

    def block_ip(self, ip: str, reason: str) -> None:
        with self._conn() as conn:
            conn.execute(
                """
                INSERT INTO blocked_ips (ts, ip, reason, active)
                VALUES (?, ?, ?, 1)
                ON CONFLICT(ip) DO UPDATE SET ts = excluded.ts, reason = excluded.reason, active = 1
                """,
                (utc_now(), ip, reason),
            )

    def log_health_snapshot(self, snapshot: dict[str, Any]) -> None:
        with self._conn() as conn:
            conn.execute(
                """
                INSERT INTO health_snapshots
                (ts, ram_percent, ram_available_mb, disk_percent_used, disk_free_gb,
                 defender_enabled, firewall_enabled, details)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    utc_now(),
                    snapshot.get("ram_percent"),
                    snapshot.get("ram_available_mb"),
                    snapshot.get("disk_percent_used"),
                    snapshot.get("disk_free_gb"),
                    1 if snapshot.get("defender_enabled") else 0,
                    1 if snapshot.get("firewall_enabled") else 0,
                    json.dumps(snapshot.get("details", {})),
                ),
            )

    def update_baseline_process(self, process_name: str) -> None:
        name = process_name.lower()
        now = utc_now()
        with self._conn() as conn:
            conn.execute(
                """
                INSERT INTO baseline_processes (process_name, first_seen, last_seen, connection_count)
                VALUES (?, ?, ?, 1)
                ON CONFLICT(process_name) DO UPDATE SET
                    last_seen = excluded.last_seen,
                    connection_count = connection_count + 1
                """,
                (name, now, now),
            )

    def is_baseline_process(self, process_name: str) -> bool:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT 1 FROM baseline_processes WHERE process_name = ?",
                (process_name.lower(),),
            ).fetchone()
            return row is not None

    def log_privacy_check(
        self, check_name: str, expected: str, actual: str, passed: bool
    ) -> None:
        with self._conn() as conn:
            conn.execute(
                """
                INSERT INTO privacy_checks (ts, check_name, expected, actual, passed)
                VALUES (?, ?, ?, ?, ?)
                """,
                (utc_now(), check_name, expected, actual, 1 if passed else 0),
            )

    def recent_suspicious_connections(self, limit: int = 50) -> list[sqlite3.Row]:
        with self._conn() as conn:
            return list(
                conn.execute(
                    """
                    SELECT * FROM connections WHERE suspicious = 1
                    ORDER BY id DESC LIMIT ?
                    """,
                    (limit,),
                ).fetchall()
            )

    def recent_events(
        self,
        modules: Iterable[str] | None = None,
        limit: int = 100,
    ) -> list[sqlite3.Row]:
        with self._conn() as conn:
            if modules:
                placeholders = ",".join("?" for _ in modules)
                return list(
                    conn.execute(
                        f"""
                        SELECT id, ts, module, severity, message, details
                        FROM events
                        WHERE module IN ({placeholders})
                        ORDER BY id DESC LIMIT ?
                        """,
                        (*list(modules), limit),
                    ).fetchall()
                )
            return list(
                conn.execute(
                    """
                    SELECT id, ts, module, severity, message, details
                    FROM events
                    ORDER BY id DESC LIMIT ?
                    """,
                    (limit,),
                ).fetchall()
            )

    def recent_failed_logons(self, limit: int = 50) -> list[sqlite3.Row]:
        with self._conn() as conn:
            return list(
                conn.execute(
                    """
                    SELECT id, ts, event_id, source_ip, username, workstation, count
                    FROM failed_logons
                    ORDER BY id DESC LIMIT ?
                    """,
                    (limit,),
                ).fetchall()
            )

    def attack_summary(self) -> dict[str, Any]:
        with self._conn() as conn:
            fail = conn.execute("SELECT COALESCE(SUM(count), 0) AS n FROM failed_logons").fetchone()
            blocked = conn.execute(
                "SELECT COUNT(*) AS n FROM blocked_ips WHERE active = 1"
            ).fetchone()
            browser_warn = conn.execute(
                """
                SELECT COUNT(*) AS n FROM events
                WHERE module = 'browser_guard' AND severity IN ('WARNING', 'CRITICAL')
                """
            ).fetchone()
            attack_warn = conn.execute(
                """
                SELECT COUNT(*) AS n FROM events
                WHERE module = 'attacks' AND severity IN ('WARNING', 'CRITICAL')
                """
            ).fetchone()
        return {
            "failed_logon_attempts": int(fail["n"] if fail else 0),
            "blocked_ips": int(blocked["n"] if blocked else 0),
            "browser_threat_events": int(browser_warn["n"] if browser_warn else 0),
            "attack_events": int(attack_warn["n"] if attack_warn else 0),
        }

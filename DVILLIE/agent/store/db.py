"""SQLite persistence for Fortoro Agent."""

from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
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
    ) -> int:
        ip = source_ip or "unknown"
        with self._conn() as conn:
            row = conn.execute(
                "SELECT id, count FROM failed_logons WHERE source_ip = ? ORDER BY id DESC LIMIT 1",
                (ip,),
            ).fetchone()
            if row:
                new_count = row["count"] + 1
                conn.execute(
                    "UPDATE failed_logons SET count = ?, ts = ? WHERE id = ?",
                    (new_count, utc_now(), row["id"]),
                )
                return new_count
            conn.execute(
                """
                INSERT INTO failed_logons (ts, event_id, source_ip, username, workstation, count)
                VALUES (?, ?, ?, ?, ?, 1)
                """,
                (utc_now(), event_id, ip, username, workstation),
            )
            return 1

    def get_failed_logon_count(self, source_ip: str) -> int:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT count FROM failed_logons WHERE source_ip = ? ORDER BY id DESC LIMIT 1",
                (source_ip,),
            ).fetchone()
            return int(row["count"]) if row else 0

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

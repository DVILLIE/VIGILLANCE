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


def cutoff_iso(*, days: float = 0.0, hours: float = 0.0) -> str:
    """UTC ISO timestamp for retention / report windows (lexicographic-safe)."""
    return (datetime.now(timezone.utc) - timedelta(days=days, hours=hours)).isoformat()


# Defaults match config/config.yaml retention + attacks blocks (audit #2.2).
DEFAULT_RETENTION: dict[str, int] = {
    "connections_days": 7,
    "events_days": 14,
    "health_snapshots_days": 14,
    "failed_logons_days": 30,
    "work_log_days": 14,
    "privacy_checks_days": 14,
}
DEFAULT_REVIEW_WINDOW_HOURS = 24.0
DEFAULT_SUMMARY_WINDOW_DAYS = 14.0


class AgentStore:
    def __init__(self, db_path: Path, *, initialize: bool = True) -> None:
        self.db_path = db_path
        self._initialize = initialize
        if initialize:
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
            self._init_schema()

    @contextmanager
    def _conn(self) -> Generator[sqlite3.Connection, None, None]:
        if self._initialize:
            conn = sqlite3.connect(self.db_path, timeout=30)
        else:
            # An attached console may arrive while the owner is still starting.
            # It may use the owner's existing ledger but must not create an empty
            # replacement when the database is missing or has been moved.
            conn = sqlite3.connect(self.db_path.resolve().as_uri() + "?mode=rw", uri=True, timeout=30)
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
                    passed INTEGER
                );

                CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
                CREATE INDEX IF NOT EXISTS idx_connections_ts ON connections(ts);
                CREATE INDEX IF NOT EXISTS idx_connections_suspicious_ts
                    ON connections(suspicious, ts);
                CREATE INDEX IF NOT EXISTS idx_failed_logons_ip ON failed_logons(source_ip);
                CREATE INDEX IF NOT EXISTS idx_failed_logons_ts ON failed_logons(ts);

                CREATE TABLE IF NOT EXISTS work_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts TEXT NOT NULL,
                    action TEXT NOT NULL,
                    message TEXT NOT NULL,
                    details TEXT
                );

                CREATE INDEX IF NOT EXISTS idx_work_log_ts ON work_log(ts);

                CREATE TABLE IF NOT EXISTS findings (
                    id TEXT PRIMARY KEY,
                    pillar TEXT NOT NULL,
                    kind TEXT NOT NULL,
                    subject_identity TEXT NOT NULL,
                    status TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_findings_subject
                    ON findings(pillar, subject_identity, kind, status);

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

                CREATE TABLE IF NOT EXISTS decisions (
                    decision_id TEXT PRIMARY KEY,
                    ts TEXT NOT NULL,
                    initiator TEXT,
                    action TEXT NOT NULL,
                    action_level INTEGER NOT NULL,
                    confidence REAL,
                    target TEXT,
                    reversible INTEGER,
                    rollback_plan TEXT,
                    policy_ref TEXT,
                    evidence TEXT,
                    details TEXT
                );

                CREATE INDEX IF NOT EXISTS idx_decisions_ts ON decisions(ts);
                """
            )

            # Additive migrations preserve existing installations and audit history.
            # sqlite3's legacy transaction control does not begin a transaction for
            # DDL. Explicitly include every migration step, including temporary-table
            # creation, so an interrupted rebuild cannot strand the next startup.
            conn.execute("BEGIN IMMEDIATE")
            columns = {row["name"] for row in conn.execute("PRAGMA table_info(failed_logons)")}
            for name, kind in (("record_id", "INTEGER"), ("status", "TEXT"),
                               ("event_key", "TEXT"), ("ingested_at", "TEXT")):
                if name not in columns:
                    conn.execute(f"ALTER TABLE failed_logons ADD COLUMN {name} {kind}")
            conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_failed_logons_event_key "
                         "ON failed_logons(event_key) WHERE event_key IS NOT NULL")
            cursor_columns = {row["name"] for row in conn.execute("PRAGMA table_info(agent_cursors)")}
            if "event_ts" not in cursor_columns:
                conn.execute("ALTER TABLE agent_cursors ADD COLUMN event_ts TEXT")
            privacy_columns = list(conn.execute("PRAGMA table_info(privacy_checks)"))
            if any(row["name"] == "passed" and row["notnull"] for row in privacy_columns):
                conn.execute("CREATE TABLE privacy_checks_nullable (id INTEGER PRIMARY KEY AUTOINCREMENT, "
                             "ts TEXT NOT NULL, check_name TEXT NOT NULL, expected TEXT, actual TEXT, passed INTEGER)")
                conn.execute("INSERT INTO privacy_checks_nullable SELECT * FROM privacy_checks")
                conn.execute("DROP TABLE privacy_checks")
                conn.execute("ALTER TABLE privacy_checks_nullable RENAME TO privacy_checks")

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
                    "SELECT * FROM (SELECT id, ts, action, message, details FROM work_log "
                    "ORDER BY id DESC LIMIT ?) ORDER BY id ASC",
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
                ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at,
                    event_ts = NULL
                """,
                (key, int(value), utc_now()),
            )

    def get_cursor_timestamp(self, key: str) -> str | None:
        with self._conn() as conn:
            row = conn.execute("SELECT event_ts FROM agent_cursors WHERE key = ?", (key,)).fetchone()
            return row["event_ts"] if row else None

    def ingest_security_events(
        self, events: list[dict[str, Any]], *, cursor_key: str,
        next_record_id: int, next_timestamp: str | None,
    ) -> list[dict[str, Any]]:
        """Commit failure evidence and its source cursor together; retries are idempotent.

        Identity includes source event time because Windows reuses record IDs after
        a Security-log clear. Successful/unknown 4776 rows advance the cursor but
        never count as failed authentication.
        """
        inserted: list[dict[str, Any]] = []
        with self._conn() as conn:
            for event in events:
                timestamp = datetime.fromisoformat(str(event["timestamp"]).replace("Z", "+00:00"))
                if timestamp.tzinfo is None:
                    raise ValueError("Security event timestamp must include timezone")
                ts = timestamp.astimezone(timezone.utc).isoformat()
                if not event.get("is_failure"):
                    continue
                source = event.get("source_ip") or f"host:{event.get('source_host') or 'unknown'}"
                identity = f"Security:{int(event['record_id'])}:{ts}:{int(event['event_id'])}"
                cur = conn.execute(
                    "INSERT OR IGNORE INTO failed_logons "
                    "(ts, event_id, source_ip, username, workstation, count, record_id, status, event_key, ingested_at) "
                    "VALUES (?, ?, ?, ?, ?, 1, ?, ?, ?, ?)",
                    (ts, event["event_id"], source, event.get("username"), event.get("source_host"),
                     event["record_id"], event.get("status"), identity, utc_now()),
                )
                if cur.rowcount:
                    inserted.append(event)
            conn.execute(
                "INSERT INTO agent_cursors (key, value, updated_at, event_ts) VALUES (?, ?, ?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value, "
                "updated_at=excluded.updated_at, event_ts=excluded.event_ts",
                (cursor_key, int(next_record_id), utc_now(), next_timestamp),
            )
        return inserted

    def log_decision(self, decision: dict[str, Any]) -> None:
        """Persist an issued Decision (L2 recommendation or higher) as a durable,
        first-class row the WHY surface can read — the observe→explain→recommend
        evidence chain, not an ephemeral UUID inside a log blob. Idempotent by id.
        """
        with self._conn() as conn:
            conn.execute(
                """
                INSERT INTO decisions
                (decision_id, ts, initiator, action, action_level, confidence, target,
                 reversible, rollback_plan, policy_ref, evidence, details)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(decision_id) DO NOTHING
                """,
                (
                    decision.get("decision_id"),
                    decision.get("ts") or utc_now(),
                    decision.get("initiator"),
                    decision.get("action"),
                    int(decision.get("action_level", 0)),
                    decision.get("confidence"),
                    decision.get("target"),
                    1 if decision.get("reversible") else 0,
                    decision.get("rollback_plan"),
                    decision.get("policy_ref"),
                    json.dumps(decision.get("evidence_summary") or []),
                    json.dumps(decision.get("details") or {}),
                ),
            )

    def decision_record(self, decision_id: str) -> sqlite3.Row | None:
        """The durable decisions-ledger row, or None when it was not saved."""
        if not decision_id:
            return None
        with self._conn() as conn:
            return conn.execute(
                """
                SELECT decision_id, action, action_level, target, evidence
                FROM decisions
                WHERE decision_id = ?
                """,
                (decision_id,),
            ).fetchone()

    def recent_decisions(self, limit: int = 50) -> list[sqlite3.Row]:
        with self._conn() as conn:
            return list(
                conn.execute(
                    """
                    SELECT decision_id, ts, initiator, action, action_level, confidence,
                           target, reversible, rollback_plan, policy_ref, evidence, details
                    FROM decisions
                    ORDER BY ts DESC LIMIT ?
                    """,
                    (limit,),
                ).fetchall()
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
        event_time: datetime | None = None,
    ) -> int:
        """Insert one failed-logon observation; return count inside rolling window.

        Lifetime cumulative counters were incorrect for brute-force thresholds
        (Architecture P0). Each event is a row; ``count`` column stores 1.
        """
        ip = source_ip or "unknown"
        now = (event_time.astimezone(timezone.utc).isoformat() if event_time else utc_now())
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
        now = datetime.now(timezone.utc)
        cutoff = now - timedelta(minutes=window_minutes)
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
                if cutoff <= ts <= now:
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
                    None if snapshot.get("defender_enabled") is None else int(bool(snapshot["defender_enabled"])),
                    None if snapshot.get("firewall_enabled") is None else int(bool(snapshot["firewall_enabled"])),
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
        self, check_name: str, expected: str, actual: str, passed: bool | None
    ) -> None:
        with self._conn() as conn:
            conn.execute(
                """
                INSERT INTO privacy_checks (ts, check_name, expected, actual, passed)
                VALUES (?, ?, ?, ?, ?)
                """,
                (utc_now(), check_name, expected, actual, None if passed is None else int(passed)),
            )

    def recent_suspicious_connections(
        self,
        limit: int = 50,
        *,
        window_hours: float = DEFAULT_REVIEW_WINDOW_HOURS,
    ) -> list[sqlite3.Row]:
        """FLAGGED peers in the review window — one row per (process, ip), not per pulse.

        Audit #2.2: a repeating connection must not fill the report with 60 copies of
        itself. reason comes from the group's newest row (MAX(id)), not a bare GROUP BY.
        """
        cutoff = cutoff_iso(hours=float(window_hours))
        with self._conn() as conn:
            return list(
                conn.execute(
                    """
                    SELECT
                        c.process_name AS process_name,
                        c.remote_ip AS remote_ip,
                        c.remote_addr AS remote_addr,
                        c.reason AS reason,
                        c.ts AS ts,
                        g.hits AS hits
                    FROM connections c
                    INNER JOIN (
                        SELECT process_name, remote_ip, MAX(id) AS max_id, COUNT(*) AS hits
                        FROM connections
                        WHERE suspicious = 1 AND ts >= ?
                        GROUP BY process_name, remote_ip
                    ) g ON c.id = g.max_id
                    ORDER BY c.ts DESC
                    LIMIT ?
                    """,
                    (cutoff, limit),
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
                    SELECT id, ts, event_id, source_ip, username, workstation, count, record_id, status, ingested_at
                    FROM failed_logons
                    ORDER BY id DESC LIMIT ?
                    """,
                    (limit,),
                ).fetchall()
            )

    def attack_summary(
        self, *, window_days: float = DEFAULT_SUMMARY_WINDOW_DAYS
    ) -> dict[str, Any]:
        """Historical counts windowed + labeled; blocked_ips is live state (unwindowed)."""
        now = utc_now()
        cutoff = cutoff_iso(days=float(window_days))
        with self._conn() as conn:
            fail = conn.execute(
                """
                SELECT COALESCE(SUM(count), 0) AS n FROM failed_logons
                WHERE ts >= ? AND ts <= ?
                """,
                (cutoff, now),
            ).fetchone()
            blocked = conn.execute(
                "SELECT COUNT(*) AS n FROM blocked_ips WHERE active = 1"
            ).fetchone()
            browser_warn = conn.execute(
                """
                SELECT COUNT(*) AS n FROM events
                WHERE module = 'browser_guard' AND severity IN ('WARNING', 'CRITICAL')
                  AND ts >= ?
                """,
                (cutoff,),
            ).fetchone()
            attack_warn = conn.execute(
                """
                SELECT COUNT(*) AS n FROM events
                WHERE module = 'attacks' AND severity IN ('WARNING', 'CRITICAL')
                  AND ts >= ?
                """,
                (cutoff,),
            ).fetchone()
        return {
            "failed_logon_attempts": int(fail["n"] if fail else 0),
            "blocked_ips": int(blocked["n"] if blocked else 0),
            "browser_threat_events": int(browser_warn["n"] if browser_warn else 0),
            "attack_events": int(attack_warn["n"] if attack_warn else 0),
            "summary_window_days": float(window_days),
        }

    def save_finding(self, finding: dict[str, Any]) -> None:
        payload = json.dumps(finding, sort_keys=True)
        with self._conn() as conn:
            conn.execute(
                """
                INSERT INTO findings (id, pillar, kind, subject_identity, status, payload, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    status=excluded.status,
                    payload=excluded.payload,
                    updated_at=excluded.updated_at,
                    subject_identity=excluded.subject_identity
                """,
                (
                    finding["id"],
                    finding["pillar"],
                    finding["kind"],
                    finding["subject_identity"],
                    finding["resolution_status"],
                    payload,
                    finding["updated_at"],
                ),
            )

    def get_finding(self, finding_id: str) -> dict[str, Any] | None:
        with self._conn() as conn:
            row = conn.execute("SELECT payload FROM findings WHERE id = ?", (finding_id,)).fetchone()
        if row is None:
            return None
        return json.loads(row["payload"])

    def find_active_finding(self, pillar: str, subject: str, kind: str) -> dict[str, Any] | None:
        with self._conn() as conn:
            row = conn.execute(
                """
                SELECT payload FROM findings
                WHERE pillar = ? AND subject_identity = ? AND kind = ?
                  AND status IN ('found', 'in_progress', 'monitoring')
                ORDER BY updated_at DESC LIMIT 1
                """,
                (pillar, subject, kind),
            ).fetchone()
        if row is None:
            return None
        return json.loads(row["payload"])

    def list_open_findings(self) -> list[dict[str, Any]]:
        with self._conn() as conn:
            rows = conn.execute(
                """
                SELECT payload FROM findings
                WHERE status IN ('found', 'in_progress', 'monitoring')
                ORDER BY updated_at
                """
            ).fetchall()
        return [json.loads(row["payload"]) for row in rows]

    def prune_old(self, retention: dict[str, Any] | None = None) -> dict[str, int]:
        """Age out observations. Never touches decisions / audits / blocks.

        Returns deleted-row counts per table. Safe to call from idle_deep.
        """
        cfg = {**DEFAULT_RETENTION, **(retention or {})}
        deleted: dict[str, int] = {}
        plans = (
            ("connections", int(cfg["connections_days"])),
            ("events", int(cfg["events_days"])),
            ("health_snapshots", int(cfg["health_snapshots_days"])),
            ("failed_logons", int(cfg["failed_logons_days"])),
            ("work_log", int(cfg["work_log_days"])),
            ("privacy_checks", int(cfg["privacy_checks_days"])),
        )
        with self._conn() as conn:
            for table, days in plans:
                if days <= 0:
                    deleted[table] = 0
                    continue
                cutoff = cutoff_iso(days=float(days))
                cur = conn.execute(f"DELETE FROM {table} WHERE ts < ?", (cutoff,))
                deleted[table] = int(cur.rowcount or 0)
        return deleted

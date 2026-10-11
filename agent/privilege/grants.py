"""One-use scoped grants. Production requires protected Windows storage.

The grant-issuing method is never exposed by the resident pipe protocol.
Test adapters are expressly non-elevated and confer no production authority.
"""
from __future__ import annotations

import hashlib
import json
import math
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path
from uuid import uuid4

from agent.privilege.contract import DEFINED_OP, validate_restrict_params
from agent.privilege.helper import _is_elevated
from agent.privilege.pipe import build_pipe_sddl
from agent.privilege.protected_paths import assert_protected_path
from agent.privilege.target import executable_lease


def request_digest(params: dict) -> str:
    return hashlib.sha256(json.dumps(params, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()).hexdigest()


class GrantStore:
    def __init__(self, directory: Path, user_sid: str, *, test_harness: bool = False):
        build_pipe_sddl(user_sid)
        self.directory = Path(directory)
        self.user_sid = user_sid
        self.test_harness = test_harness
        self._preflight()
        self.directory.mkdir(parents=True, exist_ok=True)
        self.db = self.directory / "authorization.db"
        if self.db.exists() and not test_harness:
            assert_protected_path(self.db)
        with self._conn() as conn:
            conn.execute("CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
            schema = conn.execute("SELECT value FROM metadata WHERE key='schema_version'").fetchone()
            if schema is not None and schema[0] != '1':
                raise ValueError("Unsupported protected authorization schema.")
            conn.execute("INSERT OR IGNORE INTO metadata VALUES ('schema_version', '1')")
            row = conn.execute("SELECT value FROM metadata WHERE key='installed_user'").fetchone()
            if row is not None and row[0] != user_sid:
                raise PermissionError("The protected store belongs to another installation user.")
            conn.execute("INSERT OR IGNORE INTO metadata VALUES ('installed_user', ?)", (user_sid,))
            conn.execute("CREATE TABLE IF NOT EXISTS grants (id TEXT PRIMARY KEY, op TEXT NOT NULL, "
                         "request_hash TEXT NOT NULL, identity TEXT NOT NULL, issued REAL NOT NULL, "
                         "expires REAL NOT NULL, state TEXT NOT NULL)")
            conn.execute("CREATE TABLE IF NOT EXISTS operations (id TEXT PRIMARY KEY, grant_id TEXT UNIQUE NOT NULL, "
                         "params TEXT NOT NULL, state TEXT NOT NULL, result TEXT)")

    def _preflight(self):
        if self.test_harness:
            if _is_elevated():
                raise PermissionError("Test authorization stores refuse elevated tokens.")
        else:
            assert_protected_path(self.directory)
            for child in self.directory.iterdir():
                assert_protected_path(child)

    @contextmanager
    def _conn(self):
        self._preflight()
        if self.db.exists() and not self.test_harness:
            assert_protected_path(self.db)
        connection = sqlite3.connect(self.db, timeout=5, isolation_level=None)
        try:
            connection.execute("PRAGMA synchronous=FULL")
            connection.execute("PRAGMA journal_mode=DELETE")
            connection.execute("BEGIN IMMEDIATE")
            yield connection
            connection.commit()
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()

    def issue(self, params: dict, *, ttl: float = 300) -> str:
        if not self.test_harness and not _is_elevated():
            raise PermissionError("Only the protected administrative approval path issues grants.")
        checked, error = validate_restrict_params(params)
        if checked is None:
            raise ValueError(error)
        if type(ttl) not in {int, float} or not math.isfinite(ttl) or not 0 < ttl <= 300:
            raise ValueError("One-use authorization expires within five minutes.")
        with executable_lease(checked["program"], test_harness=self.test_harness) as identity:
            now = time.time()
            grant_id = uuid4().hex
            with self._conn() as conn:
                conn.execute("INSERT INTO grants VALUES (?,?,?,?,?,?,?)", (grant_id, DEFINED_OP,
                    request_digest(checked), json.dumps(identity, sort_keys=True), now, now + ttl, "available"))
            return grant_id

    def claim(self, grant_id: str, peer_sid: str, params: dict, identity: dict) -> str:
        if peer_sid != self.user_sid:
            raise PermissionError("The OS-authenticated peer is not the installed user.")
        checked, error = validate_restrict_params(params)
        if checked is None:
            raise ValueError(error)
        with self._conn() as conn:
            row = conn.execute("SELECT op,request_hash,identity,issued,expires,state FROM grants WHERE id=?",
                               (grant_id,)).fetchone()
            now = time.time()
            if (row is None or row[0] != DEFINED_OP or row[1] != request_digest(checked)
                    or row[2] != json.dumps(identity, sort_keys=True) or not row[3] <= now < row[4]
                    or row[5] != "available"):
                raise PermissionError("Authorization is missing, stale, used or bound to another request/executable.")
            operation_id = uuid4().hex
            conn.execute("UPDATE grants SET state='consumed' WHERE id=?", (grant_id,))
            conn.execute("INSERT INTO operations VALUES (?,?,?,?,NULL)",
                         (operation_id, grant_id, json.dumps(checked, sort_keys=True), "intent_durable"))
        return operation_id

    def revoke(self, grant_id: str):
        if not self.test_harness and not _is_elevated():
            raise PermissionError("Administrative authorization is required for revocation.")
        with self._conn() as conn:
            conn.execute("UPDATE grants SET state='revoked' WHERE id=? AND state='available'", (grant_id,))

    def finish(self, operation_id: str, result: dict):
        state = "configuration_verified" if result.get("ok") is True else "outcome_unknown"
        with self._conn() as conn:
            changed = conn.execute("UPDATE operations SET state=?,result=? WHERE id=? AND state='intent_durable'",
                (state, json.dumps(result, allow_nan=False), operation_id)).rowcount
            if changed != 1:
                raise ValueError("The operation is unknown or already finalized.")

    def pending(self) -> list[dict]:
        with self._conn() as conn:
            rows = conn.execute("SELECT id,state,params FROM operations WHERE state IN ('intent_durable','outcome_unknown')").fetchall()
        return [{"id": row[0], "state": row[1], "params": json.loads(row[2])} for row in rows]

    def operation(self, operation_id: str) -> dict:
        with self._conn() as conn:
            row = conn.execute("SELECT state,params FROM operations WHERE id=?", (operation_id,)).fetchone()
        if row is None:
            raise ValueError("Unknown protected operation.")
        return {"id": operation_id, "state": row[0], "params": json.loads(row[1])}

    def record_recovery(self, operation_id: str, result: dict):
        if not self.test_harness and not _is_elevated():
            raise PermissionError("Administrative authorization is required for recovery.")
        state = "restored" if result.get("ok") is True else "outcome_unknown"
        with self._conn() as conn:
            changed = conn.execute("UPDATE operations SET state=?,result=? WHERE id=?",
                (state, json.dumps(result, allow_nan=False), operation_id)).rowcount
            if changed != 1:
                raise ValueError("Unknown protected operation.")

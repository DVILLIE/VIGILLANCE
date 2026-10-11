"""Explicit, previewed history deletion. Automatic retention defaults off."""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

from agent.local_files import file_lock

TERMINAL_STATES = ('completed', 'failed', 'stopped', 'interrupted')
MAX_DELETE_BATCH = 200


def validate_policy(policy: object) -> dict:
    if not isinstance(policy, dict) or set(policy) != {'enabled', 'days', 'max_runs'}:
        raise ValueError('Retention policy must declare enabled, days and max_runs.')
    if (type(policy['enabled']) is not bool or type(policy['days']) is not int
            or not 1 <= policy['days'] <= 3650 or type(policy['max_runs']) is not int
            or not 1 <= policy['max_runs'] <= 10000):
        raise ValueError('Invalid retention policy values.')
    return dict(policy)


class HistoryPrivacy:
    def __init__(self, engine):
        self.engine = engine

    def policy(self) -> dict:
        with self.engine._conn() as conn:
            row = conn.execute("SELECT value FROM assessment_settings WHERE key='retention'").fetchone()
        return validate_policy(json.loads(row[0])) if row else {'enabled': False, 'days': 30, 'max_runs': 100}

    def set_policy(self, policy: dict):
        checked = validate_policy(policy)
        with file_lock(self.engine.directory / 'assessment.lock', timeout=0.1):
            with self.engine._conn() as conn:
                conn.execute("INSERT OR REPLACE INTO assessment_settings VALUES ('retention', ?)",
                             (json.dumps(checked),))

    def preview(self, *, policy: dict | None = None) -> dict:
        checked = validate_policy(policy) if policy is not None else self.policy()
        cutoff = (datetime.now(timezone.utc) - timedelta(days=checked['days'])).isoformat()
        with self.engine._conn() as conn:
            # Terminal runs only; a running or ambiguous state is never selected.
            rows = conn.execute("SELECT id FROM runs WHERE state IN (?,?,?,?) AND finished IS NOT NULL "
                "AND (finished < ? OR id IN (SELECT id FROM runs WHERE state IN (?,?,?,?) "
                "AND finished IS NOT NULL ORDER BY started DESC,id DESC LIMIT -1 OFFSET ?)) "
                "ORDER BY started,id LIMIT ?", (*TERMINAL_STATES, cutoff, *TERMINAL_STATES,
                                              checked['max_runs'], MAX_DELETE_BATCH)).fetchall()
        return {'policy': checked, 'ids': [row[0] for row in rows], 'batch_limit': MAX_DELETE_BATCH,
                'meaning': 'Candidate completed/partial history records only; exports and backups are not removed.'}

    def delete(self, run_ids: list[str]) -> dict:
        if (not isinstance(run_ids, list) or not 1 <= len(run_ids) <= MAX_DELETE_BATCH
                or any(not isinstance(value, str) or not value or len(value) > 128 for value in run_ids)
                or len(set(run_ids)) != len(run_ids)):
            raise ValueError('Choose a bounded set of distinct history records.')
        with file_lock(self.engine.directory / 'assessment.lock', timeout=0.1):
            with self.engine._conn() as conn:
                conn.execute('PRAGMA secure_delete=ON')
                conn.execute('BEGIN IMMEDIATE')
                placeholders = ','.join('?' for _ in run_ids)
                rows = conn.execute(f'SELECT id,state FROM runs WHERE id IN ({placeholders})', run_ids).fetchall()
                if len(rows) != len(run_ids) or any(state not in TERMINAL_STATES for _, state in rows):
                    raise ValueError('A selected record changed, disappeared or is still running; nothing was deleted.')
                changed = conn.execute(f'DELETE FROM runs WHERE id IN ({placeholders})', run_ids).rowcount
                if changed != len(run_ids):
                    raise ValueError('The selected deletion was incomplete; the transaction was rolled back.')
        return {'deleted': len(run_ids), 'ids': list(run_ids), 'secure_erasure_claimed': False,
                'message': 'Selected database records deleted. Exports, backups, filesystem snapshots and storage-device copies remain separate.'}

    def maintain_locked(self, *, preserve_run_id: str) -> dict:
        """Called only by a run already holding assessment.lock, after saving.

        This shares the same transaction contract as explicit deletion, without
        reacquiring the non-reentrant OS lock. It never deletes a current run.
        """
        policy = self.policy()
        if not policy['enabled']:
            return {'deleted': 0, 'enabled': False}
        selected = [run_id for run_id in self.preview(policy=policy)['ids'] if run_id != preserve_run_id]
        if not selected:
            return {'deleted': 0, 'enabled': True}
        with self.engine._conn() as conn:
            conn.execute('PRAGMA secure_delete=ON')
            conn.execute('BEGIN IMMEDIATE')
            placeholders = ','.join('?' for _ in selected)
            changed = conn.execute(f'DELETE FROM runs WHERE id IN ({placeholders}) AND state IN (?,?,?,?)',
                         (*selected, *TERMINAL_STATES)).rowcount
        return {'deleted': changed, 'enabled': True, 'secure_erasure_claimed': False}

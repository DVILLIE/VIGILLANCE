"""Shared observation envelopes and bounded freshness for saved assessments."""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone

from agent.evidence import Observation

FRESHNESS_SECONDS = 300  # Product review policy, not a calibrated probability.


def digest(payload) -> str:
    return hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(',', ':'),
                                     allow_nan=False).encode('utf-8')).hexdigest()


def update_evidence(report: dict):
    records = report.setdefault('evidence_records', {})
    sources = [('observations.' + key, key, payload) for key, payload in report['observations'].items()]
    if 'target' in report.get('scope', {}):
        sources.append(('scope.target', 'target', report['scope']['target']))
    live_paths = {path for path, _, _ in sources}
    for path in list(records):
        if path not in live_paths:
            del records[path]  # Removed/private export fields must leave no raw hash behind.
    for path, key, payload in sources:
        checksum = digest(payload)
        previous = records.get(path)
        if previous and previous['payload']['sha256'] == checksum:
            continue
        record = Observation.make('assessment.' + key,
            {'source_path': path, 'sha256': checksum, 'coverage': coverage(key, payload),
             'meaning': 'Checkpoint record of this run; not a continuous sensor or tamper-proof attestation.'},
            entity=report['id'], cadence='pulse')
        records[path] = record.to_dict()
    for item in report['findings']:
        item['evidence_ids'] = []
        for reference in item.get('evidence_refs', []):
            match = next((record for path, record in records.items()
                          if reference == path or reference.startswith(path + '.')), None)
            if match:
                item['evidence_ids'].append(match['id'])


def coverage(key: str, payload) -> str:
    if isinstance(payload, dict):
        if payload.get('state') in {'unavailable', 'not_queried', 'not_evaluated'}:
            return payload['state']
        if key == 'windows_posture':
            health = payload.get('defender_health', {})
            asr = payload.get('asr_cfa', {})
            return 'partial' if (payload.get('firewall_enabled') is None
                or health.get('coverage') != 'complete' or asr.get('coverage') != 'complete') else 'observed'
        if key == 'assessment_resources':
            return payload.get('coverage', 'partial')
    return 'observed'


def freshness(report: dict, *, now: datetime | None = None) -> dict:
    now = now if now is not None else datetime.now(timezone.utc)
    try:
        started = datetime.fromisoformat(report['started'])
        if started.tzinfo is None or now.tzinfo is None:
            raise ValueError('Timezone required')
        age = (now - started).total_seconds()
        state = 'clock_uncertain' if age < 0 else 'recent_snapshot' if age <= FRESHNESS_SECONDS else 'stale_snapshot'
        return {'state': state, 'age_seconds_from_start': max(0, age) if age >= 0 else None,
                'review_policy_seconds': FRESHNESS_SECONDS,
                'meaning': 'Age from run start is conservative; recent snapshots do not establish current enforcement.'}
    except (KeyError, ValueError, TypeError):
        return {'state': 'unknown', 'age_seconds_from_start': None, 'review_policy_seconds': FRESHNESS_SECONDS}


def resolution_plan(report: dict) -> dict:
    status = freshness(report)
    records = report.get('evidence_records', {})
    known = {record['id']: record for record in records.values()}
    verified_ids = set()
    for path, record in records.items():
        if path.startswith('observations.'):
            key = path.removeprefix('observations.')
            present = key in report.get('observations', {})
            value = report.get('observations', {}).get(key)
        elif path == 'scope.target':
            present = 'target' in report.get('scope', {})
            value = report.get('scope', {}).get('target')
        else:
            present, value = False, None
        try:
            matches = present and record['payload'].get('source_path') == path and record['payload'].get('sha256') == digest(value)
        except (ValueError, TypeError):
            matches = False
        if matches:
            verified_ids.add(record['id'])
    ordered = []
    for item in report.get('findings', []):
        evidence_ids = item.get('evidence_ids', [])
        supported = bool(evidence_ids) and all(identifier in verified_ids for identifier in evidence_ids)
        unavailable = any(known[identifier]['payload']['coverage'] in {'unavailable', 'not_queried', 'not_evaluated'}
                          for identifier in evidence_ids if identifier in known)
        ordered.append({'finding_id': item['id'], 'priority': 'review_evidence_first' if not supported or unavailable
                        or status['state'] != 'recent_snapshot'
                        else 'high' if item.get('severity') == 'high' else 'review',
                        'observation': item['observation'], 'recommendation': item['resolution'],
                        'evidence_ids': evidence_ids, 'freshness': status['state'],
                        'evidence_integrity': 'matching_snapshot_digest' if supported else 'missing_or_mismatched',
                        'authorization': 'none', 'executed': False,
                        'required_before_action': ['Reobserve the exact target and relevant control.',
                            'Review scope, disruption and recovery.', 'Obtain the operation-specific approval.']})
    ranks = {'high': 0, 'review_evidence_first': 1, 'review': 2}
    ordered.sort(key=lambda row: ranks[row['priority']])
    return {'freshness': status, 'items': ordered,
            'claims': 'Evidence-linked review order only; no exploitability score, attack-path proof or action permission.'}

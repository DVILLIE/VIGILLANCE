"""Evidence/freshness contracts; fixture findings are not real vulnerabilities."""
from datetime import datetime, timedelta, timezone

from agent.assessment import AssessmentEngine
from agent.assessment.engine import finding
from agent.assessment.evidence import digest, freshness, resolution_plan, update_evidence


def report():
    return {'id': 'contract-run', 'started': datetime.now(timezone.utc).isoformat(),
            'scope': {'target': 'local'}, 'state': 'completed',
            'observations': {'listeners': [], 'dependency_review': {'state': 'not_queried'}},
            'findings': [finding('listener', 'review', 'Contract listener finding', 'Review its intended scope.')],
            'coverage': [], 'mutations': []}


def test_shared_observation_and_stable_checkpoint_identity():
    data = report()
    update_evidence(data)
    item = data['evidence_records']['observations.listeners']
    assert item['sensor'] == 'assessment.listeners'
    assert item['entity'] == data['id']
    assert item['payload']['sha256'] == digest([])
    assert data['findings'][0]['evidence_ids'] == [item['id']]
    update_evidence(data)
    assert data['evidence_records']['observations.listeners'] == item
    data['observations']['listeners'] = [{'port': 123}]
    update_evidence(data)
    assert data['findings'][0]['evidence_ids'] != [item['id']]


def test_unqueried_or_missing_evidence_cannot_authorize_or_score():
    data = report()
    data['findings'].append(finding('dependency', 'high', 'Contract applicability', 'Obtain actual evidence.'))
    data['findings'].append(finding('unknown', 'high', 'Unsupported contract finding', 'Reobserve.'))
    update_evidence(data)
    plan = resolution_plan(data)
    assert all(item['authorization'] == 'none' and item['executed'] is False for item in plan['items'])
    assert plan['items'][0]['priority'] == 'review_evidence_first'
    assert plan['items'][1]['priority'] == 'review_evidence_first'
    assert 'score' not in plan


def test_snapshot_age_is_conservative_and_clock_reversal_unknown():
    now = datetime.now(timezone.utc)
    assert freshness({'started': (now-timedelta(seconds=301)).isoformat()}, now=now)['state'] == 'stale_snapshot'
    assert freshness({'started': (now-timedelta(seconds=30)).isoformat()}, now=now)['state'] == 'recent_snapshot'
    assert freshness({'started': (now+timedelta(seconds=30)).isoformat()}, now=now)['state'] == 'clock_uncertain'
    assert freshness({'started': 'bad'}, now=now)['state'] == 'unknown'
    assert freshness({'started': now.replace(tzinfo=None).isoformat()}, now=now)['state'] == 'unknown'


def test_stale_or_future_high_finding_requires_reobservation():
    for offset in (-301, 30):
        data = report()
        data['started'] = (datetime.now(timezone.utc) + timedelta(seconds=offset)).isoformat()
        data['findings'][0]['severity'] = 'high'
        update_evidence(data)
        item = resolution_plan(data)['items'][0]
        assert item['priority'] == 'review_evidence_first'
        assert item['authorization'] == 'none'


def test_modified_observation_cannot_reuse_previous_high_priority_evidence():
    data = report()
    data['findings'][0]['severity'] = 'high'
    update_evidence(data)
    assert resolution_plan(data)['items'][0]['priority'] == 'high'
    data['observations']['listeners'] = [{'port': 456}]
    item = resolution_plan(data)['items'][0]
    assert item['priority'] == 'review_evidence_first'
    assert item['evidence_integrity'] == 'missing_or_mismatched'
    update_evidence(data)
    assert resolution_plan(data)['items'][0]['evidence_integrity'] == 'matching_snapshot_digest'


def test_redacted_export_rederives_private_payload_digests(tmp_path):
    import json
    engine = AssessmentEngine(tmp_path / 'ledger')
    data = report()
    data['scope']['authority'] = 'private authority'
    data['observations']['listeners'] = [{'address': '127.0.0.1', 'pid': 456, 'port': 123,
        'owner_identity': {'state': 'observed', 'name': 'private-process-name', 'created_epoch_seconds': 12345}}]
    data['observations']['resolved_addresses'] = ['192.0.2.1']
    data['observations']['connected_address'] = '192.0.2.1'
    update_evidence(data)
    raw_hash = data['evidence_records']['observations.listeners']['payload']['sha256']
    orphan_hash = data['evidence_records']['observations.resolved_addresses']['payload']['sha256']
    engine._save(data, insert=True)
    output = tmp_path / 'redacted.json'
    engine.export(data['id'], output)
    exported = json.loads(output.read_text())
    assert raw_hash not in output.read_text()
    assert 'private-process-name' not in output.read_text()
    assert '12345' not in output.read_text()
    assert orphan_hash not in output.read_text()
    assert 'observations.resolved_addresses' not in exported['evidence_records']
    assert 'observations.connected_address' not in exported['evidence_records']
    evidence = exported['evidence_records']['observations.listeners']
    assert evidence['payload']['sha256'] == digest(exported['observations']['listeners'])
    assert exported['findings'][0]['evidence_ids'] == [evidence['id']]
    assert engine.report(data['id'])['evidence_records']['observations.listeners']['payload']['sha256'] == raw_hash

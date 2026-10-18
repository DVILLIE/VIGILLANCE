"""Regression contracts; fixtures are not live attack acceptance evidence."""
import copy
import json
import os
from datetime import datetime, timezone

import pytest
from agent.assessment.attack_paths import investigation_paths
from agent.assessment.evidence import update_evidence


def snapshot():
    value = {'id':'test-case', 'started':datetime.now(timezone.utc).isoformat(), 'findings':[],
             'scope':{'target':'local'}, 'observations':{'listeners':[
                 {'address':'0.0.0.0','port':8080,'owner_identity':{'state':'observed'}},
                 {'address':'::','port':8080,'owner_identity':{'state':'unavailable'}}],
                 'windows_posture':{'firewall_enabled':False,'realtime_enabled':None,'asr_cfa':{'cfa_mode':0}}}}
    update_evidence(value)
    return value


def test_routes_share_control_reviews_without_claiming_prevention_or_authority():
    result = investigation_paths(snapshot())
    assert len(result['paths']) == 4
    assert result['investigation_order'][0]['id'] == 'review_listener_scope'
    assert result['investigation_order'][0]['newly_covered_route_count'] == 2
    assert not result['uncovered_route_ids']
    assert all(row['exploitability'] == 'not_established' for row in result['paths'])
    assert all(row['authorization'] == 'none' and row['executed'] is False for row in result['investigation_order'])


def test_changed_observations_and_old_snapshots_abstain():
    report = snapshot()
    report['observations']['listeners'][0]['port'] = 444
    graph = investigation_paths(report)
    assert all(row['state'] == 'reobserve_first' and not row['evidence_ids']
               for row in graph['paths'] if row['kind'] == 'network_to_listener')
    report['started'] = '2000-01-01T00:00:00+00:00'
    assert all(row['state'] == 'reobserve_first' for row in investigation_paths(report)['paths'])


@pytest.mark.skipif(os.name != 'nt', reason='Actual user-DPAPI key persistence requires Windows')
def test_actual_dpapi_persisted_signature_rejects_changes_and_substituted_signer(tmp_path):
    from agent.assessment.signatures import sign_report, verify_report
    from cryptography.exceptions import InvalidSignature
    path = tmp_path / 'report.json'
    path.write_text('{"scope":"local"}')
    first = sign_report(path, tmp_path / 'security')
    second = sign_report(path, tmp_path / 'security')
    assert first['key_fingerprint'] == second['key_fingerprint']
    assert verify_report(path, first, first['key_fingerprint'])['state'] == 'trusted_report_signature_verified'
    substituted = sign_report(path, tmp_path / 'other-security')
    with pytest.raises(ValueError, match='Untrusted'):
        verify_report(path, substituted, first['key_fingerprint'])
    tampered = copy.deepcopy(first)
    tampered['signed']['created_at'] = '2000-01-01T00:00:00+00:00'
    with pytest.raises(InvalidSignature):
        verify_report(path, tampered, first['key_fingerprint'])
    path.write_text('{"scope":"changed"}')
    with pytest.raises(ValueError, match='differs'):
        verify_report(path, first, first['key_fingerprint'])
    assert len((tmp_path / 'security/report-signing-key.dpapi').read_bytes()) > 32


def test_model_provenance_mismatch_and_missing_weights_never_authorize_execution(tmp_path):
    from agent.assessment.model_admission import inspect_candidate
    manifest = {'model_id':'regression-fixture','revision':'a'*40,'license':'Apache-2.0',
                'required_memory_bytes':1024,'artifacts':[{'filename':'weights.safetensors','sha256':'a'*64,'bytes':1}]}
    result = inspect_candidate(manifest, tmp_path)
    assert result['state'] == 'execution_held'
    assert result['artifacts_verified'] is False and result['execution_authorized'] is False
    (tmp_path / 'weights.safetensors').write_bytes(b'x')
    with pytest.raises(ValueError, match='differs'):
        inspect_candidate(manifest, tmp_path)
    manifest['artifacts'][0]['filename'] = '../outside.safetensors'
    with pytest.raises(ValueError, match='Unsafe'):
        inspect_candidate(manifest, tmp_path)


@pytest.mark.skipif(os.name != 'nt', reason='Actual Windows user-DPAPI lifecycle')
def test_real_key_rotation_revocation_and_conditional_update(tmp_path):
    from agent.assessment.signatures import (sign_report, verify_local_report,
                                             rotate_report_key, report_key_status)
    report = tmp_path / 'report.json'
    report.write_text('{"scope":"local lifecycle acceptance"}')
    directory = tmp_path / 'keys'
    first = sign_report(report, directory)
    before = (directory / 'report-signing-key.dpapi').read_bytes()
    with pytest.raises(ValueError, match='differs'):
        rotate_report_key(directory, '0' * 64)
    assert (directory / 'report-signing-key.dpapi').read_bytes() == before
    rotation = rotate_report_key(directory, first['key_fingerprint'])
    second = sign_report(report, directory)
    assert second['key_fingerprint'] == rotation['key_fingerprint'] != first['key_fingerprint']
    assert verify_local_report(report, first, directory)['signer_lifecycle'] == 'retired'
    assert verify_local_report(report, second, directory)['signer_lifecycle'] == 'active'
    rotate_report_key(directory, second['key_fingerprint'], revoke_previous=True)
    with pytest.raises(ValueError, match='revoked'):
        verify_local_report(report, second, directory)
    third = sign_report(report, directory)
    assert verify_local_report(report, third, directory)['signer_lifecycle'] == 'active'
    assert len(report_key_status(directory)['retired']) == 2
    assert not list(directory.glob('*.dpapi.dpapi'))


@pytest.mark.skipif(os.name != 'nt', reason='Actual Windows legacy seed migration')
def test_existing_dpapi_seed_migrates_only_on_explicit_rotation(tmp_path):
    import win32crypt
    from agent.assessment.signatures import CONTEXT, sign_report, rotate_report_key
    from cryptography.hazmat.primitives.asymmetric.mldsa import MLDSA65PrivateKey
    directory = tmp_path / 'keys'; directory.mkdir()
    key = MLDSA65PrivateKey.generate()
    encrypted = win32crypt.CryptProtectData(key.private_bytes_raw(), 'legacy acceptance', CONTEXT, None, None, 1)
    key_path = directory / 'report-signing-key.dpapi'; key_path.write_bytes(encrypted)
    report = tmp_path / 'report.json'; report.write_text('{"local":true}')
    original = sign_report(report, directory)
    assert key_path.read_bytes() == encrypted
    rotated = rotate_report_key(directory, original['key_fingerprint'])
    assert sign_report(report, directory)['key_fingerprint'] == rotated['key_fingerprint']

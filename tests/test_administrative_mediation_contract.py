"""Closed request validation. These are contract inputs, not live OS acceptance."""
import os
from pathlib import Path
import pytest
from agent.privilege.mediation import check_request


def test_receipt_is_beneath_inspectable_installed_application():
    from agent.privilege import mediation
    destination = mediation.receipt_path('1' * 32)
    assert destination.parent == Path(mediation.__file__).resolve().parents[2]
    assert destination.name == 'DVielleConsent-' + '1' * 32 + '.json'


def request(action='recover', payload=None):
    return {'v': 1, 'action': action, 'nonce': '1' * 32, 'caller_pid': os.getpid(),
            'caller_created': 1.0, 'payload': payload or {'operation_id': '2' * 32}}


def test_closed_request_refuses_identity_or_command_overrides():
    for field in ('sid', 'is_admin', 'command', 'runner', 'directory'):
        value = request()
        value[field] = 'untrusted'
        with pytest.raises(ValueError):
            check_request(value)


@pytest.mark.parametrize('action', ['install', 'stop_defender', 'shell', 'approve_and_apply', [], None])
def test_undefined_administrative_actions_are_refused(action):
    with pytest.raises(ValueError):
        check_request(request(action))


@pytest.mark.parametrize('operation', ['../outside', '2' * 31, 'G' * 32, '2' * 32 + ';whoami', None])
def test_recovery_requires_exact_operation(operation):
    with pytest.raises(ValueError):
        check_request(request(payload={'operation_id': operation}))


def test_approval_normalizes_scope_for_existing_real_file(tmp_path):
    # The fixture is only a path for schema validation; it grants no OS permission.
    path = tmp_path / 'contract-path.exe'
    path.write_bytes(b'not an executable; no process is launched')
    params = {'program': str(path), 'profile': 'Private',
              'address_families': ['IPv4'], 'remote_addresses': ['192.0.2.1']}
    checked = check_request(request('approve', {'params': params}))
    assert checked['remote_addresses'] == ['192.0.2.1/32']
    assert checked['program'] == str(path)

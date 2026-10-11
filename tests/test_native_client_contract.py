"""Client routing and outcome reporting; no host mutation or SYSTEM service."""
import pytest

from agent.privilege import broker, native_client
from agent.engine.net_block import block_app_network


@pytest.fixture
def params(tmp_path):
    program = tmp_path / 'fixture.exe'
    program.write_bytes(b'contract fixture')
    return {'program': str(program), 'profile': 'Public', 'address_families': ['IPv4'],
            'remote_addresses': ['192.0.2.1/32']}


def test_native_route_requires_local_gate_and_server_grant(monkeypatch, params):
    calls = []
    monkeypatch.setattr(native_client, 'submit', lambda checked, grant: calls.append((checked, grant)) or
                        {'ok': True, 'performed': True, 'code': 'ok'})
    monkeypatch.setattr(broker, 'cortex_mutate_active', lambda: False)
    assert broker.submit_restrict_network(params, endpoint=None, grant_id='a'*32)['code'] == 'refused'
    assert not calls
    monkeypatch.setattr(broker, 'cortex_mutate_active', lambda: True)
    assert broker.submit_restrict_network(params, endpoint=None, grant_id='a'*32)['ok']
    assert calls == [(params, 'a'*32)]


def test_lost_service_reply_cannot_be_reported_as_no_change(monkeypatch, params):
    monkeypatch.setattr(broker, 'cortex_mutate_active', lambda: True)
    def fail(*args):
        raise TimeoutError('lost reply')
    monkeypatch.setattr(native_client, 'submit', fail)
    ok, message = block_app_network('fixture.exe', params['program'], grant_id='a'*32)
    assert not ok
    assert 'unknown' in message
    assert 'Traffic was not stopped' not in message


def test_failed_operation_is_not_success_even_if_performed(monkeypatch, params):
    monkeypatch.setattr(broker, 'submit_restrict_network', lambda *args, **kwargs:
                        {'ok': False, 'performed': True, 'message': 'Configuration verification failed.'})
    assert block_app_network('fixture.exe', params['program'])[0] is False


@pytest.mark.parametrize('timeout', [False, 0, float('nan'), 31])
def test_client_rejects_unbounded_exchange(params, timeout):
    with pytest.raises(ValueError):
        native_client.submit(params, 'a'*32, timeout=timeout)


def test_client_requires_exact_grant(params):
    with pytest.raises(ValueError):
        native_client.submit(params, 'fake consent')

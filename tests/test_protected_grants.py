"""Non-elevated contract checks; injected execution is not host enforcement."""
import json
from concurrent.futures import ThreadPoolExecutor

import pytest

from agent.privilege.grants import GrantStore
from agent.privilege.native_channel import ReceivedRequest
from agent.privilege.service_dispatch import ServiceDispatcher
from agent.privilege.target import executable_lease
from agent.modules.firewall_apply import rule_names

SID = 'S-1-5-21-111-222-333-1001'


@pytest.fixture
def setup(tmp_path):
    program = tmp_path / 'program.exe'
    program.write_bytes(b'contract fixture, not executable malware')
    params = {'program': str(program), 'profile': 'Public',
              'address_families': ['IPv4'], 'remote_addresses': ['192.0.2.1/32']}
    store = GrantStore(tmp_path / 'state', SID, test_harness=True)
    return store, params


def request(grant, params, sid=SID):
    return ReceivedRequest({'sid': sid, 'identity_source': 'Windows pipe client token'},
                           {'v': 1, 'op': 'restrict_network', 'grant_id': grant, 'params': params})


def identity(params):
    with executable_lease(params['program'], test_harness=True) as observed:
        return observed


@pytest.mark.requires_unelevated
def test_consumption_and_intent_are_durable_and_single_use(setup):
    store, params = setup
    grant = store.issue(params)
    operation = store.claim(grant, SID, params, identity(params))
    reopened = GrantStore(store.directory, SID, test_harness=True)
    assert reopened.pending() == [{'id': operation, 'state': 'intent_durable', 'params': params}]
    with pytest.raises(PermissionError):
        reopened.claim(grant, SID, params, identity(params))


@pytest.mark.requires_unelevated
@pytest.mark.parametrize('alteration', ['scope', 'identity', 'sid', 'expired', 'revoked'])
def test_grant_rejects_changed_authority(setup, alteration):
    store, params = setup
    grant = store.issue(params)
    observed = identity(params)
    sid = SID
    if alteration == 'scope':
        params = dict(params, profile='Private')
    elif alteration == 'identity':
        observed = dict(observed, sha256='0' * 64)
    elif alteration == 'sid':
        sid = 'S-1-5-21-111-222-333-1002'
    elif alteration == 'expired':
        with store._conn() as conn:
            conn.execute('UPDATE grants SET expires=0 WHERE id=?', (grant,))
    else:
        store.revoke(grant)
    with pytest.raises(PermissionError):
        store.claim(grant, sid, params, observed)
    assert store.pending() == []


@pytest.mark.requires_unelevated
def test_concurrent_claims_have_one_winner(setup):
    store, params = setup
    grant = store.issue(params)
    observed = identity(params)
    def claim(_):
        try:
            return store.claim(grant, SID, params, observed)
        except PermissionError:
            return None
    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(claim, range(4)))
    assert sum(value is not None for value in results) == 1
    assert len(store.pending()) == 1


@pytest.mark.requires_unelevated
def test_installation_user_and_schema_are_bound(setup):
    store, _ = setup
    with pytest.raises(PermissionError):
        GrantStore(store.directory, 'S-1-5-21-111-222-333-1002', test_harness=True)
    with store._conn() as conn:
        conn.execute("UPDATE metadata SET value='999' WHERE key='schema_version'")
    with pytest.raises(ValueError):
        GrantStore(store.directory, SID, test_harness=True)


@pytest.mark.requires_unelevated
def test_dispatch_durable_before_runner_and_replay_refused(setup):
    store, params = setup
    calls = []
    def runner(script):
        pending = store.pending()
        assert len(pending) == 1
        journal = json.loads((store.directory / (pending[0]['id'] + '.firewall.json')).read_text())
        assert journal['state'] == 'intent_durable'
        calls.append(script)
        name = rule_names(params['program'], 'Public', ['IPv4'], ['192.0.2.1/32'])[0][0]
        return (f"VERIFY:{name}|True|Outbound|Block|Public|derived|{params['program']}|"
                f"192.0.2.1/32|DVielle|DVielle invocation {journal['ownership_token']}\nSTATUS:OK"), False
    dispatcher = ServiceDispatcher(store, runner=runner)
    req = request(store.issue(params), params)
    assert dispatcher.dispatch(req)['ok'] is True
    assert dispatcher.dispatch(req)['code'] == 'unauthorized'
    assert len(calls) == 1
    assert store.pending() == []


@pytest.mark.requires_unelevated
def test_crash_intent_blocks_other_mutations(setup):
    store, params = setup
    store.claim(store.issue(params), SID, params, identity(params))
    dispatcher = ServiceDispatcher(store, runner=lambda _: pytest.fail('must not execute'))
    assert dispatcher.dispatch(request(store.issue(params), params))['code'] == 'recovery_required'


@pytest.mark.requires_unelevated
def test_replaced_executable_cannot_use_original_grant(setup):
    store, params = setup
    grant = store.issue(params)
    from pathlib import Path
    Path(params['program']).write_bytes(b'changed fixture')
    dispatcher = ServiceDispatcher(store, runner=lambda _: pytest.fail('must not execute'))
    assert dispatcher.dispatch(request(grant, params))['code'] == 'unauthorized'


@pytest.mark.requires_unelevated
def test_request_cannot_supply_identity_or_consent(setup):
    store, params = setup
    dispatcher = ServiceDispatcher(store, runner=lambda _: pytest.fail('must not execute'))
    req = request(store.issue(params), params)
    req.body['consent'] = True
    assert dispatcher.dispatch(req)['code'] == 'bad_params'
    assert dispatcher.dispatch(ReceivedRequest(None, request('a'*32, params).body))['code'] == 'unauthorized'


@pytest.mark.requires_unelevated
def test_transaction_failure_rolls_back_claim(setup):
    store, params = setup
    grant = store.issue(params)
    with store._conn() as conn:
        conn.execute("CREATE TRIGGER reject_intent BEFORE INSERT ON operations BEGIN SELECT RAISE(ABORT, 'disk contract'); END")
    with pytest.raises(Exception):
        store.claim(grant, SID, params, identity(params))
    with store._conn() as conn:
        assert conn.execute('SELECT state FROM grants WHERE id=?', (grant,)).fetchone()[0] == 'available'
    assert store.pending() == []


def test_production_refuses_user_writable_state(tmp_path):
    with pytest.raises((PermissionError, OSError)):
        GrantStore(tmp_path, SID)


def test_native_windows_lease_blocks_changes_and_releases(tmp_path):
    import os
    if os.name != 'nt':
        pytest.skip('Actual Windows sharing semantics required')
    program = tmp_path / 'lease.exe'
    program.write_bytes(b'actual read-only lease fixture')
    with executable_lease(str(program)) as observed:
        assert observed['size'] == program.stat().st_size
        with pytest.raises(OSError):
            program.write_bytes(b'changed')
        with pytest.raises(OSError):
            program.rename(tmp_path / 'renamed.exe')
    program.write_bytes(b'after lease')
    program.rename(tmp_path / 'renamed.exe')


@pytest.mark.requires_unelevated
@pytest.mark.parametrize('mode', ['missing', 'mismatched', 'conflict', 'restored'])
def test_administrative_recovery_keeps_unresolved_evidence(setup, mode):
    from agent.privilege.recovery import reconcile
    store, params = setup
    operation = store.claim(store.issue(params), SID, params, identity(params))
    path = store.directory / (operation + '.firewall.json')
    names = [item[0] for item in rule_names(params['program'], 'Public', ['IPv4'], ['192.0.2.1/32'])]
    if mode != 'missing':
        record = {'version': 1, 'state': 'outcome_unknown', 'ownership_token': 'a'*32,
                  'params': dict(params, profile='Private') if mode == 'mismatched' else params,
                  'rule_names': names}
        path.write_text(json.dumps(record))
    calls = []
    def runner(_):
        calls.append(True)
        return '\n'.join([('REMOVE:FAILED:' if mode == 'conflict' else 'REMOVE:GONE:') + name
                          for name in names] + ['STATUS:OK']), False
    result = reconcile(store, operation, runner=runner)
    assert result['ok'] is (mode == 'restored')
    assert bool(store.pending()) is (mode != 'restored')
    assert bool(calls) is (mode in {'conflict', 'restored'})


@pytest.mark.requires_unelevated
def test_deleted_program_does_not_strand_owned_recovery(setup):
    from pathlib import Path
    from agent.privilege.recovery import reconcile
    from agent.privilege.contract import validate_restrict_params
    store, params = setup
    operation = store.claim(store.issue(params), SID, params, identity(params))
    names = [item[0] for item in rule_names(params['program'], 'Public', ['IPv4'], ['192.0.2.1/32'])]
    path = store.directory / (operation + '.firewall.json')
    path.write_text(json.dumps({'version': 1, 'state': 'outcome_unknown', 'ownership_token': 'a'*32,
                               'params': params, 'rule_names': names}))
    Path(params['program']).unlink()
    assert validate_restrict_params(params)[0] is None
    result = reconcile(store, operation, runner=lambda script:
                       ('\n'.join(['REMOVE:GONE:' + name for name in names] + ['STATUS:OK']), False))
    assert result['ok']
    assert store.pending() == []

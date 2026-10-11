"""Actual child-process termination and SQLite reopen; no firewall execution."""
import json
import subprocess
import sys

import pytest

from agent.privilege.grants import GrantStore
from agent.privilege.target import executable_lease

SID = 'S-1-5-21-111-222-333-1001'

CODE = r'''
import json, os, sys
from pathlib import Path
from agent.privilege.grants import GrantStore
from agent.privilege.target import executable_lease
data = json.load(sys.stdin)
store = GrantStore(Path(data['directory']), data['sid'], test_harness=True)
if data['phase'] == 'committed':
    with executable_lease(data['params']['program'], test_harness=True) as identity:
        store.claim(data['grant'], data['sid'], data['params'], identity)
else:
    with store._conn() as conn:
        conn.execute("UPDATE grants SET state='consumed' WHERE id=?", (data['grant'],))
        conn.execute("INSERT INTO operations VALUES (?,?,?,?,NULL)",
                     ('b'*32, data['grant'], json.dumps(data['params']), 'intent_durable'))
        os._exit(73)
os._exit(73)
'''


@pytest.mark.requires_unelevated
@pytest.mark.parametrize('phase', ['committed', 'uncommitted'])
def test_process_exit_preserves_transaction_boundary(tmp_path, phase):
    program = tmp_path / 'fixture.exe'
    program.write_bytes(b'non-executable authorization contract fixture')
    params = {'program': str(program), 'profile': 'Public', 'address_families': ['IPv4'],
              'remote_addresses': ['192.0.2.1/32']}
    directory = tmp_path / 'state'
    store = GrantStore(directory, SID, test_harness=True)
    grant = store.issue(params)
    result = subprocess.run([sys.executable, '-c', CODE], input=json.dumps(
        {'directory': str(directory), 'sid': SID, 'params': params, 'grant': grant, 'phase': phase}),
        text=True, capture_output=True, timeout=15)
    assert result.returncode == 73, result.stdout + result.stderr
    reopened = GrantStore(directory, SID, test_harness=True)
    with executable_lease(params['program'], test_harness=True) as identity:
        if phase == 'committed':
            assert len(reopened.pending()) == 1
            with pytest.raises(PermissionError):
                reopened.claim(grant, SID, params, identity)
        else:
            assert reopened.pending() == []
            assert reopened.claim(grant, SID, params, identity)

"""Actual Windows pipe plus contract executor; no real firewall mutation."""
import json
import os
import subprocess
import sys

import pytest


CODE = r'''
import json, pathlib, tempfile, threading
from uuid import uuid4
import win32api, win32con, win32file, win32pipe, win32security
from agent.privilege.grants import GrantStore
from agent.privilege.native_channel import NativeRequestChannel
from agent.privilege.pipe import PIPE_CLIENT_RIGHTS
from agent.privilege.service_dispatch import ServiceDispatcher
from agent.modules.firewall_apply import rule_names
token = win32security.OpenProcessToken(win32api.GetCurrentProcess(), win32con.TOKEN_QUERY)
sid = win32security.ConvertSidToStringSid(win32security.GetTokenInformation(token, win32security.TokenUser)[0])
token.Close()
with tempfile.TemporaryDirectory() as temporary:
    directory = pathlib.Path(temporary)
    program = directory / 'fixture.exe'
    program.write_bytes(b'non-executable contract fixture')
    params = {'program':str(program), 'profile':'Public', 'address_families':['IPv4'], 'remote_addresses':['192.0.2.1/32']}
    store = GrantStore(directory / 'state', sid, test_harness=True)
    grant = store.issue(params)
    def executor(script):
        pending = store.pending()
        assert len(pending) == 1
        journal = json.loads((store.directory / (pending[0]['id']+'.firewall.json')).read_text())
        name = rule_names(params['program'], 'Public', ['IPv4'], ['192.0.2.1/32'])[0][0]
        return (f"VERIFY:{name}|True|Outbound|Block|Public|derived|{params['program']}|192.0.2.1/32|DVielle|DVielle invocation {journal['ownership_token']}\nSTATUS:OK"), False
    dispatcher = ServiceDispatcher(store, runner=executor)
    name = r'\\.\pipe\DVielle-roundtrip-' + uuid4().hex
    reply = []
    errors = []
    with NativeRequestChannel(sid, name=name) as channel:
        def client():
            handle = None
            try:
                handle = win32file.CreateFile(name, PIPE_CLIENT_RIGHTS, 0, None, win32con.OPEN_EXISTING, 0x00110000, None)
                win32pipe.SetNamedPipeHandleState(handle, win32pipe.PIPE_READMODE_MESSAGE, None, None)
                win32file.WriteFile(handle, json.dumps({'v':1,'op':'restrict_network','grant_id':grant,'params':params}).encode())
                status, blob = win32file.ReadFile(handle, 65536)
                assert status == 0
                reply.append(json.loads(blob))
            except Exception as exc:
                errors.append(repr(exc))
            finally:
                if handle is not None:
                    handle.Close()
        worker = threading.Thread(target=client, daemon=True)
        worker.start()
        received = channel.receive(timeout=4)
        result = dispatcher.dispatch(received)
        channel.respond(result, timeout=4)
        worker.join(5)
    assert not errors, errors
    assert len(reply) == 1 and reply[0]['ok'] is True
    assert dispatcher.dispatch(received)['code'] == 'unauthorized'
    print(json.dumps({'os_peer_matches':received.peer['sid']==sid,'reply_received':True,'replay_refused':True,'host_mutations':False}))
'''


@pytest.mark.skipif(os.name != 'nt', reason='Actual Windows pipe required')
def test_native_authenticated_dispatch_roundtrip():
    result = subprocess.run([sys.executable, '-c', CODE], capture_output=True, text=True, timeout=15)
    assert result.returncode == 0, result.stdout + result.stderr
    assert json.loads(result.stdout) == {'os_peer_matches': True, 'reply_received': True,
                                       'replay_refused': True, 'host_mutations': False}


def test_user_session_cannot_start_system_host():
    from agent.privilege.service_host import assert_runtime_trust
    with pytest.raises(PermissionError):
        assert_runtime_trust()


@pytest.mark.skipif(os.name != 'nt', reason='Actual Windows service/pipe APIs required')
def test_client_rejects_a_user_session_pipe_server():
    code = r'''
import json, threading, pywintypes
from uuid import uuid4
import win32api, win32con, win32file, win32security
from agent.privilege.native_channel import NativeRequestChannel
from agent.privilege.native_client import authenticate_server
from agent.privilege.pipe import PIPE_CLIENT_RIGHTS
token = win32security.OpenProcessToken(win32api.GetCurrentProcess(), win32con.TOKEN_QUERY)
sid = win32security.ConvertSidToStringSid(win32security.GetTokenInformation(token, win32security.TokenUser)[0])
token.Close()
name = r'\\.\pipe\DVielle-fake-server-' + uuid4().hex
result = []
with NativeRequestChannel(sid, name=name) as channel:
    def client():
        handle = win32file.CreateFile(name, PIPE_CLIENT_RIGHTS, 0, None, win32con.OPEN_EXISTING, 0x00110000, None)
        try:
            process = authenticate_server(handle)
            process.Close()
            result.append(False)
        except Exception:
            result.append(True)
        finally:
            handle.Close()
    worker = threading.Thread(target=client)
    worker.start()
    try:
        channel.receive(timeout=1)
    except (TimeoutError, OSError, pywintypes.error):
        pass
    worker.join(4)
assert result == [True], result
print(json.dumps({'fake_server_refused': True, 'request_sent': False}))
'''
    result = subprocess.run([sys.executable, '-c', code], capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stdout + result.stderr
    assert json.loads(result.stdout) == {'fake_server_refused': True, 'request_sent': False}


def test_administrative_approval_cannot_be_issued_from_normal_session():
    from agent.privilege.admin import main
    with pytest.raises(PermissionError):
        main(['approve', '--program', str(__file__), '--profile', 'Public', '--family', 'IPv4'])


def test_host_contract_continues_after_disconnected_client(monkeypatch, tmp_path):
    """Non-production loop contract with OS startup guards deliberately replaced."""
    import threading
    import pywintypes
    from agent.privilege import service_host
    stop = threading.Event()
    attempts = []
    monkeypatch.setattr(service_host, 'assert_runtime_trust', lambda: None)
    monkeypatch.setattr(service_host, 'allow_bound_user_identity_query', lambda sid: None)
    monkeypatch.setattr(service_host, 'installed_configuration', lambda: (tmp_path, 'contract'))
    from agent.privilege import release_identity
    monkeypatch.setattr(release_identity, 'verify_installed_identity', lambda directory: {})
    monkeypatch.setattr(service_host, 'GrantStore', lambda *args: None)
    monkeypatch.setattr(service_host, 'ServiceDispatcher', lambda *args: None)
    class Channel:
        def __init__(self, *args):
            pass
        def __enter__(self):
            return self
        def __exit__(self, *args):
            pass
        def receive(self, **kwargs):
            attempts.append(True)
            if len(attempts) == 1:
                raise pywintypes.error(109, 'ReadFile', 'pipe ended')
            stop.set()
            raise TimeoutError()
    monkeypatch.setattr(service_host, 'NativeRequestChannel', Channel)
    service_host.serve(stop)
    assert len(attempts) == 2


@pytest.mark.skipif(os.name != 'nt', reason='Actual Windows process token required')
def test_normal_user_cannot_publish_system_identity():
    from agent.privilege.service_host import allow_bound_user_identity_query
    with pytest.raises(PermissionError, match='Only the SYSTEM host'):
        allow_bound_user_identity_query('S-1-5-18')

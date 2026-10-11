"""Real Windows transport cases isolated in child processes; no mutation."""
import json
import os
import subprocess
import sys

import pytest

CODE = r'''
import json, os, sys, threading, time
from uuid import uuid4
import win32api, win32con, win32file, win32security
from agent.privilege.native_channel import NativeRequestChannel
from agent.privilege.pipe import PIPE_CLIENT_RIGHTS
token = win32security.OpenProcessToken(win32api.GetCurrentProcess(), win32con.TOKEN_QUERY)
sid = win32security.ConvertSidToStringSid(win32security.GetTokenInformation(token, win32security.TokenUser)[0])
token.Close()
mode = sys.argv[1]
release = threading.Event()
errors = []
name = r"\\.\pipe\DVielle-native-test-" + uuid4().hex
with NativeRequestChannel(sid, name=name) as channel:
    def client():
        handle = None
        try:
            handle = win32file.CreateFile(name, PIPE_CLIENT_RIGHTS, 0, None, win32con.OPEN_EXISTING,
                0x00100000 | 0x00010000, None)
            if mode != 'idle':
                data = {'normal': b'{"v":1,"op":"inspect"}', 'duplicate': b'{"v":1,"v":2}',
                        'oversized': b'x' * 65538, 'nonfinite': b'{"v":NaN}'}[mode]
                win32file.WriteFile(handle, data)
            release.wait(4)
        except Exception as exc:
            errors.append(type(exc).__name__)
        finally:
            if handle is not None:
                handle.Close()
    worker = threading.Thread(target=client, daemon=True)
    if mode != 'no_client':
        worker.start()
    try:
        received = channel.receive(timeout=1.5)
        result = {'state':'received', 'identity_matches':received.peer['sid']==sid,
                  'authorized':received.peer['authorized'], 'body':received.body}
    except Exception as exc:
        result = {'state':'refused', 'error':type(exc).__name__}
    finally:
        release.set()
        if mode != 'no_client':
            worker.join(timeout=4)
print(json.dumps(result))
'''


@pytest.mark.skipif(os.name != "nt", reason="Requires Windows native pipes")
@pytest.mark.parametrize("mode", ["normal", "duplicate", "oversized", "idle", "no_client", "nonfinite"])
def test_real_bounded_channel(mode):
    pytest.importorskip("win32file")
    result = subprocess.run([sys.executable, "-c", CODE, mode], capture_output=True, text=True, timeout=12)
    assert result.returncode == 0, result.stdout + result.stderr
    evidence = json.loads(result.stdout)
    if mode == "normal":
        assert evidence == {"state": "received", "identity_matches": True, "authorized": False,
                            "body": {"v": 1, "op": "inspect"}}
    else:
        assert evidence["state"] == "refused"
        if mode in {"idle", "no_client"}:
            assert evidence["error"] == "TimeoutError"
        if mode in {"duplicate", "nonfinite"}:
            assert evidence["error"] == "ValueError"

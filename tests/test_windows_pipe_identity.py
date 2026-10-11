"""Real temporary Windows kernel pipe; no service or firewall changes."""
import os
import threading
import time
from uuid import uuid4

import pytest

from agent.privilege.identity import authenticate_pipe_peer
from agent.privilege.pipe import PIPE_CLIENT_RIGHTS, build_pipe_sddl


@pytest.mark.skipif(os.name != "nt", reason="Requires Windows kernel pipe identity")
@pytest.mark.parametrize("wrong_identity", [False, True])
def test_real_pipe_token_identity_and_reversion(wrong_identity):
    win32api = pytest.importorskip("win32api")
    win32con = pytest.importorskip("win32con")
    win32file = pytest.importorskip("win32file")
    win32pipe = pytest.importorskip("win32pipe")
    security = pytest.importorskip("win32security")
    import pywintypes
    token = security.OpenProcessToken(win32api.GetCurrentProcess(), win32con.TOKEN_QUERY)
    try:
        sid = security.ConvertSidToStringSid(security.GetTokenInformation(token, security.TokenUser)[0])
    finally:
        token.Close()
    attrs = security.SECURITY_ATTRIBUTES()
    attrs.SECURITY_DESCRIPTOR = security.ConvertStringSecurityDescriptorToSecurityDescriptor(build_pipe_sddl(sid), 1)
    attrs.bInheritHandle = False
    name = r"\\.\pipe\DVielle-identity-test-" + uuid4().hex
    handle = win32pipe.CreateNamedPipe(name, win32pipe.PIPE_ACCESS_DUPLEX | 0x00080000,
        win32pipe.PIPE_TYPE_MESSAGE | win32pipe.PIPE_READMODE_MESSAGE | win32pipe.PIPE_NOWAIT | 0x8,
        1, 4096, 4096, 1000, attrs)
    release = threading.Event()
    errors = []
    def client():
        client_handle = None
        try:
            client_handle = win32file.CreateFile(name, PIPE_CLIENT_RIGHTS, 0, None,
                win32con.OPEN_EXISTING, 0x00100000 | 0x00010000, None)  # SQOS present, identification
            win32file.WriteFile(client_handle, b"identity-only")
            release.wait(5)
        except Exception as exc:
            errors.append(exc)
        finally:
            if client_handle is not None:
                client_handle.Close()
    worker = None
    try:
        try:
            win32pipe.ConnectNamedPipe(handle, None)
        except pywintypes.error as exc:
            assert exc.winerror == 536  # listening in nonblocking test mode
        worker = threading.Thread(target=client, daemon=True)
        worker.start()
        deadline = time.monotonic() + 4
        while True:
            try:
                _, data = win32file.ReadFile(handle, 4096)
                if data:
                    break
            except pywintypes.error as exc:
                if exc.winerror not in {232, 536}:
                    raise
            if errors:
                raise errors[0]
            if time.monotonic() >= deadline:
                pytest.fail("Client did not submit its real pipe message")
            time.sleep(0.01)
        assert data == b"identity-only"
        expected = "S-1-5-21-111-222-333-444" if wrong_identity else sid
        if wrong_identity:
            with pytest.raises(PermissionError):
                authenticate_pipe_peer(handle, expected)
        else:
            peer = authenticate_pipe_peer(handle, expected)
            assert peer["sid"] == sid and peer["process_id"] == os.getpid()
            assert peer["authorized"] is False
        with pytest.raises(pywintypes.error) as no_thread_token:
            security.OpenThreadToken(win32api.GetCurrentThread(), win32con.TOKEN_QUERY, True)
        assert no_thread_token.value.winerror == 1008
    finally:
        release.set()
        if worker is not None:
            worker.join(timeout=5)
        handle.Close()

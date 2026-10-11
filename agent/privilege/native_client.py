"""Mutually authenticated client for the installed SYSTEM service only."""
from __future__ import annotations

import json
import math
import threading
import time
from pathlib import Path

from agent.privilege.contract import DEFINED_OP, PIPE_NAME, PROTOCOL_VERSION, validate_restrict_params
from agent.privilege.native_channel import MAX_FRAME, NativeRequestChannel, _nonfinite, _object
from agent.privilege.pipe import PIPE_CLIENT_RIGHTS
from agent.privilege.protected_paths import TRUSTED_OWNERS, assert_protected_path

SERVICE_NAME = 'DViellePrivilegedHelper'


def authenticate_server(pipe_handle):
    """Bind the pipe to SCM's running, protected SYSTEM process.

    The returned process handle stays open through the exchange. Failure to
    query OS identity is refusal, never permission to trust an endpoint file.
    """
    import ctypes
    from ctypes import wintypes
    import win32api
    import win32con
    import win32pipe
    import win32security
    import win32service

    manager = win32service.OpenSCManager(None, None, win32service.SC_MANAGER_CONNECT)
    service = None
    process = None
    try:
        service = win32service.OpenService(manager, SERVICE_NAME,
            win32service.SERVICE_QUERY_STATUS | win32service.SERVICE_QUERY_CONFIG | win32con.READ_CONTROL)
        config = win32service.QueryServiceConfig(service)
        if config[7].lower() not in {'localsystem', 'nt authority\\system'}:
            raise PermissionError('The helper is not registered under SYSTEM.')
        descriptor = win32service.QueryServiceObjectSecurity(service,
            win32security.OWNER_SECURITY_INFORMATION | win32security.DACL_SECURITY_INFORMATION)
        if win32security.ConvertSidToStringSid(descriptor.GetSecurityDescriptorOwner()) not in TRUSTED_OWNERS:
            raise PermissionError('The service has an untrusted owner.')
        acl = descriptor.GetSecurityDescriptorDacl()
        if acl is None:
            raise PermissionError('The service configuration is unprotected.')
        for offset in range(acl.GetAceCount()):
            header, mask, sid = acl.GetAce(offset)
            if header[1] & 8 or header[0] == win32security.ACCESS_DENIED_ACE_TYPE:
                continue
            if header[0] != win32security.ACCESS_ALLOWED_ACE_TYPE:
                raise PermissionError('Unsupported service security descriptor.')
            if mask & 0x10000000:
                mask |= 0x000F01FF
            if mask & (0x000D0002 | 0x40000000) and win32security.ConvertSidToStringSid(sid) not in TRUSTED_OWNERS:
                raise PermissionError('An untrusted principal can replace service configuration.')
        pid = win32pipe.GetNamedPipeServerProcessId(pipe_handle)
        status = win32service.QueryServiceStatusEx(service)
        if status['CurrentState'] != win32service.SERVICE_RUNNING or status['ProcessId'] != pid:
            raise PermissionError('The pipe server is not the running registered helper.')
        process = win32api.OpenProcess(0x1000, False, pid)  # PROCESS_QUERY_LIMITED_INFORMATION
        token = win32security.OpenProcessToken(process, win32con.TOKEN_QUERY)
        try:
            sid = win32security.GetTokenInformation(token, win32security.TokenUser)[0]
            if win32security.ConvertSidToStringSid(sid) != 'S-1-5-18':
                raise PermissionError('The actual pipe server token is not SYSTEM.')
        finally:
            token.Close()
        query = ctypes.WinDLL('kernel32', use_last_error=True).QueryFullProcessImageNameW
        query.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD)]
        query.restype = wintypes.BOOL
        size = wintypes.DWORD(32768)
        buffer = ctypes.create_unicode_buffer(size.value)
        if not query(int(process), 0, buffer, ctypes.byref(size)):
            raise ctypes.WinError(ctypes.get_last_error())
        assert_protected_path(Path(buffer.value))
        status = win32service.QueryServiceStatusEx(service)
        if status['CurrentState'] != win32service.SERVICE_RUNNING or status['ProcessId'] != pid:
            raise PermissionError('The registered helper changed during authentication.')
        result, process = process, None
        return result
    finally:
        if process is not None:
            process.Close()
        if service is not None:
            win32service.CloseServiceHandle(service)
        win32service.CloseServiceHandle(manager)


class _Connection:
    # Identical same-thread cancellation/drain semantics on a client handle.
    _wait = NativeRequestChannel._wait
    _cancel_and_drain = NativeRequestChannel._cancel_and_drain

    def __init__(self, handle):
        self.handle = handle


def submit(params: dict, grant_id: str, *, timeout: float = 30) -> dict:
    import re
    if type(timeout) not in {float, int} or not math.isfinite(timeout) or not 0 < timeout <= 30:
        raise ValueError('The exchange deadline must be within thirty seconds.')
    checked, error = validate_restrict_params(params)
    if checked is None:
        raise ValueError(error)
    if not isinstance(grant_id, str) or re.fullmatch('[0-9a-f]{32}', grant_id) is None:
        raise ValueError('An exact one-use administrative grant is required.')
    import pywintypes
    import win32con
    import win32event
    import win32file
    import win32pipe
    deadline = time.monotonic() + timeout
    win32pipe.WaitNamedPipe(PIPE_NAME, min(1000, int(timeout * 1000)))
    handle = win32file.CreateFile(PIPE_NAME, PIPE_CLIENT_RIGHTS, 0, None, win32con.OPEN_EXISTING,
        0x40000000 | 0x00110000, None)  # overlapped, identification SQOS
    process = None
    try:
        process = authenticate_server(handle)  # Before sending executable path or grant.
        win32pipe.SetNamedPipeHandleState(handle, win32pipe.PIPE_READMODE_MESSAGE, None, None)
        connection = _Connection(handle)
        stop = threading.Event()
        blob = json.dumps({'v': PROTOCOL_VERSION, 'op': DEFINED_OP,
                           'grant_id': grant_id, 'params': checked}, allow_nan=False).encode('utf-8')
        if len(blob) > MAX_FRAME:
            raise ValueError('Request exceeds the frame limit.')
        write = pywintypes.OVERLAPPED()
        write.hEvent = win32event.CreateEvent(None, True, False, None)
        try:
            status, count = win32file.WriteFile(handle, blob, write)
            if status == 997:
                count = connection._wait(write, deadline, stop)
            elif status != 0:
                raise OSError('Unexpected request write status.')
            if count != len(blob):
                raise OSError('The request was not completely written.')
        finally:
            write.hEvent.Close()
        read = pywintypes.OVERLAPPED()
        read.hEvent = win32event.CreateEvent(None, True, False, None)
        buffer = win32file.AllocateReadBuffer(MAX_FRAME + 1)
        try:
            status, _ = win32file.ReadFile(handle, buffer, read)
            if status not in {0, 997}:
                raise ValueError('Invalid response frame.')
            count = connection._wait(read, deadline, stop) if status == 997 else win32file.GetOverlappedResult(handle, read, False)
            if not 0 < count <= MAX_FRAME:
                raise ValueError('Invalid response length.')
            response = json.loads(bytes(buffer[:count]).decode('utf-8'), object_pairs_hook=_object, parse_constant=_nonfinite)
            if (not isinstance(response, dict) or type(response.get('ok')) is not bool
                    or type(response.get('performed')) is not bool or not isinstance(response.get('code'), str)):
                raise ValueError('The service result does not match its contract.')
            return response
        finally:
            read.hEvent.Close()
    finally:
        if process is not None:
            process.Close()
        handle.Close()

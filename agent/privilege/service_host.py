"""Protected SYSTEM host. Installing or elevating this checkout is not supported."""
from __future__ import annotations

import json
import os
import sys
import threading
from pathlib import Path

from agent.privilege.grants import GrantStore
from agent.privilege.native_channel import NativeRequestChannel
from agent.privilege.protected_paths import assert_protected_path
from agent.privilege.service_dispatch import ServiceDispatcher, system_identity

SERVICE_NAME = 'DViellePrivilegedHelper'


def allow_bound_user_identity_query(sid: str):
    """Permit only identity queries needed for mutual pipe authentication."""
    import win32api
    import win32con
    import win32security as security
    if not system_identity():
        raise PermissionError('Only the SYSTEM host can publish its identity.')
    reader = security.ConvertStringSidToSid(sid)
    if security.LookupAccountSid(None, reader)[2] != security.SidTypeUser:
        raise PermissionError('An exact installed user identity is required.')
    process = win32api.GetCurrentProcess()
    token = security.OpenProcessToken(process, win32con.TOKEN_QUERY | win32con.READ_CONTROL | win32con.WRITE_DAC)
    try:
        for handle, rights in ((process, 0x1000), (token, win32con.TOKEN_QUERY)):
            descriptor = security.GetSecurityInfo(handle, security.SE_KERNEL_OBJECT,
                                                 security.DACL_SECURITY_INFORMATION)
            acl = descriptor.GetSecurityDescriptorDacl()
            if acl is None:
                raise PermissionError('Identity objects must have an explicit DACL.')
            acl.AddAccessAllowedAce(security.ACL_REVISION, rights, reader)
            security.SetSecurityInfo(handle, security.SE_KERNEL_OBJECT,
                                     security.DACL_SECURITY_INFORMATION, None, None, acl, None)
    finally:
        token.Close()


def assert_runtime_trust(*, require_system: bool = True):
    """Fail closed on mutable runtime/import roots or loaded module files.

    This checks access control, not publisher identity. A trusted release
    manifest and installer provenance remain separate activation requirements.
    """
    if require_system and not system_identity():
        raise PermissionError('The service host requires SYSTEM.')
    if sys.version_info[:2] != (3, 14) or sys.version_info[:3] < (3, 14, 8):
        raise PermissionError('Protected helper activation requires validated Python 3.14.8 or newer in the 3.14 series.')
    assert_protected_path(Path(sys.executable))
    for entry in sys.path:
        if not entry or not Path(entry).is_absolute():
            raise PermissionError('Ambient or relative import roots are refused.')
        path = Path(entry)
        if path.exists():
            assert_protected_path(path)
        else:
            # CPython may declare an optional absent standard-library zip.
            # Its ancestor must prevent users from placing a replacement.
            assert_protected_path(path.parent)
    for module in tuple(sys.modules.values()):
        name = getattr(module, '__file__', None)
        if name:
            assert_protected_path(Path(name))


def installed_configuration() -> tuple[Path, str]:
    import win32com.shell.shell as shell
    import win32com.shell.shellcon as shellcon
    # Resolve Windows' known common-data folder, not caller-supplied env vars.
    common = Path(shell.SHGetFolderPath(0, shellcon.CSIDL_COMMON_APPDATA, None, 0))
    directory = common / 'DVielle' / 'privileged'
    assert_protected_path(directory)
    config = directory / 'installation.json'
    assert_protected_path(config)
    if config.stat().st_size > 4096:
        raise ValueError('Oversized service installation configuration.')
    payload = json.loads(config.read_text(encoding='utf-8'))
    if (not isinstance(payload, dict) or set(payload) != {'version', 'user_sid'}
            or type(payload['version']) is not int or payload['version'] != 1):
        raise ValueError('Unsupported service installation configuration.')
    return directory, payload['user_sid']


def serve(stop: threading.Event):
    import pywintypes
    assert_runtime_trust()
    directory, sid = installed_configuration()
    from agent.privilege.release_identity import verify_installed_identity
    verify_installed_identity(directory)
    allow_bound_user_identity_query(sid)
    dispatcher = ServiceDispatcher(GrantStore(directory, sid))
    while not stop.is_set():
        # Revalidate protected roots before each connection. No grant issuing,
        # shell strings, external fetches or automatic recovery in this loop.
        assert_runtime_trust()
        with NativeRequestChannel(sid) as channel:
            try:
                received = channel.receive(timeout=5, stop=stop)
            except TimeoutError:
                continue
            except (ValueError, UnicodeError, OSError, RecursionError, pywintypes.error):
                stop.wait(0.05)
                continue
            if stop.is_set():
                break
            result = dispatcher.dispatch(received)
            try:
                channel.respond(result, timeout=5, stop=stop)
            except (TimeoutError, ValueError, OSError, pywintypes.error):
                # The durable operation, not delivery of a response, decides
                # its state. Never rerun a consumed grant on a lost reply.
                continue


if os.name == 'nt':
    import win32service
    import win32serviceutil

    class DViellePrivilegedService(win32serviceutil.ServiceFramework):
        _svc_name_ = SERVICE_NAME
        _svc_display_name_ = "D'Vielle Scoped Protection Helper"
        _svc_description_ = 'Performs one-use administratively approved network restrictions.'

        def __init__(self, args):
            super().__init__(args)
            self.stop = threading.Event()

        def SvcStop(self):
            self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
            self.stop.set()

        def SvcDoRun(self):
            serve(self.stop)


def main():
    if os.name != 'nt':
        raise OSError('Windows Service Control Manager is required.')
    # No install/start/elevate command is exposed by this source entry point.
    assert_runtime_trust()
    import servicemanager
    servicemanager.Initialize()
    servicemanager.PrepareToHostSingle(DViellePrivilegedService)
    servicemanager.StartServiceCtrlDispatcher()


if __name__ == '__main__':
    main()

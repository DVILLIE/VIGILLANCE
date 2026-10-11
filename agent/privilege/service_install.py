"""Administrator-only registration from an already protected approved runtime.

This does not stage, elevate, download, enroll a publisher or change code ACLs.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from agent.local_files import atomic_text, file_lock
from agent.privilege.helper import _is_elevated
from agent.privilege.protected_paths import TRUSTED_OWNERS, assert_protected_path
from agent.privilege.release_identity import runtime_roots, verify_manifest, verify_installed_identity
from agent.privilege.service_host import SERVICE_NAME, assert_runtime_trust, installed_configuration


def binary_command() -> str:
    program = str(Path(sys.executable).resolve())
    if '"' in program or '\n' in program or '\r' in program:
        raise ValueError('Unsafe service interpreter path.')
    return f'"{program}" -I -B -m agent.privilege.service_host'


def assert_service_security(handle):
    import win32security
    import win32service
    descriptor = win32service.QueryServiceObjectSecurity(handle,
        win32security.OWNER_SECURITY_INFORMATION | win32security.DACL_SECURITY_INFORMATION)
    if win32security.ConvertSidToStringSid(descriptor.GetSecurityDescriptorOwner()) not in TRUSTED_OWNERS:
        raise PermissionError('Untrusted service owner.')
    acl = descriptor.GetSecurityDescriptorDacl()
    if acl is None:
        raise PermissionError('Null service DACL.')
    for index in range(acl.GetAceCount()):
        header, mask, sid = acl.GetAce(index)
        if header[1] & 8 or header[0] == win32security.ACCESS_DENIED_ACE_TYPE:
            continue
        if header[0] != win32security.ACCESS_ALLOWED_ACE_TYPE:
            raise PermissionError('Unsupported service ACE.')
        if mask & 0x10000000:
            mask |= 0x000F01FF
        if mask & (0x000D0032 | 0x40000000) and win32security.ConvertSidToStringSid(sid) not in TRUSTED_OWNERS:
            raise PermissionError('An untrusted principal can control the helper.')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    register = commands.add_parser('register', help='Register stopped helper after exact runtime approval')
    register.add_argument('--manifest', required=True, type=Path)
    register.add_argument('--approved-sha256', required=True)
    commands.add_parser('start', help='Verify identity and start the exact registered helper')
    commands.add_parser('remove', help='Remove the exact stopped helper; preserve grants and recovery records')
    args = parser.parse_args(argv)
    if not _is_elevated():
        raise PermissionError('Service registration requires an explicit Windows Administrator token.')
    assert_runtime_trust(require_system=False)
    directory, sid = installed_configuration()
    import pywintypes
    import win32con
    import win32service
    import win32security
    with file_lock(directory / 'service-registration.lock'):
        assert_protected_path(directory / 'service-registration.lock')
        manager = win32service.OpenSCManager(None, None,
            win32service.SC_MANAGER_CONNECT | (win32service.SC_MANAGER_CREATE_SERVICE if args.command == 'register' else 0))
        handle = None
        try:
            if args.command == 'register':
                # Never replace an existing same-name service, even if it seems
                # owned. Upgrade needs a separate reviewed migration journey.
                try:
                    existing = win32service.OpenService(manager, SERVICE_NAME, win32service.SERVICE_QUERY_CONFIG)
                except pywintypes.error as exc:
                    if exc.winerror != 1060:
                        raise
                else:
                    win32service.CloseServiceHandle(existing)
                    raise FileExistsError('Helper name is already registered; no replacement was performed.')
                result = verify_manifest(args.manifest, args.approved_sha256, runtime_roots())
                destination = directory / 'runtime_manifest.json'
                receipt = directory / 'release_identity.json'
                if destination.exists() or receipt.exists():
                    raise FileExistsError('Identity records already exist; review migration or recovery first.')
                atomic_text(destination, args.manifest.read_bytes().decode('utf-8'))
                atomic_text(receipt, json.dumps({'version': 1, 'manifest_sha256': args.approved_sha256}))
                verify_installed_identity(directory)
                handle = win32service.CreateService(manager, SERVICE_NAME,
                    "D'Vielle Scoped Protection Helper", win32service.SERVICE_ALL_ACCESS,
                    win32service.SERVICE_WIN32_OWN_PROCESS, win32service.SERVICE_DEMAND_START,
                    win32service.SERVICE_ERROR_NORMAL, binary_command(), None, 0, None, 'LocalSystem', None)
                descriptor = win32security.ConvertStringSecurityDescriptorToSecurityDescriptor(
                    'O:BAG:BAD:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;CCLCRC;;;AU)', 1)
                win32service.SetServiceObjectSecurity(handle,
                    win32security.OWNER_SECURITY_INFORMATION | win32security.DACL_SECURITY_INFORMATION, descriptor)
                assert_service_security(handle)
                config = win32service.QueryServiceConfig(handle)
                if config[3] != binary_command() or config[7].lower() != 'localsystem' or config[1] != win32service.SERVICE_DEMAND_START:
                    raise RuntimeError('Registered service readback mismatch; helper was not started.')
                print(json.dumps({'state': 'registered_stopped', 'started': False, 'identity': result}))
                return 0
            verify_installed_identity(directory)
            handle = win32service.OpenService(manager, SERVICE_NAME,
                win32service.SERVICE_QUERY_CONFIG | win32service.SERVICE_QUERY_STATUS
                | (win32service.SERVICE_START if args.command == 'start' else win32con.DELETE) | win32con.READ_CONTROL)
            config = win32service.QueryServiceConfig(handle)
            assert_service_security(handle)
            if config[3] != binary_command() or config[7].lower() != 'localsystem' or config[0] != win32service.SERVICE_WIN32_OWN_PROCESS:
                raise PermissionError('Service identity does not match this exact installation.')
            status = win32service.QueryServiceStatusEx(handle)
            if status['CurrentState'] != win32service.SERVICE_STOPPED:
                raise RuntimeError('Only an exactly stopped helper can be started or removed.')
            if args.command == 'start':
                win32service.StartService(handle, None)
                print(json.dumps({'state': 'start_requested', 'running_verified': False,
                                  'policy_enforcement': 'not_measured'}))
            else:
                win32service.DeleteService(handle)
                print(json.dumps({'state': 'removal_requested', 'records_preserved': True,
                                  'firewall_rules_changed': False}))
            return 0
        finally:
            if handle is not None:
                win32service.CloseServiceHandle(handle)
            win32service.CloseServiceHandle(manager)


if __name__ == '__main__':
    raise SystemExit(main())

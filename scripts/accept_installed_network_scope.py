"""Actual narrow installed-helper acceptance; requires explicit Administrator token.

Launch reviewed code as an immutable command snapshot with installed Python.
Never run this mutable source filename elevated. Only the running interpreter's
executable's traffic to one Python.org IP endpoint is restricted, then restored.
This path scope includes other processes using the same interpreter executable.
No broader network coverage or packet-drop attribution is claimed.
"""
from __future__ import annotations

import ipaddress
import json
import socket
import ssl
import sys
import time
from datetime import datetime, timezone
from pathlib import Path


def probe(address):
    started = time.monotonic()
    try:
        with socket.create_connection((address, 443), timeout=4):
            return {'state': 'connected', 'elapsed_seconds': time.monotonic() - started}
    except OSError as exc:
        return {'state': 'connection_failed', 'error_type': type(exc).__name__,
                'windows_error': getattr(exc, 'winerror', None), 'errno': exc.errno,
                'elapsed_seconds': time.monotonic() - started}


def main():
    if len(sys.argv) != 3:
        raise ValueError('Require exact IP endpoint and unique protected evidence filename')
    parsed_address = ipaddress.ip_address(sys.argv[1])
    address = str(parsed_address)
    family = 'IPv4' if parsed_address.version == 4 else 'IPv6'
    destination = Path(sys.argv[2])
    if destination.parent != Path('C:/Windows/Temp') or not destination.name.startswith('DVielleNetwork-') or destination.suffix != '.json':
        raise ValueError('Require bounded Windows Temp evidence destination')
    from agent.privilege.helper import _is_elevated
    from agent.privilege.service_host import assert_runtime_trust, installed_configuration
    from agent.privilege.release_identity import verify_installed_identity
    from agent.privilege.grants import GrantStore
    from agent.privilege.native_client import submit
    from agent.privilege.recovery import reconcile
    import psutil
    actual_image = str(Path(psutil.Process().exe()).resolve(strict=True))
    if not _is_elevated():
        raise PermissionError('Windows Administrator approval is required')
    assert_runtime_trust(require_system=False)
    directory, sid = installed_configuration()
    identity = verify_installed_identity(directory)
    store = GrantStore(directory, sid)
    if store.pending():
        raise RuntimeError('Existing recovery backlog must be retained; no acceptance mutation started')
    # Create the evidence file exclusively, with private writer permissions at
    # creation. A pre-created path causes refusal before any network mutation.
    import pywintypes
    import win32con
    import win32file
    import win32security
    descriptor = win32security.ConvertStringSecurityDescriptorToSecurityDescriptor(
        'O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;' + sid + ')', 1)
    attributes = pywintypes.SECURITY_ATTRIBUTES()
    attributes.SECURITY_DESCRIPTOR = descriptor
    handle = win32file.CreateFile(str(destination), win32con.GENERIC_WRITE, win32con.FILE_SHARE_READ,
        attributes, win32con.CREATE_NEW, win32con.FILE_ATTRIBUTE_NORMAL, None)
    report = {'started': datetime.now(timezone.utc).isoformat(), 'runtime_identity': identity,
        'scope': {'program': actual_image, 'launch_executable': sys.executable,
                  'scope_kind': 'executable_path_all_instances_not_single_pid',
                  'remote_address': address, 'address_family': family,
                  'port': 443, 'profile': 'Any'},
        'state': 'started', 'mutations': [], 'packet_drop_attribution': 'not_measured',
        'excluded': ['IPv6' if family == 'IPv4' else 'IPv4', 'UDP', 'QUIC', 'VPN',
                     'proxy', 'children', 'competing policy', 'crash recovery']}
    operation = None
    existing = None
    grant = None
    try:
        report['before'] = probe(address)
        if report['before']['state'] != 'connected':
            report['state'] = 'inconclusive_baseline_unavailable'
            return 2
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.verify_flags |= ssl.VERIFY_X509_STRICT | ssl.VERIFY_X509_PARTIAL_CHAIN
        context.load_default_certs()
        raw = socket.create_connection((address, 443), timeout=4)
        try:
            existing = context.wrap_socket(raw, server_hostname='www.python.org')
        except BaseException:
            raw.close()
            raise
        report['before_verified_tls'] = {'version': existing.version(), 'hostname_verified': True}
        params = {'program': actual_image, 'profile': 'Any',
                  'address_families': [family], 'remote_addresses': [address + ('/32' if family == 'IPv4' else '/128')]}
        grant = store.issue(params)
        result = submit(params, grant)
        report['apply'] = result
        operation = result.get('operation_id')
        if operation is None:
            # Failure after durable claim may omit its identifier from the
            # transport result. Bind the retained operation to our exact grant.
            with store._conn() as conn:
                row = conn.execute('SELECT id FROM operations WHERE grant_id=?', (grant,)).fetchone()
            operation = row[0] if row else None
        if operation:
            report['mutations'].append({'operation_id': operation, 'operation': 'restrict_network'})
        if result.get('ok') is not True:
            report['state'] = 'apply_not_verified'
            return 2
        report['during_new_tcp'] = [probe(address) for _ in range(2)]
        try:
            existing.sendall(b'HEAD / HTTP/1.1\r\nHost: www.python.org\r\nConnection: close\r\n\r\n')
            received = existing.recv(4096)
            report['during_existing_tls'] = {'state': 'response_received' if received else 'connection_closed',
                                             'received_bytes': len(received)}
        except OSError as exc:
            report['during_existing_tls'] = {'state': 'io_failed', 'error_type': type(exc).__name__,
                                             'windows_error': getattr(exc, 'winerror', None)}
        blocked = all(item['state'] == 'connection_failed' for item in report['during_new_tcp'])
        existing_blocked = report['during_existing_tls']['state'] in {'io_failed', 'connection_closed'}
        report['state'] = 'bounded_traffic_block_observed' if blocked and existing_blocked else 'traffic_continued_acceptance_failed'
        return 0 if blocked and existing_blocked else 2
    except Exception as exc:
        report.update(state='failed_or_incomplete', error_type=type(exc).__name__)
        return 2
    finally:
        if existing is not None:
            existing.close()
        if operation:
            try:
                report['recovery'] = reconcile(store, operation)
            except Exception as exc:
                report['recovery'] = {'ok': False, 'state_unknown': True, 'error_type': type(exc).__name__}
            if report['recovery'].get('ok') is True:
                report['after'] = probe(address)
            else:
                report['state'] = 'recovery_required'
        elif grant:
            try:
                store.revoke(grant)
            except Exception as exc:
                report.update(state='approval_cleanup_unknown', cleanup_error_type=type(exc).__name__)
        report['finished'] = datetime.now(timezone.utc).isoformat()
        report['acceptance'] = 'observations_only_not_full_network_certification'
        try:
            win32file.WriteFile(handle, json.dumps(report, indent=2, allow_nan=False).encode())
            win32file.FlushFileBuffers(handle)
        finally:
            handle.Close()
        if report['state'] in {'recovery_required', 'approval_cleanup_unknown'}:
            raise RuntimeError('Acceptance ended with unresolved recovery; inspect protected evidence')


if __name__ == '__main__':
    raise SystemExit(main())

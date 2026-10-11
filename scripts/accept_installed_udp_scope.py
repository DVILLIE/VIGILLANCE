"""Real UDP DNS acceptance through the installed helper, with owned restoration.

Operator-approved immutable snapshot only; do not elevate this writable filename.
One public resolver, one harmless public DNS question, exact executable-image rule.
No VPN, QUIC, proxy or IPv6 certification is inferred from UDP DNS observations.
"""
import json
import secrets
import socket
import struct
import time
from datetime import datetime, timezone
from pathlib import Path


def probe(address):
    question = b''.join(bytes([len(part)]) + part for part in (b'www', b'python', b'org')) + b'\0\0\1\0\1'
    identifier = secrets.randbits(16)
    request = struct.pack('!6H', identifier, 0x0100, 1, 0, 0, 0) + question
    started = time.monotonic()
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as transport:
            transport.settimeout(3)
            transport.connect((address, 53))
            sent = transport.send(request)
            response = transport.recv(4096)
            if sent != len(request) or len(response) < 12:
                raise ValueError('Truncated DNS transaction')
            received_id, flags, questions, answers, _, _ = struct.unpack('!6H', response[:12])
            if (received_id != identifier or not flags & 0x8000 or flags & 0x0200
                    or flags & 0x000f or questions != 1 or answers < 1
                    or response[12:12 + len(question)] != question):
                raise ValueError('DNS response does not match the exact successful question')
            return {'state': 'matching_dns_response', 'answer_records': answers,
                    'elapsed_seconds': time.monotonic() - started}
    except (OSError, ValueError) as exc:
        return {'state': 'response_unavailable', 'error_type': type(exc).__name__,
                'windows_error': getattr(exc, 'winerror', None),
                'elapsed_seconds': time.monotonic() - started}


def main(acceptance):
    address = acceptance['resolver']
    if address not in {'1.1.1.1', '8.8.8.8'}:
        raise ValueError('Only the reviewed public DNS resolver addresses are permitted')
    from agent.privilege.helper import _is_elevated
    from agent.privilege.service_host import assert_runtime_trust, installed_configuration
    from agent.privilege.release_identity import verify_installed_identity
    from agent.privilege.grants import GrantStore
    from agent.privilege.native_client import submit
    from agent.privilege.recovery import reconcile
    import psutil
    import pywintypes
    import win32api
    import win32con
    import win32file
    import win32security
    if not _is_elevated():
        raise PermissionError('Explicit Windows Administrator approval required')
    assert_runtime_trust(require_system=False)
    directory, sid = installed_configuration()
    identity = verify_installed_identity(directory)
    if identity['manifest_sha256'] != acceptance['runtime_sha256']:
        raise ValueError('Installed runtime differs from the approved test identity')
    store = GrantStore(directory, sid)
    if store.pending():
        raise RuntimeError('Resolve the retained recovery backlog before any acceptance mutation')
    destination = Path(acceptance['output'])
    if (destination.parent != Path(win32api.GetWindowsDirectory()) / 'Temp'
            or not destination.name.startswith('DVielleUDP-') or destination.suffix != '.json'):
        raise ValueError('Unsafe evidence destination')
    attributes = pywintypes.SECURITY_ATTRIBUTES()
    attributes.SECURITY_DESCRIPTOR = win32security.ConvertStringSecurityDescriptorToSecurityDescriptor(
        'O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;' + sid + ')', 1)
    handle = win32file.CreateFile(str(destination), win32con.GENERIC_WRITE, win32con.FILE_SHARE_READ,
        attributes, win32con.CREATE_NEW, win32con.FILE_ATTRIBUTE_NORMAL, None)
    actual_image = str(Path(psutil.Process().exe()).resolve(strict=True))
    params = {'program': actual_image, 'profile': 'Any', 'address_families': ['IPv4'],
              'remote_addresses': [address + '/32']}
    report = {'state': 'started', 'started': datetime.now(timezone.utc).isoformat(),
        'runtime_identity': identity, 'scope': params, 'observed_protocol': 'UDP DNS port 53',
        'question': 'www.python.org A', 'mutations': [],
        'packet_drop_attribution': 'not_measured', 'scope_kind': 'all_instances_of_exact_executable',
        'excluded': ['IPv6', 'QUIC', 'VPN', 'proxy', 'child images', 'competing policy']}
    grant = operation = None
    try:
        report['before'] = probe(address)
        if report['before']['state'] != 'matching_dns_response':
            report['state'] = 'inconclusive_baseline_unavailable'
            return
        grant = store.issue(params)
        result = submit(params, grant)
        report['apply'] = result
        operation = result.get('operation_id')
        if result.get('ok') is not True:
            report['state'] = 'apply_not_verified'
            return
        report['during'] = [probe(address) for _ in range(2)]
        # A timeout alone cannot prove that Windows blocked a packet.
        blocked = all(r['state'] == 'response_unavailable' and r['windows_error'] == 10013
                      for r in report['during'])
        report['state'] = 'bounded_udp_denial_observed' if blocked else 'udp_acceptance_not_proven'
    except Exception as exc:
        report.update(state='failed_or_incomplete', error_type=type(exc).__name__)
    finally:
        # A lost reply can follow a durable claim. Recover its exact grant-bound
        # operation before revoking an apparently unused permission.
        if grant and not operation:
            try:
                with store._conn() as conn:
                    row = conn.execute('SELECT id FROM operations WHERE grant_id=?', (grant,)).fetchone()
                operation = row[0] if row else None
            except Exception as exc:
                report.update(state='recovery_required', lookup_error_type=type(exc).__name__)
        if operation:
            report['mutations'].append({'operation': 'restrict_network', 'operation_id': operation})
            try:
                report['recovery'] = reconcile(store, operation)
                if report['recovery'].get('ok') is True:
                    report['after'] = probe(address)
                    if report['after']['state'] != 'matching_dns_response':
                        report['state'] = 'post_restore_connectivity_not_verified'
                else:
                    report['state'] = 'recovery_required'
            except Exception as exc:
                report.update(state='recovery_required', recovery_error_type=type(exc).__name__)
        elif grant and report['state'] != 'recovery_required':
            try:
                store.revoke(grant)
            except Exception as exc:
                report.update(state='approval_cleanup_unknown', cleanup_error_type=type(exc).__name__)
        report['finished'] = datetime.now(timezone.utc).isoformat()
        try:
            win32file.WriteFile(handle, json.dumps(report, indent=2, allow_nan=False).encode())
            win32file.FlushFileBuffers(handle)
        finally:
            handle.Close()
        if report['state'] in {'recovery_required', 'approval_cleanup_unknown'}:
            raise RuntimeError('Retained recovery requires attention; no clean state is claimed')


if __name__ == '__main__':
    main(ACCEPTANCE)

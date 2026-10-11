"""Local ML-DSA-65 detached report signatures, with Windows user-DPAPI keys.

Trust the public-key fingerprint independently. A signature is not a publisher
certificate, an OS authorization, or quantum-safe network authentication.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.mldsa import MLDSA65PrivateKey, MLDSA65PublicKey
from agent.local_files import file_lock

CONTEXT = b'DVielle-local-report-signature-v1'
MAX_BYTES = 16 * 1024 * 1024


def _read(path: Path) -> bytes:
    path = Path(path)
    if path.is_symlink() or getattr(path.lstat(), 'st_file_attributes', 0) & 0x400:
        raise ValueError('Reparse report inputs are refused.')
    with path.open('rb') as stream:
        data = stream.read(MAX_BYTES + 1)
    if not data or len(data) > MAX_BYTES:
        raise ValueError('Report exceeds bounded signature input.')
    return data


def _directory(directory: Path) -> Path:
    if os.name != 'nt':
        raise RuntimeError('User-DPAPI key persistence requires Windows.')
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    # Reject reparse ancestry rather than letting an app-key directory redirect.
    for path in (directory, *directory.parents):
        if path.is_symlink() or getattr(path.lstat(), 'st_file_attributes', 0) & 0x400:
            raise ValueError('Reparse key ancestry is refused.')
    return directory


def _load_state(path: Path) -> dict:
    import win32crypt
    _, raw = win32crypt.CryptUnprotectData(_read(path), CONTEXT, None, None, 1)
    # Backward compatible with the original DPAPI-protected 32-byte seed.
    if len(raw) == 32:
        return {'schema_version': 2, 'seed': base64.b64encode(raw).decode(), 'retired': []}
    value = json.loads(raw)
    if (not isinstance(value, dict) or set(value) != {'schema_version', 'seed', 'retired'}
            or value['schema_version'] != 2 or not isinstance(value['retired'], list)
            or len(value['retired']) > 256):
        raise ValueError('Invalid protected key lifecycle.')
    MLDSA65PrivateKey.from_seed_bytes(base64.b64decode(value['seed'], validate=True))
    seen = set()
    for row in value['retired']:
        if (not isinstance(row, dict) or set(row) != {'fingerprint', 'state', 'retired_at'}
                or not _fingerprint_valid(row['fingerprint']) or row['fingerprint'] in seen
                or row['state'] not in {'retired', 'revoked'} or not isinstance(row['retired_at'], str)):
            raise ValueError('Invalid protected retired signer.')
        seen.add(row['fingerprint'])
    return value


def _fingerprint_valid(value) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(char in '0123456789abcdef' for char in value)


def _save_state(path: Path, state: dict, *, replace: bool) -> None:
    """One encrypted, write-through atomic lifecycle record; no plaintext seed file."""
    import win32crypt, win32security, win32api, win32con
    import pywintypes, win32file
    protected = win32crypt.CryptProtectData(json.dumps(state, sort_keys=True).encode(),
                                            'DVielle report signing', CONTEXT, None, None, 1)
    token = win32security.OpenProcessToken(win32api.GetCurrentProcess(), win32con.TOKEN_QUERY)
    try:
        sid = win32security.ConvertSidToStringSid(win32security.GetTokenInformation(token, win32security.TokenUser)[0])
    finally:
        token.Close()
    sa = pywintypes.SECURITY_ATTRIBUTES()
    sa.SECURITY_DESCRIPTOR = win32security.ConvertStringSecurityDescriptorToSecurityDescriptor(
        'D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;' + sid + ')', 1)
    temporary = path.with_name(path.name + '.' + secrets.token_hex(12) + '.dpapi') if replace else path
    handle = win32file.CreateFile(str(temporary), win32con.GENERIC_WRITE, 0, sa,
                                 win32con.CREATE_NEW, win32con.FILE_ATTRIBUTE_NORMAL, None)
    try:
        try:
            win32file.WriteFile(handle, protected)
            win32file.FlushFileBuffers(handle)
        finally:
            handle.Close()
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise
    if replace:
        try:
            # Reject a redirected destination before the write-through replacement.
            _read(path)
            win32file.MoveFileEx(str(temporary), str(path),
                                0x1 | 0x8)  # MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH
        finally:
            temporary.unlink(missing_ok=True)


def _key(directory: Path):
    directory = _directory(directory)
    with file_lock(directory / 'report-key.lock'):
        path = directory / 'report-signing-key.dpapi'
        if path.exists():
            state = _load_state(path)
            return MLDSA65PrivateKey.from_seed_bytes(base64.b64decode(state['seed'], validate=True))
        key = MLDSA65PrivateKey.generate()
        _save_state(path, {'schema_version': 2, 'seed': base64.b64encode(key.private_bytes_raw()).decode(),
                           'retired': []}, replace=False)
        return key


def report_key_status(directory: Path) -> dict:
    directory = _directory(directory)
    with file_lock(directory / 'report-key.lock'):
        path = directory / 'report-signing-key.dpapi'
        if not path.exists():
            return {'state': 'not_initialized', 'algorithm': 'ML-DSA-65', 'retired': []}
        state = _load_state(path)
        key = MLDSA65PrivateKey.from_seed_bytes(base64.b64decode(state['seed'], validate=True))
        return {'state': 'active', 'algorithm': 'ML-DSA-65',
                'key_fingerprint': hashlib.sha256(key.public_key().public_bytes_raw()).hexdigest(),
                'retired': state['retired'], 'scope': 'Local report signing only'}


def rotate_report_key(directory: Path, expected_fingerprint: str, *, revoke_previous: bool = False) -> dict:
    """Explicit compare-and-rotate; retire or revoke old trust and discard its seed."""
    if not _fingerprint_valid(expected_fingerprint) or type(revoke_previous) is not bool:
        raise ValueError('Exact independently retained current signer fingerprint required.')
    directory = _directory(directory)
    with file_lock(directory / 'report-key.lock'):
        path = directory / 'report-signing-key.dpapi'
        state = _load_state(path)
        previous = MLDSA65PrivateKey.from_seed_bytes(base64.b64decode(state['seed'], validate=True))
        fingerprint = hashlib.sha256(previous.public_key().public_bytes_raw()).hexdigest()
        if fingerprint != expected_fingerprint:
            raise ValueError('Current signer differs from approved rotation fingerprint.')
        if len(state['retired']) >= 256:
            raise ValueError('Retired signer registry is full; no history is silently discarded.')
        key = MLDSA65PrivateKey.generate()
        state['seed'] = base64.b64encode(key.private_bytes_raw()).decode()
        state['retired'].append({'fingerprint': fingerprint,
                                'state': 'revoked' if revoke_previous else 'retired',
                                'retired_at': datetime.now(timezone.utc).isoformat()})
        _save_state(path, state, replace=True)
        return {'state': 'rotated', 'previous_fingerprint': fingerprint,
                'previous_state': state['retired'][-1]['state'],
                'key_fingerprint': hashlib.sha256(key.public_key().public_bytes_raw()).hexdigest(),
                'scope': 'Local report signing only; externally retained trust must be updated explicitly.'}


def verify_local_report(path: Path, envelope: dict, directory: Path) -> dict:
    """Use the operator's local lifecycle registry; never trust envelope keys alone."""
    status = report_key_status(directory)
    if status['state'] != 'active' or not isinstance(envelope, dict):
        raise ValueError('No active local trust registry.')
    fingerprint = envelope.get('key_fingerprint')
    approved = {status['key_fingerprint']: 'active', **{row['fingerprint']: row['state'] for row in status['retired']}}
    if fingerprint not in approved or approved[fingerprint] == 'revoked':
        raise ValueError('Unknown or revoked local report signer.')
    result = verify_report(path, envelope, fingerprint)
    result['signer_lifecycle'] = approved[fingerprint]
    return result


def sign_report(path: Path, key_directory: Path) -> dict:
    data = _read(path)
    key = _key(key_directory)
    public = key.public_key().public_bytes_raw()
    message = {'schema_version': 1, 'algorithm': 'ML-DSA-65', 'report_sha256': hashlib.sha256(data).hexdigest(),
               'report_bytes': len(data), 'created_at': datetime.now(timezone.utc).isoformat()}
    encoded = json.dumps(message, sort_keys=True, separators=(',', ':')).encode()
    return {'signed': message, 'public_key': base64.b64encode(public).decode(),
            'signature': base64.b64encode(key.sign(encoded, CONTEXT)).decode(),
            'key_fingerprint': hashlib.sha256(public).hexdigest()}


def verify_report(path: Path, envelope: dict, trusted_fingerprint: str) -> dict:
    if not _fingerprint_valid(trusted_fingerprint):
        raise ValueError('An independently retained trusted fingerprint is required.')
    if not isinstance(envelope, dict) or set(envelope) != {'signed', 'public_key', 'signature', 'key_fingerprint'}:
        raise ValueError('Invalid detached signature envelope.')
    public = base64.b64decode(envelope['public_key'], validate=True)
    signature = base64.b64decode(envelope['signature'], validate=True)
    fingerprint = hashlib.sha256(public).hexdigest()
    if fingerprint != trusted_fingerprint or envelope['key_fingerprint'] != trusted_fingerprint:
        raise ValueError('Untrusted report signer; no trust-on-first-use is performed.')
    message = envelope['signed']
    if (not isinstance(message, dict) or set(message) != {'schema_version','algorithm','report_sha256','report_bytes','created_at'}
            or type(message['schema_version']) is not int or message['schema_version'] != 1
            or message['algorithm'] != 'ML-DSA-65' or type(message['report_bytes']) is not int):
        raise ValueError('Invalid signed report declaration.')
    data = _read(path)
    if message['report_bytes'] != len(data) or message['report_sha256'] != hashlib.sha256(data).hexdigest():
        raise ValueError('Report differs from signed bytes.')
    MLDSA65PublicKey.from_public_bytes(public).verify(signature,
        json.dumps(message, sort_keys=True, separators=(',', ':')).encode(), CONTEXT)
    return {'state': 'trusted_report_signature_verified', 'algorithm':'ML-DSA-65',
            'key_fingerprint':fingerprint, 'report_sha256':message['report_sha256'],
            'scope':'Local report bytes only; not OS authorization or network/publisher authentication.'}


def main() -> int:
    import argparse
    parser = argparse.ArgumentParser(description="D'Vielle local report-signing lifecycle")
    parser.add_argument('action', choices=('status', 'rotate', 'verify'))
    parser.add_argument('--key-directory', type=Path, required=True)
    parser.add_argument('--expected-fingerprint')
    parser.add_argument('--revoke-previous', action='store_true')
    parser.add_argument('--report', type=Path)
    parser.add_argument('--signature', type=Path)
    args = parser.parse_args()
    if args.action == 'rotate':
        if not args.expected_fingerprint:
            parser.error('Rotation requires the independently retained current fingerprint.')
        result = rotate_report_key(args.key_directory, args.expected_fingerprint,
                                   revoke_previous=args.revoke_previous)
    elif args.action == 'verify':
        if args.report is None or args.signature is None:
            parser.error('Verification requires --report and --signature.')
        envelope = json.loads(_read(args.signature))
        result = verify_local_report(args.report, envelope, args.key_directory)
    else:
        result = report_key_status(args.key_directory)
    print(json.dumps(result, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())

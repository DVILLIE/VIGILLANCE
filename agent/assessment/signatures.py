"""Local ML-DSA-65 detached report signatures, with Windows user-DPAPI keys.

Trust the public-key fingerprint independently. A signature is not a publisher
certificate, an OS authorization, or quantum-safe network authentication.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
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


def _key(directory: Path):
    if os.name != 'nt':
        raise RuntimeError('User-DPAPI key persistence requires Windows.')
    import win32crypt
    import win32security
    import win32api
    import win32con
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    # Reject reparse ancestry rather than letting an app-key directory redirect.
    for path in (directory, *directory.parents):
        if path.is_symlink() or getattr(path.lstat(), 'st_file_attributes', 0) & 0x400:
            raise ValueError('Reparse key ancestry is refused.')
    with file_lock(directory / 'report-key.lock'):
        path = directory / 'report-signing-key.dpapi'
        if path.exists():
            protected = _read(path)
            _, seed = win32crypt.CryptUnprotectData(protected, CONTEXT, None, None, 1)
            return MLDSA65PrivateKey.from_seed_bytes(seed)
        key = MLDSA65PrivateKey.generate()
        protected = win32crypt.CryptProtectData(key.private_bytes_raw(), 'DVielle report signing', CONTEXT, None, None, 1)
        # Exclusive creation; owner/Admin/SYSTEM ACL from the first file handle.
        import pywintypes, win32file
        token = win32security.OpenProcessToken(win32api.GetCurrentProcess(), win32con.TOKEN_QUERY)
        try:
            sid = win32security.ConvertSidToStringSid(win32security.GetTokenInformation(token, win32security.TokenUser)[0])
        finally:
            token.Close()
        sa = pywintypes.SECURITY_ATTRIBUTES()
        sa.SECURITY_DESCRIPTOR = win32security.ConvertStringSecurityDescriptorToSecurityDescriptor(
            'D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;' + sid + ')', 1)
        handle = win32file.CreateFile(str(path), win32con.GENERIC_WRITE, 0, sa, win32con.CREATE_NEW, win32con.FILE_ATTRIBUTE_NORMAL, None)
        try:
            win32file.WriteFile(handle, protected)
            win32file.FlushFileBuffers(handle)
        finally:
            handle.Close()
        return key


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
    if not isinstance(trusted_fingerprint, str) or len(trusted_fingerprint) != 64:
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

"""Exact runtime baselines. Operator digest approval is not publisher signing."""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path, PurePosixPath
import sys

from agent.privilege.protected_paths import assert_protected_path

MAX_FILES = 50000
MAX_MANIFEST = 16 * 1024 * 1024


def runtime_roots() -> dict[str, Path]:
    return {'application': Path(__file__).resolve().parents[2],
            'environment': Path(sys.prefix).resolve(), 'python': Path(sys.base_prefix).resolve()}


def _files(root: Path, prefixes: list[str]):
    for prefix in prefixes:
        path = root / prefix
        if not path.exists():
            continue
        pending = [path]
        while pending:
            item = pending.pop()
            if item.is_symlink() or getattr(item.lstat(), 'st_file_attributes', 0) & 0x400:
                raise PermissionError('Reparse runtime inputs are refused.')
            if item.is_dir():
                pending.extend(item.iterdir())
            elif item.is_file():
                # Include bytecode: CPython can load it even with -B enabled.
                yield item
            else:
                raise ValueError('Non-file runtime input.')


PREFIXES = {'application': ['agent', 'dvielle'], 'environment': ['Lib', 'Scripts'],
            'python': ['Lib', 'DLLs', 'python.exe', 'pythonw.exe', 'python3.dll', 'python312.dll', 'python314.dll']}


def inventory(roots: dict[str, Path]) -> dict:
    records = []
    for label, prefixes in PREFIXES.items():
        for path in _files(roots[label], prefixes):
            with path.open('rb') as stream:
                digest = hashlib.file_digest(stream, 'sha256').hexdigest()
            records.append({'root': label, 'path': path.relative_to(roots[label]).as_posix(),
                            'bytes': path.stat().st_size, 'sha256': digest})
            if len(records) > MAX_FILES:
                raise ValueError('Runtime inventory exceeds file bound.')
    if not records:
        raise ValueError('Empty runtime inventory.')
    return {'version': 1, 'files': sorted(records, key=lambda x: (x['root'], x['path']))}


def verify_manifest(manifest: Path, expected_sha256: str, roots: dict[str, Path], *, protected=True) -> dict:
    if not isinstance(expected_sha256, str) or not re.fullmatch('[a-f0-9]{64}', expected_sha256):
        raise ValueError('An independently approved exact manifest SHA256 is required.')
    if protected:
        if any(not root.is_absolute() for root in roots.values()):
            raise ValueError('Runtime roots must be absolute.')
        assert_protected_path(manifest)
        for root in roots.values():
            assert_protected_path(root)
    if manifest.stat().st_size > MAX_MANIFEST:
        raise ValueError('Oversized runtime manifest.')
    data = manifest.read_bytes()
    if hashlib.sha256(data).hexdigest() != expected_sha256:
        raise ValueError('Runtime manifest does not match the approved digest.')
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError('Duplicate manifest field.')
            result[key] = value
        return result
    payload = json.loads(data, object_pairs_hook=unique)
    if (not isinstance(payload, dict) or set(payload) != {'version', 'files'}
            or type(payload['version']) is not int or payload['version'] != 1
            or not isinstance(payload['files'], list) or not 0 < len(payload['files']) <= MAX_FILES):
        raise ValueError('Invalid runtime manifest schema.')
    seen = set()
    for record in payload['files']:
        if not isinstance(record, dict) or set(record) != {'root', 'path', 'bytes', 'sha256'}:
            raise ValueError('Invalid runtime record.')
        label, relative = record['root'], record['path']
        if label not in PREFIXES or not isinstance(relative, str):
            raise ValueError('Unknown runtime root.')
        parts = PurePosixPath(relative)
        if (not relative or '\\' in relative or ':' in relative or parts.is_absolute()
                or any(p in {'', '.', '..'} for p in relative.split('/'))
                or parts.parts[0] not in PREFIXES[label]
                or type(record['bytes']) is not int or record['bytes'] < 0
                or not isinstance(record['sha256'], str) or not re.fullmatch('[a-f0-9]{64}', record['sha256'])):
            raise ValueError('Unsafe or invalid runtime record.')
        identity = (label, relative.casefold())
        if identity in seen:
            raise ValueError('Duplicate runtime path.')
        seen.add(identity)
        path = roots[label].joinpath(*parts.parts)
        if protected:
            assert_protected_path(path)
    actual = inventory(roots)
    if payload != actual:
        raise ValueError('Missing, added or changed runtime inputs.')
    return {'state': 'approved_runtime_digest_verified' if protected else 'runtime_digest_verified_unprotected', 'files': len(seen),
            'manifest_sha256': expected_sha256, 'publisher_authenticated': False}


def verify_installed_identity(directory: Path) -> dict:
    receipt = directory / 'release_identity.json'
    assert_protected_path(receipt)
    if receipt.stat().st_size > 4096:
        raise ValueError('Oversized identity receipt.')
    payload = json.loads(receipt.read_text(encoding='utf-8'))
    if (not isinstance(payload, dict) or set(payload) != {'version', 'manifest_sha256'}
            or type(payload['version']) is not int or payload['version'] != 1):
        raise ValueError('Invalid identity receipt.')
    return verify_manifest(directory / 'runtime_manifest.json', payload['manifest_sha256'], runtime_roots())

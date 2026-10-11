"""Read-only local-model admission. Candidate provenance never grants execution."""
from __future__ import annotations

import hashlib
import math
from pathlib import Path

import psutil


def inspect_candidate(manifest: dict, directory: Path) -> dict:
    required = {'model_id', 'revision', 'license', 'artifacts', 'required_memory_bytes'}
    if not isinstance(manifest, dict) or set(manifest) != required:
        raise ValueError('Exact model provenance declaration required.')
    if (manifest['license'] not in {'Apache-2.0', 'MIT', 'BSD-3-Clause'}
            or not isinstance(manifest['revision'], str) or len(manifest['revision']) != 40
            or any(char not in '0123456789abcdef' for char in manifest['revision'])
            or not isinstance(manifest['model_id'], str) or len(manifest['model_id']) > 200):
        raise ValueError('Unreviewed model license or immutable revision.')
    budget = manifest['required_memory_bytes']
    if type(budget) is not int or not 0 < budget <= 8 * 1024 ** 3:
        raise ValueError('Bounded real model memory requirement required.')
    rows = manifest['artifacts']
    if not isinstance(rows, list) or not 1 <= len(rows) <= 32:
        raise ValueError('Bounded model artifact list required.')
    root = Path(directory).resolve(strict=True)
    for ancestor in (root, *root.parents):
        if ancestor.is_symlink() or getattr(ancestor.lstat(), 'st_file_attributes', 0) & 0x400:
            raise ValueError('Model reparse ancestry is refused.')
    observed, seen = [], set()
    for row in rows:
        if not isinstance(row, dict) or set(row) != {'filename','sha256','bytes'}:
            raise ValueError('Invalid artifact record.')
        name = row['filename']
        if (not isinstance(name, str) or Path(name).name != name or '/' in name or '\\' in name
                or ':' in name or name.casefold() in seen or Path(name).suffix not in {'.gguf','.safetensors','.json','.txt'}
                or type(row['bytes']) is not int or not 0 < row['bytes'] <= 4 * 1024 ** 3
                or not isinstance(row['sha256'], str) or len(row['sha256']) != 64
                or any(char not in '0123456789abcdef' for char in row['sha256'])):
            raise ValueError('Unsafe, duplicate or unbounded artifact.')
        seen.add(name.casefold())
        path = root / name
        if not path.exists():
            observed.append({'filename':name, 'state':'missing'})
            continue
        if path.is_symlink() or getattr(path.lstat(), 'st_file_attributes', 0) & 0x400:
            raise ValueError('Reparse artifact is refused.')
        with path.open('rb') as stream:
            checksum = hashlib.file_digest(stream, 'sha256').hexdigest()
        if path.stat().st_size != row['bytes'] or checksum != row['sha256']:
            raise ValueError('Model artifact differs from immutable provenance.')
        observed.append({'filename':name, 'state':'hash_matched'})
    memory = psutil.virtual_memory()
    ready = all(row['state'] == 'hash_matched' for row in observed)
    resource_ok = memory.available >= budget + 512 * 1024 ** 2
    return {'state':'execution_held', 'model_id':manifest['model_id'], 'revision':manifest['revision'],
            'artifacts':observed, 'artifacts_verified':ready, 'memory_admission':resource_ok,
            'available_memory_bytes':memory.available, 'required_memory_bytes':budget,
            'isolation':'not_verified', 'evaluation':'not_completed', 'execution_authorized':False,
            'fallback':'deterministic_evidence_linked_investigation',
            'holds':['Verify an exact isolated runtime with outbound denial and resource limits.',
                     'Evaluate evidence fidelity and benefit on held-out real cases before admission.']}

"""Package a local reviewed candidate; grants no publisher or SYSTEM authority."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import zipfile

ROOT = Path(__file__).resolve().parents[1]
FOLDERS = ('agent', 'dvielle', 'installer', 'scripts', 'assets', 'config', 'tests')
FILES = ('pyproject.toml', 'requirements.txt', 'README.md', 'LICENSE')


def files_under(root):
    pending = [root]
    while pending:
        path = pending.pop()
        if path.is_symlink() or getattr(path.lstat(), 'st_file_attributes', 0) & 0x400:
            raise ValueError('Reparse source inputs are refused.')
        if path.is_dir():
            if path.name != '__pycache__':
                pending.extend(sorted(path.iterdir()))
        elif path.is_file() and path.suffix != '.pyc' and path.name != '.env':
            yield path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--dependencies', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    if not (args.dependencies / 'manifest.json').is_file():
        raise ValueError('A completed verified dependency candidate is required.')
    dependency_manifest = json.loads((args.dependencies / 'manifest.json').read_text())
    if dependency_manifest.get('state') != 'verified_dependency_candidate' or dependency_manifest.get('target_python') != '3.14':
        raise ValueError('Python 3.14 verified dependency candidate required.')
    artifact_names = set()
    for artifact in dependency_manifest['artifacts']:
        name = artifact['filename']
        if Path(name).name != name or '/' in name or '\\' in name or ':' in name or name in artifact_names:
            raise ValueError('Unsafe or duplicate wheel record.')
        artifact_names.add(name)
        path = args.dependencies / 'wheels' / name
        with path.open('rb') as stream:
            digest = hashlib.file_digest(stream, 'sha256').hexdigest()
        if digest != artifact['sha256'] or path.stat().st_size != artifact['bytes']:
            raise ValueError('Dependency changed since PyPI verification.')
    if artifact_names != {path.name for path in (args.dependencies / 'wheels').iterdir()}:
        raise ValueError('Unlisted dependency artifact.')
    inputs = []
    for folder in FOLDERS:
        inputs.extend((path, path.relative_to(ROOT).as_posix()) for path in files_under(ROOT / folder))
    inputs.extend((ROOT / file, file) for file in FILES)
    for file in ('requirements.lock', 'manifest.json'):
        inputs.append((args.dependencies / file, 'offline-dependencies/' + file))
    inputs.extend((path, 'offline-dependencies/wheels/' + path.name) for path in files_under(args.dependencies / 'wheels'))
    if len(inputs) > 5000 or len({name.casefold() for _, name in inputs}) != len(inputs):
        raise ValueError('Duplicate or excessive archive inputs.')
    records = []
    with zipfile.ZipFile(args.output, 'x', zipfile.ZIP_DEFLATED) as archive:
        for path, name in sorted(inputs, key=lambda pair: pair[1]):
            if path.stat().st_size > 64 * 1024 * 1024:
                raise ValueError('Oversized archive input.')
            data = path.read_bytes()
            archive.writestr(name, data)
            records.append({'path': name, 'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()})
        archive.writestr('payload_manifest.json', json.dumps({'version': 1, 'files': records}, indent=2))
    with zipfile.ZipFile(args.output) as archive:
        if archive.testzip() is not None:
            raise ValueError('Archive CRC failure.')
    with args.output.open('rb') as stream:
        digest = hashlib.file_digest(stream, 'sha256').hexdigest()
    result = {'archive': str(args.output.resolve()), 'sha256': digest, 'files': len(records),
              'publisher_authenticated': False, 'installed': False}
    args.output.with_suffix('.json').write_text(json.dumps(result, indent=2), encoding='utf-8')
    print(json.dumps(result))


if __name__ == '__main__':
    main()

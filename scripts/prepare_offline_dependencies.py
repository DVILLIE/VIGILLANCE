"""Prepare an unprivileged Windows wheel candidate; never install downloaded code."""
from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import subprocess
import sys
import tomllib
import urllib.parse
import urllib.request
import zipfile
from email.parser import BytesParser

from packaging.requirements import Requirement
from packaging.utils import canonicalize_name, parse_wheel_filename

ROOT = Path(__file__).resolve().parents[1]


def wheel_record(path: Path) -> dict:
    name, version, _, _ = parse_wheel_filename(path.name)
    with zipfile.ZipFile(path) as archive:
        members = [item for item in archive.infolist()
                   if item.filename.count('/') == 1 and item.filename.endswith('.dist-info/METADATA')]
        if len(members) != 1 or members[0].file_size > 2_000_000:
            raise ValueError('Invalid wheel metadata: ' + path.name)
        metadata = BytesParser().parsebytes(archive.read(members[0]))
    if canonicalize_name(metadata['Name']) != name or str(version) != metadata['Version']:
        raise ValueError('Wheel identity mismatch: ' + path.name)
    with path.open('rb') as stream:
        digest = hashlib.file_digest(stream, 'sha256').hexdigest()
    return {'name': name, 'version': str(version), 'filename': path.name,
            'sha256': digest,
            'bytes': path.stat().st_size, 'requires': metadata.get_all('Requires-Dist', [])}


def verify_index(record: dict) -> dict:
    url = 'https://pypi.org/pypi/{}/{}/json'.format(
        urllib.parse.quote(record['name'], safe=''), urllib.parse.quote(record['version'], safe=''))
    with urllib.request.urlopen(url, timeout=30) as response:
        body = response.read(8_000_001)
    if len(body) > 8_000_000:
        raise ValueError('Oversized index metadata')
    matches = [item for item in json.loads(body)['urls'] if item['filename'] == record['filename']]
    if (len(matches) != 1 or matches[0]['digests']['sha256'] != record['sha256']
            or matches[0]['size'] != record['bytes'] or matches[0].get('yanked')):
        raise ValueError('PyPI artifact mismatch or yanked artifact: ' + record['filename'])
    return {'index_metadata': url, 'artifact_url': matches[0]['url']}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--verify-existing', action='store_true')
    parser.add_argument('--target-python', choices=['3.12', '3.14'], default='3.12')
    args = parser.parse_args()
    if os.name != 'nt' or sys.version_info[:2] != (3, 12):
        raise RuntimeError('Prepare with the Windows Python 3.12 target runtime.')
    import ctypes
    if ctypes.windll.shell32.IsUserAnAdmin():
        raise PermissionError('Dependency preparation must run without elevation.')
    destination = args.output.resolve()
    destination.mkdir(parents=True, exist_ok=args.verify_existing)
    wheels = destination / 'wheels'
    wheels.mkdir(exist_ok=args.verify_existing)
    project = tomllib.loads((ROOT / 'pyproject.toml').read_text(encoding='utf-8'))
    requirements = [Requirement(text) for text in project['project']['dependencies']]
    requirements += [Requirement(text) for text in project['project']['optional-dependencies']['windows']]
    requirements += [Requirement(text) for text in project['build-system']['requires']]
    roots = []
    for requirement in requirements:
        if requirement.marker and not requirement.marker.evaluate():
            continue
        version = importlib.metadata.version(requirement.name)
        if not requirement.specifier.contains(version):
            raise ValueError('Installed version violates project requirements: ' + str(requirement))
        roots.append(f'{requirement.name}=={version}')
    constraints = destination / 'observed-versions.txt'
    observed = sorted({f'{canonicalize_name(d.metadata["Name"])}=={d.version}'
                       for d in importlib.metadata.distributions() if d.metadata['Name']})
    constraints.write_text('\n'.join(observed) + '\n', encoding='utf-8')
    target = ['--python-version', args.target_python, '--implementation', 'cp',
              '--abi', 'cp' + args.target_python.replace('.', ''), '--platform', 'win_amd64']
    if not args.verify_existing:
        subprocess.run([sys.executable, '-I', '-m', 'pip', '--isolated', '--disable-pip-version-check',
            'download', '--index-url', 'https://pypi.org/simple', '--only-binary=:all:',
            '--no-cache-dir', '--dest', str(wheels), '--constraint', str(constraints), *target, *roots],
            check=True, timeout=600)
    records = []
    for path in sorted(wheels.iterdir()):
        if path.suffix != '.whl' or path.is_symlink():
            raise ValueError('Only wheel artifacts are accepted.')
        record = wheel_record(path)
        record.update(verify_index(record))
        records.append(record)
    if not records or len({r['name'] for r in records}) != len(records):
        raise ValueError('Empty or duplicate dependency artifacts')
    identities = {f"{canonicalize_name(r['name'])}=={r['version']}" for r in records}
    expected = {f'{canonicalize_name(root.split("==", 1)[0])}=={root.split("==", 1)[1]}' for root in roots}
    if not expected.issubset(identities):
        raise ValueError('Missing required project or build dependency')
    lock = '\n'.join(f"{r['name']}=={r['version']} --hash=sha256:{r['sha256']}" for r in records) + '\n'
    (destination / 'requirements.lock').write_text(lock, encoding='utf-8')
    # Verify the entire dependency closure offline; this downloads nothing new
    # and executes no wheel installation or source build.
    verification = destination / 'closure-check'
    subprocess.run([sys.executable, '-I', '-m', 'pip', '--isolated', '--disable-pip-version-check',
        'download', '--no-index', '--find-links', str(wheels), '--require-hashes',
        '--only-binary=:all:', '--no-cache-dir', '--dest', str(verification),
        '--requirement', str(destination / 'requirements.lock'), *target], check=True, timeout=120)
    manifest = {'version': 1, 'state': 'verified_dependency_candidate',
        'publisher_authenticated': False, 'preparation_python': sys.version, 'target_python': args.target_python,
        'roots': roots, 'artifacts': records}
    (destination / 'manifest.json').write_text(json.dumps(manifest, indent=2), encoding='utf-8')
    print(json.dumps({'output': str(destination), 'wheels': len(records),
                      'installed': False, 'publisher_authenticated': False}))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())

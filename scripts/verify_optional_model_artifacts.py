"""Verify a real immutable publisher artifact; never load or execute model weights."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import tempfile
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from agent.assessment.model_admission import inspect_candidate
from agent.local_files import atomic_text

MODEL_ID = 'HuggingFaceTB/SmolLM2-135M-Instruct'
REVISION = '12fd25f77366fa6b3b4b768ec3050bf629380bac'
ARTIFACT = {'filename': 'model.safetensors', 'sha256':
            '5af571cbf074e6d21a03528d2330792e532ca608f24ac70a143f6b369968ab8c',
            'bytes': 269060552}
MANIFEST = {'model_id': MODEL_ID, 'revision': REVISION, 'license': 'Apache-2.0',
            'required_memory_bytes': 805306368, 'artifacts': [ARTIFACT]}


def verify(directory: Path) -> dict:
    directory.mkdir(parents=True, exist_ok=True)
    # Admission validates ancestry before any remote bytes are persisted.
    inspect_candidate(MANIFEST, directory)
    metadata_url = f'https://huggingface.co/api/models/{MODEL_ID}/revision/{REVISION}?blobs=true'
    with urllib.request.urlopen(metadata_url, timeout=30) as response:
        raw = response.read(2 * 1024 * 1024 + 1)
    if len(raw) > 2 * 1024 * 1024:
        raise ValueError('Publisher metadata exceeds bounded size')
    metadata = json.loads(raw)
    rows = [row for row in metadata.get('siblings', []) if row.get('rfilename') == ARTIFACT['filename']]
    if (metadata.get('sha') != REVISION or metadata.get('cardData', {}).get('license') != 'apache-2.0'
            or len(rows) != 1 or rows[0].get('lfs', {}).get('sha256') != ARTIFACT['sha256']
            or rows[0].get('lfs', {}).get('size') != ARTIFACT['bytes']):
        raise ValueError('Publisher metadata differs from reviewed immutable artifact')
    destination = directory / ARTIFACT['filename']
    downloaded = False
    if not destination.exists():
        descriptor, name = tempfile.mkstemp(prefix='model-', suffix='.partial', dir=directory)
        temporary = Path(name)
        try:
            checksum, size = hashlib.sha256(), 0
            url = f'https://huggingface.co/{MODEL_ID}/resolve/{REVISION}/{ARTIFACT["filename"]}'
            with os.fdopen(descriptor, 'wb') as stream:
                with urllib.request.urlopen(url, timeout=60) as response:
                    while chunk := response.read(1024 * 1024):
                        size += len(chunk)
                        if size > ARTIFACT['bytes']:
                            raise ValueError('Publisher artifact exceeds approved size')
                        checksum.update(chunk)
                        stream.write(chunk)
                stream.flush()
                os.fsync(stream.fileno())
            if size != ARTIFACT['bytes'] or checksum.hexdigest() != ARTIFACT['sha256']:
                raise ValueError('Downloaded model bytes do not match reviewed artifact')
            # Never replace an artifact another concurrent verifier has created.
            if destination.exists():
                raise FileExistsError('Candidate appeared during verification; reobserve it')
            os.rename(temporary, destination)
            downloaded = True
        finally:
            temporary.unlink(missing_ok=True)
    admission = inspect_candidate(MANIFEST, directory)
    if not admission['artifacts_verified']:
        raise ValueError('Actual model artifact verification did not complete')
    return {'observed_at': datetime.now(timezone.utc).isoformat(),
            'state': 'real_publisher_artifact_hash_verified', 'publisher_metadata': metadata_url,
            'manifest': MANIFEST, 'weights_downloaded_this_run': downloaded, 'admission': admission,
            'execution_performed': False, 'model_evaluation': 'not_performed',
            'license_scope': 'Immutable publisher card declaration; no redistribution of model weights',
            'measurement_environment': 'github-hosted' if os.environ.get('RUNNER_ENVIRONMENT') == 'github-hosted' else 'local'}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    result = verify(args.directory)
    atomic_text(args.output, json.dumps(result, indent=2))
    print(json.dumps({'state': result['state'], 'model_id': MODEL_ID,
                      'execution_performed': False, 'memory_admission': result['admission']['memory_admission']}))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())

"""Export actual installed Python distributions as SPDX 2.3 package inventory.

This is a package inventory, not binary provenance or license clearance.
Run with the intended runtime; no download, installation or upload occurs.
"""
from __future__ import annotations

import argparse
import importlib.metadata
import json
import platform
import sys
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from agent.local_files import atomic_text


def main():
    parser = argparse.ArgumentParser(description="D'Vielle installed runtime package SBOM")
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    packages = []
    relationships = []
    for index, distribution in enumerate(sorted(importlib.metadata.distributions(),
            key=lambda item: (item.metadata.get('Name', '').lower(), item.version))):
        metadata = distribution.metadata
        identifier = 'SPDXRef-Package-' + str(index)
        license_text = metadata.get('License-Expression') or metadata.get('License') or 'Not supplied'
        packages.append({'SPDXID': identifier, 'name': metadata.get('Name', 'UNKNOWN'),
            'versionInfo': distribution.version, 'downloadLocation': 'NOASSERTION',
            'filesAnalyzed': False, 'licenseConcluded': 'NOASSERTION',
            'licenseDeclared': 'NOASSERTION', 'copyrightText': 'NOASSERTION',
            'comment': 'Unverified distribution license metadata: ' + license_text[:4096]})
        relationships.append({'spdxElementId': 'SPDXRef-DOCUMENT',
                              'relationshipType': 'DESCRIBES', 'relatedSpdxElement': identifier})
    document = {'spdxVersion': 'SPDX-2.3', 'dataLicense': 'CC0-1.0',
        'SPDXID': 'SPDXRef-DOCUMENT', 'name': "D'Vielle actual Python runtime package inventory",
        'documentNamespace': 'https://spdx.org/spdxdocs/dvielle-' + str(uuid4()),
        'creationInfo': {'creators': ['Tool: DVielle-export-runtime-sbom'],
            'created': datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')},
        'documentComment': 'Actual importlib.metadata inventory under Python ' + platform.python_version()
            + '. No artifact hashes, publisher provenance, OS/native dependency completeness, dependency resolution or license approval asserted.',
        'packages': packages, 'relationships': relationships}
    atomic_text(args.output, json.dumps(document, indent=2, allow_nan=False))
    print(json.dumps({'packages': len(packages), 'spdxVersion': document['spdxVersion']}))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())

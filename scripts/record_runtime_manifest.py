"""Record real runtime hashes for review; never authorize or install a service."""
import argparse
import hashlib
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from agent.privilege.release_identity import inventory, runtime_roots


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    data = json.dumps(inventory(runtime_roots()), sort_keys=True, indent=2).encode('utf-8')
    with args.output.open('xb') as stream:
        stream.write(data)
    print(json.dumps({'manifest': str(args.output.resolve()), 'sha256': hashlib.sha256(data).hexdigest(),
                      'authorized': False, 'publisher_authenticated': False}))


if __name__ == '__main__':
    main()

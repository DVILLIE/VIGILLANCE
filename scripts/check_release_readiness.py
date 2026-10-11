"""Explicit read-only installed prerequisite check with optional saved report."""
import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from agent.local_files import atomic_text
from agent.privilege.readiness import inspect_readiness


def main():
    parser = argparse.ArgumentParser(description="D'Vielle read-only release readiness")
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    report = inspect_readiness()
    if args.output:
        atomic_text(args.output, json.dumps(report, indent=2))
    print(json.dumps(report, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())

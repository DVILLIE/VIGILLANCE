"""Explicit local/authorized-origin assessment CLI."""
from __future__ import annotations

import argparse
import json
import threading
import time
from pathlib import Path

from agent.assessment import AssessmentEngine, AssessmentScope


def main() -> int:
    parser = argparse.ArgumentParser(description="D'Vielle scoped ethical assessment")
    parser.add_argument("--directory", type=Path, required=True, help="Local evidence directory")
    parser.add_argument("--target", default="local", help="local or one authorized HTTP(S) origin")
    parser.add_argument("--authority", default="Local computer read-only review")
    parser.add_argument("--authorize-origin", action="store_true", help="Confirm your authority for this origin")
    parser.add_argument("--share-runtime-versions", action="store_true",
                        help="Authorize sharing runtime package names/versions with OSV for this run")
    parser.add_argument("--output", type=Path, help="Export redacted JSON evidence")
    parser.add_argument('--sign-export', action='store_true', help='Sign exported bytes with a local Windows user-DPAPI protected ML-DSA-65 key')
    args = parser.parse_args()
    if args.sign_export and args.output is None:
        parser.error('--sign-export requires --output')
    scope = AssessmentScope(args.target, args.authority,
                            args.authorize_origin if args.target != "local" else args.share_runtime_versions,
                            time.time() + 300, args.share_runtime_versions)
    engine = AssessmentEngine(args.directory)
    stop = threading.Event()
    try:
        report = engine.run(scope, stop)
    except (ValueError, TimeoutError) as exc:
        parser.error(str(exc))
    except KeyboardInterrupt:
        stop.set()
        return 130
    if args.output:
        engine.export(report["id"], args.output)
        if args.sign_export:
            from agent.assessment.signatures import sign_report
            from agent.local_files import atomic_text
            envelope = sign_report(args.output, args.directory / 'security')
            atomic_text(args.output.with_suffix(args.output.suffix + '.sig.json'), json.dumps(envelope, indent=2))
    print(json.dumps({"id": report["id"], "state": report["state"],
                      "review_items": len(report["findings"]), "mutations": report["mutations"]}))
    return 0 if report["state"] == "completed" else 1


if __name__ == "__main__":
    raise SystemExit(main())

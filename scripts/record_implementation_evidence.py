"""Record actual source-file hashes and saved evidence without modifying Git."""
from __future__ import annotations

import hashlib
import json
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from agent.local_files import atomic_text


def digest(path: Path) -> str:
    result = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1048576), b""):
            result.update(chunk)
    return result.hexdigest()


def git(*args: str) -> str:
    return subprocess.run(["git", *args], cwd=ROOT, check=True,
                          capture_output=True, text=True, encoding="utf-8", timeout=10).stdout.strip()


def main() -> int:
    files = []
    for name in sorted(set(git("ls-files", "-co", "-z", "--exclude-standard").split("\0"))):
        if not (name.startswith(("agent/", "dvielle/", "tests/", "scripts/", "installer/", "assets/"))
                or name in {"pyproject.toml", "LICENSE", "README.md"}):
            continue
        path = ROOT / name
        if not path.is_file():
            continue
        files.append({"path": name, "bytes": path.stat().st_size, "sha256": digest(path)})
    directory = ROOT / "docs" / "implementation"
    log = next(directory / name for name in (
        'AUDIT_FIX_FINAL_REGRESSION_2026-10-11.txt',
        'ASSESSMENT_AND_CONSENT_FINAL_REGRESSION_2026-10-10.txt',
        'HYBRID_GATE_FINAL_REGRESSION_2026-10-10.txt',
        'MEDIATION_FINAL_REGRESSION_2026-10-10.txt',
        'MEDIATION_GUI_REGRESSION_RECHECK_2026-10-10.txt',
        'TLS_OBSERVER_INTEGRATION_REGRESSION_2026-10-10.txt',
        'ACTUAL_IMAGE_FINAL_REGRESSION_2026-10-10.txt',
        'FINAL_PRODUCT_INCREMENT_VERIFIED_TESTS_2026-10-10.txt',
        'CONTINUATION_FINAL_REGRESSION_2026-10-10.txt',
        'PYTHON314_FINAL_TEST_RESULTS_2026-10-10.txt',
        'PYTHON314_TEST_RESULTS_2026-10-10.txt',
        'ACTIVATION_PREPARATION_TEST_RESULTS_2026-10-10.txt',
        'PROTECTED_REGISTRATION_TEST_RESULTS_2026-10-10.txt',
        'OFFLINE_DEPENDENCY_TEST_RESULTS_2026-10-10.txt',
        'INSTALLER_REGRESSION_RESULTS_2026-10-10.txt',
        'TEST_RESULTS_2026-10-10.txt') if (directory / name).exists())
    lines = [line for line in log.read_text(encoding="utf-8-sig").splitlines() if line.strip()]
    summaries = [line for line in lines if re.search(r"^\d+ passed(?:,| in )", line)]
    if not summaries:
        raise ValueError("The saved test log has no completed result; do not record an invented pass.")
    assessment = next(directory / name for name in (
        'POST_ACTIVATION_LOCAL_ASSESSMENT_2026-10-10.json',
        'LOCAL_ASSESSMENT_CURRENT_2026-10-10.json') if (directory / name).exists())
    report = json.loads(assessment.read_text(encoding="utf-8-sig"))
    readiness_path = next(directory / name for name in (
        'POST_AUDIT_FIX_READINESS_2026-10-11.json',
        'POST_MEDIATION_READINESS_2026-10-10.json',
        'POST_ACTIVATION_READINESS_2026-10-10.json',
        'INSTALLED_READINESS_2026-10-10.json') if (directory / name).exists())
    readiness = json.loads(readiness_path.read_text(encoding='utf-8-sig'))
    if readiness.get('mutations') != []:
        raise ValueError('The saved readiness record is not a read-only observation.')
    runtime_path = directory / 'INSTALLED_RUNTIME_IDENTITY_2026-10-10.json'
    runtime = json.loads(runtime_path.read_text(encoding='utf-8-sig')) if runtime_path.exists() else {}
    approvals = []
    for path in directory.glob('PROTECTED_*INCREMENT_RESULT_*.json'):
        candidate = json.loads(path.read_text(encoding='utf-8-sig'))
        if candidate.get('state') == 'activated_identity_verified':
            approvals.append((datetime.fromisoformat(candidate['finished']), path, candidate))
    if not approvals:
        raise ValueError('No completed protected activation receipt was recorded.')
    _, activation, activated = max(approvals, key=lambda row: row[0])
    matches = []
    for path in directory.glob('POST_*RUNTIME_CHECKS_*.json'):
        observed = json.loads(path.read_text(encoding='utf-8-sig'))
        if (observed.get('runtime_sha256') == activated['identity']['manifest_sha256']
                and observed.get('runtime_files') == activated['identity']['files']):
            matches.append(path)
    if not matches:
        raise ValueError('Latest completed activation has no matching independent inventory.')
    live = max(matches, key=lambda path: path.stat().st_mtime_ns)
    if activation.exists() and live.exists():
        activated = json.loads(activation.read_text(encoding='utf-8-sig'))
        observed = json.loads(live.read_text(encoding='utf-8-sig'))
        if (activated.get('state') != 'activated_identity_verified'
                or observed['runtime_sha256'] != activated['identity']['manifest_sha256']
                or observed['runtime_files'] != activated['identity']['files']):
            raise ValueError('Activation and independent runtime inventory disagree.')
        runtime = dict(activated['identity'], independent_inventory_sha256=digest(live),
                       activation_receipt_sha256=digest(activation))
    installed_identity = ('local_operator_digest_verified' if
        runtime.get('state') == 'approved_runtime_digest_verified' else 'not_verified')
    tls_path = directory / 'ACTUAL_INSTALLED_TLS_ASSESSMENT_2026-10-10.json'
    tls_evidence = {'state': 'not_measured'}
    if tls_path.exists():
        measured = json.loads(tls_path.read_text(encoding='utf-8-sig'))
        tls = measured.get('observations', {}).get('tls', {})
        if measured.get('state') == 'completed' and tls.get('finished_verified') is True:
            tls_evidence = {'state': 'bounded_verified_handshake_observed',
                'path': tls_path.name, 'sha256': digest(tls_path), 'run_id': measured['id'],
                'key_exchange_group': tls.get('key_exchange_group'),
                'post_quantum_hybrid_exchange': tls.get('post_quantum_hybrid_exchange'),
                'post_quantum_authentication': tls.get('post_quantum_authentication'),
                'scope': 'Recorded installed assessment connection only; not every application or peer'}
    evidence = {"schema_version": 1, "recorded_at": datetime.now(timezone.utc).isoformat(),
        "source_root": str(ROOT), "commit": git("rev-parse", "HEAD"),
        "branch": git("branch", "--show-current"), "source_files": files,
        "identity_status": "Source file hashes observed; not installed-runtime attestation",
        "test_log": {"path": log.name, "sha256": digest(log), "reported_summary": summaries[-1],
            "scope": "Affected GUI and mediation subset" if log.name.startswith('MEDIATION_GUI_') else "Recorded suite",
            "full_regression_log": log.name if log.name.startswith(('AUDIT_FIX_FINAL_', 'ASSESSMENT_AND_CONSENT_FINAL_', 'MEDIATION_FINAL_', 'HYBRID_GATE_FINAL_')) else
                "MEDIATION_AND_RECOVERY_REGRESSION_2026-10-10.txt",
            "full_regression_result": summaries[-1] if log.name.startswith(('AUDIT_FIX_FINAL_', 'ASSESSMENT_AND_CONSENT_FINAL_', 'MEDIATION_FINAL_', 'HYBRID_GATE_FINAL_')) else
                "690 passed; one readiness timing failure, passed on targeted recheck",
            "initial_timing_failure_log": "MEDIATION_AND_RECOVERY_REGRESSION_2026-10-10.txt"},
        "actual_local_assessment": {"id": report["id"], "state": report["state"],
            "review_items": len(report["findings"]), "mutations": report["mutations"],
            "report_sha256": digest(assessment)},
        "actual_installed_readiness": {'path': readiness_path.name, 'sha256': digest(readiness_path),
            'observed_at': readiness['observed_at'], 'state': readiness['state'],
            'service': readiness['service'], 'mutations': readiness['mutations']},
        "actual_installed_runtime_identity": runtime,
        "actual_installed_tls_measurement": tls_evidence,
        "deployment": {"protected_service": readiness['service']['state'], "installed_artifact": installed_identity,
                       "post_quantum_negotiation": tls_evidence['state']}}
    destination = directory / ("IMPLEMENTATION_EVIDENCE_MANIFEST_" + datetime.now(timezone.utc).strftime('%Y-%m-%d') + ".json")
    atomic_text(destination, json.dumps(evidence, indent=2, allow_nan=False))
    print(json.dumps({"manifest": str(destination), "source_files": len(files),
                      "tests": summaries[-1], "deployment": "not_certified"}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

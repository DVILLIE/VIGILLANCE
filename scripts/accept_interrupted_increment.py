"""Actual operator-approved abrupt-worker exit and immediate recovery experiment.

ACCEPTANCE is embedded in a reviewed immutable command. An exact leased archive
contains the reviewed fault worker, recovery code and harmless comment increment.
No generic helper command or production failure-injection flag is introduced.
"""
import base64
import hashlib
import json
import subprocess
import sys
import zipfile
from pathlib import Path


def main(acceptance):
    from agent.privilege.helper import _is_elevated
    from agent.privilege.service_host import assert_runtime_trust, installed_configuration
    from agent.privilege.release_identity import verify_installed_identity, runtime_roots, inventory
    from agent.privilege.protected_paths import assert_protected_path
    from agent.privilege.target import executable_lease
    from agent.local_files import atomic_text
    if not _is_elevated():
        raise PermissionError('Explicit Windows Administrator approval required')
    assert_runtime_trust(require_system=False)
    directory, _ = installed_configuration()
    before = verify_installed_identity(directory)
    plan = acceptance['plan']
    if before['manifest_sha256'] != plan['old_runtime_sha256']:
        raise ValueError('Predecessor differs from approved acceptance identity')
    archive = acceptance['archive']
    with executable_lease(archive) as leased:
        if leased['sha256'] != acceptance['archive_sha256']:
            raise ValueError('Fault archive differs from reviewed exact bytes')
        with zipfile.ZipFile(archive) as z:
            if z.namelist() != ['fault_worker.py', 'recovery.py', 'readiness.py']:
                raise ValueError('Unexpected acceptance archive input')
            payloads = {name: z.read(name) for name in z.namelist()}
    if any(len(data) > 131072 for data in payloads.values()):
        raise ValueError('Oversized acceptance code')
    app = runtime_roots()['application']
    stage = Path(plan['stage'])
    if stage.parent != app.parent or not stage.name.startswith('DVielleStage-'):
        raise ValueError('Unsafe acceptance stage')
    stage.mkdir()
    assert_protected_path(stage)
    destination = stage / 'agent' / 'privilege' / 'readiness.py'
    atomic_text(destination, payloads['readiness.py'].decode('utf-8'))
    assert_protected_path(destination)
    if hashlib.sha256(destination.read_bytes()).hexdigest() != plan['changes'][0]['new_sha256']:
        raise ValueError('Acceptance source does not match approved plan')
    worker = 'import base64,json;PLAN=json.loads(base64.b64decode(' + repr(
        base64.b64encode(json.dumps(plan).encode()).decode()) + '));exec(base64.b64decode(' + repr(
        base64.b64encode(payloads['fault_worker.py']).decode()) + '))'
    if len(worker) > 28000:
        raise ValueError('Fault-worker command exceeds bounded Windows input')
    report = {'scope': 'Actual abrupt upgrade-worker exit after one harmless comment source replacement',
              'state': 'started', 'before': before, 'backup_name': acceptance['backup_name'],
              'network_mutations': [], 'power_loss_acceptance': 'not_tested'}
    try:
        worker_result = subprocess.run([sys.executable, '-I', '-B', '-c', worker], cwd=app,
                                      capture_output=True, timeout=120)
        report['worker_exit_code'] = worker_result.returncode
        report['replacement_observed'] = hashlib.sha256((app / plan['changes'][0]['path']).read_bytes()).hexdigest() == plan['changes'][0]['new_sha256']
        if worker_result.returncode != 23 or not report['replacement_observed']:
            raise RuntimeError('Deliberate interruption was not observed at the approved checkpoint')
        report['state'] = 'actual_interruption_observed'
    except Exception as exc:
        report.update(state='interruption_experiment_failed', error_type=type(exc).__name__)
    finally:
        backup = directory / acceptance['backup_name']
        if backup.exists():
            try:
                namespace = {'__name__': 'reviewed_recovery_snapshot'}
                exec(compile(payloads['recovery.py'], '<reviewed-recovery-snapshot>', 'exec'), namespace)
                restored = namespace['recover'](plan, acceptance['backup_name'])
                report['recovery'] = {'state': restored['state'], 'identity': restored['identity']}
                report['after'] = verify_installed_identity(directory)
                if report.get('worker_exit_code') == 23 and report.get('replacement_observed'):
                    report['state'] = 'actual_interruption_and_predecessor_recovery_passed'
            except Exception as exc:
                report.update(state='manual_recovery_required', recovery_error=str(exc))
        else:
            report['recovery'] = {'state': 'no_backup_observed_no_recovery_claimed'}
        atomic_text(app / 'actual-upgrade-interruption-20261010.json', json.dumps(report, indent=2))
    if report['state'] != 'actual_interruption_and_predecessor_recovery_passed':
        raise RuntimeError('Interrupted-upgrade acceptance did not pass; inspect protected result')


if __name__ == '__main__':
    main(ACCEPTANCE)

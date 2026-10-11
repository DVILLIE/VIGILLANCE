"""Exact two-launcher repair; embed PLAN in an immutable elevated snapshot."""
import base64
import hashlib
import json
from pathlib import Path
from uuid import uuid4


def main(plan):
    from agent.local_files import atomic_text, file_lock
    from agent.privilege.helper import _is_elevated
    from agent.privilege.protected_paths import assert_protected_path
    from agent.privilege.service_host import assert_runtime_trust, installed_configuration
    from agent.privilege.release_identity import verify_installed_identity, runtime_roots
    if not _is_elevated():
        raise PermissionError('Windows Administrator approval required')
    assert_runtime_trust(require_system=False)
    directory, _ = installed_configuration()
    app = runtime_roots()['application']
    if len(plan) != 2 or {item['path'] for item in plan} != {
            'installer/Install-DVielle.bat', 'installer/Launch-DVielle.bat'}:
        raise ValueError('Only the exact two installed launchers are admitted')
    digest = lambda data: hashlib.sha256(data).hexdigest()
    changes = []
    report = {'state': 'preflight', 'runtime_changed': False, 'firewall_mutations': []}
    with file_lock(directory / 'service-registration.lock'):
        verify_installed_identity(directory)
        for item in plan:
            target = app / item['path']
            assert_protected_path(target)
            before = target.read_bytes()
            after = base64.b64decode(item['payload'], validate=True)
            if digest(before) != item['old_sha256'] or digest(after) != item['new_sha256']:
                raise ValueError('Launcher bytes differ from exact approved repair')
            changes.append((target, before, after))
        backup = directory / ('launcher-repair-' + uuid4().hex)
        backup.mkdir()
        assert_protected_path(backup)
        changed = []
        try:
            for target, before, after in changes:
                atomic_text(backup / target.name, before.decode('utf-8'))
            atomic_text(backup / 'plan.json', json.dumps(plan, indent=2))
            for target, before, after in changes:
                changed.append((target, before, after))
                atomic_text(backup / 'journal.json', json.dumps({'state': 'applying',
                    'change_intents': [str(entry[0]) for entry in changed]}))
                atomic_text(target, after.decode('utf-8'))
                assert_protected_path(target)
                if target.read_bytes() != after:
                    raise ValueError('Launcher replacement readback differs')
            report.update(state='launcher_bytes_verified', identity=verify_installed_identity(directory),
                          changed=[str(entry[0]) for entry in changed], backup=str(backup))
        except Exception:
            report['state'] = 'manual_recovery_required'
            for target, before, after in reversed(changed):
                if target.read_bytes() not in {before, after}:
                    raise RuntimeError('External launcher edit blocks conditional restoration')
                atomic_text(target, before.decode('utf-8'))
            report['state'] = 'failed_predecessor_restored'
            raise
        finally:
            atomic_text(backup / 'journal.json', json.dumps(report, indent=2))
            atomic_text(app / ('launcher-result-' + backup.name + '.json'), json.dumps(report, indent=2))


if __name__ == '__main__':
    main(PLAN)

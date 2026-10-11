"""Operator-approved, backed-up application-only increment.

Execute an immutable snapshot with the protected installed interpreter; PLAN must
be embedded in that snapshot. Never elevate a mutable source filename. Does not
update dependencies, service registration, grants, or network rules. A crash leaves
the durable private journal and backups for explicit recovery, not silent success.
"""
from __future__ import annotations
import hashlib
import json
import time
from pathlib import Path
from datetime import datetime, timezone
from uuid import uuid4


def sha(data):
    return hashlib.sha256(data).hexdigest()


def main(plan):
    import win32service as svc
    import win32com.client
    import win32security
    from agent.local_files import atomic_text, file_lock
    from agent.privilege.helper import _is_elevated
    from agent.privilege.protected_paths import assert_protected_path
    from agent.privilege.release_identity import inventory, runtime_roots, verify_installed_identity
    from agent.privilege.service_host import assert_runtime_trust, installed_configuration, SERVICE_NAME
    from agent.privilege.service_install import assert_service_security, binary_command
    from agent.privilege.grants import GrantStore
    if not _is_elevated():
        raise PermissionError('Explicit Windows Administrator approval required')
    assert_runtime_trust(require_system=False)
    directory, sid = installed_configuration()
    roots = runtime_roots()
    app = roots['application']
    stage = Path(plan['stage'])
    if stage.parent != app.parent or not stage.name.startswith('DVielleStage-'):
        raise ValueError('Stage must be a protected sibling in Program Files')
    assert_protected_path(stage)
    if not 0 < len(plan['changes']) <= 100:
        raise ValueError('Invalid increment size')
    payloads = {}
    for change in plan['changes']:
        name = change['path']
        parts = name.split('/')
        if parts[0] not in {'agent', 'dvielle'} or not name.endswith('.py') or any(
                p in {'', '.', '..'} or '\\' in p or ':' in p for p in parts):
            raise ValueError('Only bounded application Python files are admitted')
        if name in payloads:
            raise ValueError('Duplicate change')
        source = stage.joinpath(*parts)
        assert_protected_path(source)
        data = source.read_bytes()
        if len(data) > 1048576 or sha(data) != change['new_sha256']:
            raise ValueError('Staged increment differs from approved bytes')
        compile(data, name, 'exec')
        target = app.joinpath(*parts)
        assert_protected_path(target if target.exists() else target.parent)
        if (sha(target.read_bytes()) if target.exists() else None) != change['old_sha256']:
            raise ValueError('Predecessor file differs from approved increment')
        payloads[name] = data
    manager = svc.OpenSCManager(None, None, svc.SC_MANAGER_CONNECT)
    handle = svc.OpenService(manager, SERVICE_NAME, svc.SERVICE_QUERY_CONFIG |
        svc.SERVICE_QUERY_STATUS | svc.SERVICE_STOP | svc.SERVICE_START | 0x20000)
    task = None
    task_enabled = None
    initial_running = False
    backup = None
    changed = []
    report = {'started': datetime.now(timezone.utc).isoformat(), 'state': 'preflight',
              'plan': plan, 'firewall_mutations': [], 'grants_preserved': True}

    def wait_state(state):
        deadline = time.monotonic() + 40
        while time.monotonic() < deadline:
            if svc.QueryServiceStatusEx(handle)['CurrentState'] == state:
                return
            time.sleep(.2)
        raise TimeoutError('Helper service state transition timed out')

    def save():
        atomic_text(backup / 'journal.json', json.dumps(report, indent=2))

    try:
        with file_lock(directory / 'service-registration.lock'):
            assert_service_security(handle)
            config = svc.QueryServiceConfig(handle)
            if config[3] != binary_command() or config[7].lower() != 'localsystem':
                raise PermissionError('Service belongs to a different runtime')
            observed = verify_installed_identity(directory)
            if observed['manifest_sha256'] != plan['old_runtime_sha256']:
                raise ValueError('Installed predecessor is not approved')
            if GrantStore(directory, sid).pending():
                raise RuntimeError('Unresolved recovery blocks upgrade')
            status = svc.QueryServiceStatusEx(handle)['CurrentState']
            if status not in {svc.SERVICE_RUNNING, svc.SERVICE_STOPPED}:
                raise RuntimeError('Helper is already transitioning')
            initial_running = status == svc.SERVICE_RUNNING
            scheduler = win32com.client.Dispatch('Schedule.Service')
            scheduler.Connect()
            task = scheduler.GetFolder('\\').GetTask('DVielle')
            actions = list(task.Definition.Actions)
            if (len(actions) != 1 or Path(actions[0].Path).resolve() != app / '.venv' / 'Scripts' / 'pythonw.exe'
                    or actions[0].Arguments != '-m agent.main'
                    or Path(actions[0].WorkingDirectory).resolve() != app
                    or task.Definition.Principal.RunLevel != 0):
                raise PermissionError('Resident task is not owned by this installation')
            account_sid = win32security.LookupAccountName(None, task.Definition.Principal.UserId)[0]
            if win32security.ConvertSidToStringSid(account_sid) != sid:
                raise PermissionError('Resident task user differs from installed authorization')
            backup = directory / ('upgrade-' + uuid4().hex)
            backup.mkdir()
            assert_protected_path(backup)
            for name in ('runtime_manifest.json', 'release_identity.json'):
                atomic_text(backup / name, (directory / name).read_bytes().decode('utf-8'))
            for change in plan['changes']:
                target = app / change['path']
                if target.exists():
                    atomic_text(backup / change['path'], target.read_bytes().decode('utf-8'))
            task_enabled = bool(task.Enabled)
            report.update(state='prepared', task_enabled=task_enabled, helper_was_running=initial_running)
            save()
            task.Enabled = False
            task.Stop(0)
            task_deadline = time.monotonic() + 10
            while task.State == 4 and time.monotonic() < task_deadline:
                time.sleep(.2)
            if task.State == 4:
                raise TimeoutError('Resident task did not stop')
            if initial_running:
                svc.ControlService(handle, svc.SERVICE_CONTROL_STOP)
            wait_state(svc.SERVICE_STOPPED)
            # Recheck after service quiescence, before changing loaded code.
            verify_installed_identity(directory)
            if GrantStore(directory, sid).pending():
                raise RuntimeError('Recovery appeared during quiescence')
            report['state'] = 'applying'
            save()
            for change in plan['changes']:
                name = change['path']
                # Persist intent before mutation for interruption recovery.
                changed.append(name)
                report['change_intents'] = list(changed)
                save()
                atomic_text(app / name, payloads[name].decode('utf-8'))
                assert_protected_path(app / name)
            manifest = json.dumps(inventory(roots), sort_keys=True, indent=2)
            if sha(manifest.encode()) != plan['new_runtime_sha256']:
                raise ValueError('Actual upgraded inventory differs from independently derived approval')
            atomic_text(directory / 'runtime_manifest.json', manifest)
            atomic_text(directory / 'release_identity.json', json.dumps(
                {'version': 1, 'manifest_sha256': plan['new_runtime_sha256']}))
            report['identity'] = verify_installed_identity(directory)
            if initial_running:
                svc.StartService(handle, None)
                wait_state(svc.SERVICE_RUNNING)
            report['state'] = 'activated_identity_verified'
            save()
    except Exception as exc:
        report.update(state='failed', error_type=type(exc).__name__, error=str(exc))
        if backup:
            try:
                if svc.QueryServiceStatusEx(handle)['CurrentState'] == svc.SERVICE_RUNNING:
                    svc.ControlService(handle, svc.SERVICE_CONTROL_STOP)
                wait_state(svc.SERVICE_STOPPED)
                for name in reversed(changed):
                    old = backup / name
                    target = app / name
                    expected = next(item for item in plan['changes'] if item['path'] == name)
                    current = sha(target.read_bytes()) if target.exists() else None
                    if current not in {expected['old_sha256'], expected['new_sha256']}:
                        raise RuntimeError('External file change prevents conditional rollback')
                    if old.exists():
                        assert_protected_path(old)
                        if sha(old.read_bytes()) != expected['old_sha256']:
                            raise RuntimeError('Rollback predecessor backup changed')
                        atomic_text(target, old.read_bytes().decode('utf-8'))
                    else:
                        target.unlink(missing_ok=True)
                for name in ('runtime_manifest.json', 'release_identity.json'):
                    atomic_text(directory / name, (backup / name).read_bytes().decode('utf-8'))
                verify_installed_identity(directory)
                if initial_running:
                    svc.StartService(handle, None)
                    wait_state(svc.SERVICE_RUNNING)
                report['state'] = 'failed_predecessor_restored'
            except Exception as recovery_error:
                report.update(state='manual_recovery_required', recovery_error=str(recovery_error))
            save()
        raise
    finally:
        if task is not None and task_enabled is not None:
            # Keep the resident stopped on unresolved recovery.
            if report['state'] != 'manual_recovery_required':
                task.Enabled = task_enabled
                if task_enabled:
                    task.Run(None)
        if backup:
            report['finished'] = datetime.now(timezone.utc).isoformat()
            save()
            # A readable protected receipt contains no authorization material.
            atomic_text(app / ('upgrade-result-' + backup.name + '.json'), json.dumps(report, indent=2))
        svc.CloseServiceHandle(handle)
        svc.CloseServiceHandle(manager)


if __name__ == '__main__':
    main(PLAN)

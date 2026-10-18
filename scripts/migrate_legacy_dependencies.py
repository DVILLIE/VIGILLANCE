"""Exact, backed-up dependency retirement; never invoke pip as Administrator.

The operator embeds a reviewed immutable snapshot and a protected plan path.
File helpers have no authority; main enforces installed service/task ownership.
"""
from __future__ import annotations
import hashlib
import json
import os
import re
import tempfile
import time
from pathlib import Path
from uuid import uuid4

LEGACY = {'win10toast', 'win10toast-0.9.dist-info', 'pyttsx3',
          'pyttsx3-2.99.dist-info', 'pypiwin32-223.dist-info',
          'comtypes', 'comtypes-1.4.17.dist-info', 'dvielle-2.4.2.dist-info'}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def validate_plan(plan):
    changes = plan.get('changes')
    if not isinstance(changes, list) or not 1 <= len(changes) <= 1000:
        raise ValueError('Invalid dependency migration size')
    for key in ('old_runtime_sha256', 'new_runtime_sha256'):
        if not re.fullmatch('[a-f0-9]{64}', plan.get(key, '')):
            raise ValueError('Exact runtime digest required')
    seen = set()
    for item in changes:
        name = item['path']
        parts = name.split('/')
        if (name in seen or any(p in {'', '.', '..'} or ':' in p or '\\' in p
                               or p.endswith(('.', ' ')) for p in parts)):
            raise ValueError('Unsafe or duplicate migration path')
        seen.add(name)
        old, new = item['old_sha256'], item['new_sha256']
        if old is None and new is None:
            raise ValueError('Empty mutation')
        for digest in (old, new):
            if digest is not None and not re.fullmatch('[a-f0-9]{64}', digest):
                raise ValueError('Invalid file digest')
        if name == 'pyproject.toml':
            if old is None or new is None:
                raise ValueError('Project declaration must be replaced, never removed')
            continue
        if name == '.venv/Scripts/clear_comtypes_cache.exe':
            if old is None or new is not None:
                raise ValueError('Owned legacy cache launcher may only be retired')
            continue
        if len(parts) < 5 or parts[:3] != ['.venv', 'Lib', 'site-packages']:
            raise ValueError('Only exact installed package trees are admitted')
        if parts[3] in LEGACY:
            if old is None or new is not None:
                raise ValueError('Legacy package files may only be retired')
        elif parts[3] == 'dvielle-2.5.0.dist-info':
            if old is not None or new is None:
                raise ValueError('New application metadata must be newly created')
        else:
            raise ValueError('Unapproved package namespace')


def file_digest(path):
    return sha(path.read_bytes()) if path.exists() else None


def atomic_bytes(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix='.dependency-', dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        if os.name == 'nt':
            import win32file
            win32file.MoveFileEx(str(temporary), str(path), 0x1 | 0x8)
        else:
            os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def nearest_existing(path):
    while not path.exists():
        path = path.parent
    return path


def prepare_files(app, stage, backup, plan, protect):
    validate_plan(plan)
    payloads = {}
    for item in plan['changes']:
        name = item['path']
        target = app / name
        protect(nearest_existing(target))
        if file_digest(target) != item['old_sha256']:
            raise ValueError('Predecessor file differs: ' + name)
        if target.exists():
            if target.stat().st_size > 4 * 1024 * 1024:
                raise ValueError('Oversized predecessor')
            atomic_bytes(backup / name, target.read_bytes())
            protect(backup / name)
        if item['new_sha256'] is not None:
            source = stage / 'migration-payload' / name
            protect(source)
            if source.stat().st_size > 4 * 1024 * 1024:
                raise ValueError('Oversized payload')
            data = source.read_bytes()
            if sha(data) != item['new_sha256']:
                raise ValueError('Payload differs from approved bytes')
            payloads[name] = data
    return payloads


def apply_files(app, plan, payloads, intents, save, protect):
    for item in plan['changes']:
        name = item['path']
        target = app / name
        protect(nearest_existing(target))
        if file_digest(target) != item['old_sha256']:
            raise ValueError('Predecessor changed after preparation')
        intents.append(name)
        save()  # durable intent before every mutation
        if item['new_sha256'] is None:
            target.unlink()
        else:
            atomic_bytes(target, payloads[name])
            protect(target)
    # Empty dist-info directories must not masquerade as installed distributions.
    directories = {parent for item in plan['changes'] if item['new_sha256'] is None
                   for parent in (app / item['path']).parents
                   if parent.is_relative_to(app / '.venv/Lib/site-packages')
                   and parent != app / '.venv/Lib/site-packages'}
    for directory in sorted(directories, key=lambda p: len(p.parts), reverse=True):
        if directory.exists():
            protect(directory)
            if not any(directory.iterdir()):
                directory.rmdir()  # never recursive deletion


def restore_files(app, backup, plan, intents, protect):
    by_name = {item['path']: item for item in plan['changes']}
    if not isinstance(intents, list) or len(set(intents)) != len(intents) or set(intents) - set(by_name):
        raise ValueError('Unapproved recovery intents')
    # Validate the entire recovery before writing any file.
    for name in intents:
        item = by_name[name]
        protect(nearest_existing(app / name))
        if file_digest(app / name) not in {item['old_sha256'], item['new_sha256']}:
            raise ValueError('Foreign edit prevents conditional recovery')
        if item['old_sha256'] is not None:
            protect(backup / name)
            if file_digest(backup / name) != item['old_sha256']:
                raise ValueError('Predecessor backup changed')
    for name in reversed(intents):
        item = by_name[name]
        target = app / name
        if item['old_sha256'] is None:
            target.unlink(missing_ok=True)
        else:
            atomic_bytes(target, (backup / name).read_bytes())
            protect(target)
    for item in plan['changes']:
        if item['old_sha256'] is None:
            parent = (app / item['path']).parent
            while parent != app / '.venv/Lib/site-packages' and parent.exists() and not any(parent.iterdir()):
                protect(parent)
                parent.rmdir()
                parent = parent.parent


def main(plan, recovery_name=None):
    import win32service as svc
    import win32com.client
    import win32security
    from agent.local_files import atomic_text, file_lock
    from agent.privilege.helper import _is_elevated
    from agent.privilege.protected_paths import assert_protected_path as protect
    from agent.privilege.release_identity import inventory, runtime_roots, verify_installed_identity
    from agent.privilege.service_host import assert_runtime_trust, installed_configuration, SERVICE_NAME
    from agent.privilege.service_install import assert_service_security, binary_command
    from agent.privilege.grants import GrantStore
    from datetime import datetime, timezone
    if not _is_elevated():
        raise PermissionError('Explicit Windows Administrator approval required')
    assert_runtime_trust(require_system=False)
    validate_plan(plan)
    directory, sid = installed_configuration()
    roots = runtime_roots()
    app = roots['application']
    stage = Path(plan['stage'])
    if stage.parent != app.parent or not stage.name.startswith('DVielleStage-'):
        raise ValueError('Require a protected Program Files stage')
    protect(stage)
    manager = svc.OpenSCManager(None, None, svc.SC_MANAGER_CONNECT)
    handle = svc.OpenService(manager, SERVICE_NAME, svc.SERVICE_QUERY_CONFIG |
        svc.SERVICE_QUERY_STATUS | svc.SERVICE_STOP | svc.SERVICE_START | 0x20000)
    report = {'state': 'preflight', 'plan': plan, 'change_intents': [],
              'started': datetime.now(timezone.utc).isoformat(),
              'firewall_mutations': [], 'grants_preserved': True}
    task = None
    backup = None
    def wait_state(state):
        deadline = time.monotonic() + 40
        while svc.QueryServiceStatusEx(handle)['CurrentState'] != state:
            if time.monotonic() > deadline:
                raise TimeoutError('Helper state transition timed out')
            time.sleep(.2)
    def save():
        atomic_text(backup / 'journal.json', json.dumps(report, indent=2))
    def restore():
        for name in ('runtime_manifest.json', 'release_identity.json'):
            protect(backup / name)
        if sha((backup / 'runtime_manifest.json').read_bytes()) != plan['old_runtime_sha256']:
            raise ValueError('Backup identity changed')
        if json.loads((backup / 'release_identity.json').read_text()) != {'version': 1, 'manifest_sha256': plan['old_runtime_sha256']}:
            raise ValueError('Backup receipt changed')
        restore_files(app, backup, plan, report['change_intents'], protect)
        for name in ('runtime_manifest.json', 'release_identity.json'):
            atomic_bytes(directory / name, (backup / name).read_bytes())
        report['identity'] = verify_installed_identity(directory)
    try:
        with file_lock(directory / 'service-registration.lock'):
            assert_service_security(handle)
            config = svc.QueryServiceConfig(handle)
            if config[3] != binary_command() or config[7].lower() != 'localsystem':
                raise PermissionError('Service belongs to another runtime')
            scheduler = win32com.client.Dispatch('Schedule.Service')
            scheduler.Connect()
            task = scheduler.GetFolder('\\').GetTask('DVielle')
            actions = list(task.Definition.Actions)
            if (len(actions) != 1 or Path(actions[0].Path).resolve() != app / '.venv/Scripts/pythonw.exe'
                or actions[0].Arguments != '-m agent.main' or Path(actions[0].WorkingDirectory).resolve() != app
                or task.Definition.Principal.RunLevel != 0
                or win32security.ConvertSidToStringSid(win32security.LookupAccountName(None, task.Definition.Principal.UserId)[0]) != sid):
                raise PermissionError('Resident task ownership mismatch')
            if GrantStore(directory, sid).pending():
                raise RuntimeError('Unresolved network recovery blocks migration')
            if recovery_name is not None:
                if not re.fullmatch('dependency-upgrade-[a-f0-9]{32}', recovery_name):
                    raise ValueError('Invalid private recovery identifier')
                backup = directory / recovery_name
                protect(backup / 'journal.json')
                report = json.loads((backup / 'journal.json').read_text())
                if (report['plan'] != plan or report['state'] not in {'prepared', 'applying', 'failed', 'manual_recovery_required'}
                    or type(report.get('task_enabled')) is not bool or type(report.get('helper_was_running')) is not bool
                    or task.Enabled or task.State == 4 or svc.QueryServiceStatusEx(handle)['CurrentState'] != svc.SERVICE_STOPPED):
                    raise ValueError('Recovery requires the exact interrupted journal and quiescent runtime')
                if sha((backup / 'runtime_manifest.json').read_bytes()) != plan['old_runtime_sha256']:
                    raise ValueError('Backup manifest changed')
                restore()
                report['state'] = 'interrupted_dependency_predecessor_restored'
                save()
                return
            observed = verify_installed_identity(directory)
            if observed['manifest_sha256'] != plan['old_runtime_sha256']:
                raise ValueError('Installed identity differs from approval')
            status = svc.QueryServiceStatusEx(handle)['CurrentState']
            if status not in {svc.SERVICE_RUNNING, svc.SERVICE_STOPPED}:
                raise RuntimeError('Helper already transitioning')
            backup = directory / ('dependency-upgrade-' + uuid4().hex)
            backup.mkdir()
            protect(backup)
            for name in ('runtime_manifest.json', 'release_identity.json'):
                atomic_bytes(backup / name, (directory / name).read_bytes())
            payloads = prepare_files(app, stage, backup, plan, protect)
            report.update(state='prepared', task_enabled=bool(task.Enabled), helper_was_running=status == svc.SERVICE_RUNNING)
            save()
            task.Enabled = False
            task.Stop(0)
            deadline = time.monotonic() + 15
            while task.State == 4:
                if time.monotonic() > deadline:
                    raise TimeoutError('Resident did not stop')
                time.sleep(.2)
            if report['helper_was_running']:
                svc.ControlService(handle, svc.SERVICE_CONTROL_STOP)
            wait_state(svc.SERVICE_STOPPED)
            verify_installed_identity(directory)
            if GrantStore(directory, sid).pending():
                raise RuntimeError('Network recovery appeared during quiescence')
            report['state'] = 'applying'
            save()
            apply_files(app, plan, payloads, report['change_intents'], save, protect)
            manifest = json.dumps(inventory(roots), sort_keys=True, indent=2)
            if sha(manifest.encode()) != plan['new_runtime_sha256']:
                raise ValueError('Actual migrated inventory differs from approval')
            atomic_text(directory / 'runtime_manifest.json', manifest)
            atomic_text(directory / 'release_identity.json', json.dumps({'version': 1, 'manifest_sha256': plan['new_runtime_sha256']}))
            report['identity'] = verify_installed_identity(directory)
            if report['helper_was_running']:
                svc.StartService(handle, None)
                wait_state(svc.SERVICE_RUNNING)
            report['state'] = 'dependency_migration_identity_verified'
            save()
    except Exception as exc:
        report.update(state='failed', error_type=type(exc).__name__, error=str(exc))
        if backup is not None and 'task_enabled' in report:
            try:
                if svc.QueryServiceStatusEx(handle)['CurrentState'] == svc.SERVICE_RUNNING:
                    svc.ControlService(handle, svc.SERVICE_CONTROL_STOP)
                wait_state(svc.SERVICE_STOPPED)
                restore()
                report['state'] = 'failed_predecessor_restored'
            except Exception as recovery_error:
                report.update(state='manual_recovery_required', recovery_error=str(recovery_error))
            save()
        raise
    finally:
        try:
            if backup is not None and 'task_enabled' in report:
                try:
                    if report['state'] != 'manual_recovery_required':
                        if report['helper_was_running'] and svc.QueryServiceStatusEx(handle)['CurrentState'] == svc.SERVICE_STOPPED:
                            svc.StartService(handle, None)
                            wait_state(svc.SERVICE_RUNNING)
                        task.Enabled = report['task_enabled']
                        if report['task_enabled']:
                            task.Run(None)
                            deadline = time.monotonic() + 15
                            while task.State != 4:
                                if time.monotonic() > deadline:
                                    raise TimeoutError('Resident restart did not reach running state')
                                time.sleep(.2)
                except Exception as restart_error:
                    report.update(state='restart_incomplete', restart_error=str(restart_error))
                    raise
                finally:
                    report['finished'] = datetime.now(timezone.utc).isoformat()
                    save()
                    atomic_text(app / ('dependency-result-' + backup.name + '.json'), json.dumps(report, indent=2))
        finally:
            svc.CloseServiceHandle(handle)
            svc.CloseServiceHandle(manager)


if __name__ == '__main__':
    raise SystemExit('Use a reviewed immutable launcher and protected exact plan; no migration was started.')

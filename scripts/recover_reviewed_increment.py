"""Explicit interrupted-increment recovery from protected exact backups.

Run a reviewed immutable snapshot with PLAN and BACKUP_NAME embedded. This is
not automatic rollback, arbitrary file restoration, or a service protocol action.
Grants and network recovery records are retained; foreign file edits are refused.
"""
import hashlib
import json
import re
import time
from pathlib import Path


def recover(plan, backup_name):
    import win32service as svc
    import win32com.client
    import win32security
    from agent.local_files import atomic_text, file_lock
    from agent.privilege.helper import _is_elevated
    from agent.privilege.protected_paths import assert_protected_path
    from agent.privilege.service_host import assert_runtime_trust, installed_configuration, SERVICE_NAME
    from agent.privilege.service_install import assert_service_security, binary_command
    from agent.privilege.release_identity import verify_installed_identity, runtime_roots
    from agent.privilege.grants import GrantStore
    from agent.privilege.native_channel import _object, _nonfinite
    if not _is_elevated():
        raise PermissionError('Explicit Windows Administrator approval required')
    assert_runtime_trust(require_system=False)
    directory, sid = installed_configuration()
    if not isinstance(backup_name, str) or not re.fullmatch('upgrade-[0-9a-f]{32}', backup_name):
        raise ValueError('Require an exact private increment backup identifier')
    backup = directory / backup_name
    assert_protected_path(backup)
    def read_json(path, limit):
        assert_protected_path(path)
        if path.stat().st_size > limit:
            raise ValueError('Oversized recovery evidence')
        return json.loads(path.read_text(encoding='utf-8'), object_pairs_hook=_object, parse_constant=_nonfinite)
    journal = read_json(backup / 'journal.json', 262144)
    if (journal.get('plan') != plan or journal.get('state') not in {
            'prepared', 'applying', 'failed', 'manual_recovery_required'}
            or type(journal.get('helper_was_running')) is not bool
            or type(journal.get('task_enabled')) is not bool):
        raise ValueError('Backup journal is not the approved interrupted increment')
    app = runtime_roots()['application']
    if not isinstance(plan.get('changes'), list) or not 0 < len(plan['changes']) <= 100:
        raise ValueError('Invalid approved increment change set')
    intents = journal.get('change_intents', [])
    if not isinstance(intents, list) or len(set(intents)) != len(intents):
        raise ValueError('Invalid durable change intents')
    sources = {}
    for item in plan['changes']:
        name = item['path']
        parts = name.split('/')
        if (parts[0] not in {'agent', 'dvielle'} or not name.endswith('.py')
                or any(part in {'', '.', '..'} or ':' in part or '\\' in part for part in parts)
                or name in sources):
            raise ValueError('Unsafe or duplicate application recovery path')
        target = app / name
        assert_protected_path(target if target.exists() else target.parent)
        current = hashlib.sha256(target.read_bytes()).hexdigest() if target.exists() else None
        if current not in {item['old_sha256'], item['new_sha256']}:
            raise ValueError('External edit blocks conditional predecessor restoration')
        if item['old_sha256'] is not None:
            source = backup / name
            assert_protected_path(source)
            data = source.read_bytes()
            if hashlib.sha256(data).hexdigest() != item['old_sha256']:
                raise ValueError('Predecessor backup differs from approved bytes')
            sources[name] = data
        else:
            sources[name] = None
    if set(intents) - set(sources):
        raise ValueError('Journal includes an unapproved intent')
    old_manifest = backup / 'runtime_manifest.json'
    assert_protected_path(old_manifest)
    if hashlib.sha256(old_manifest.read_bytes()).hexdigest() != plan['old_runtime_sha256']:
        raise ValueError('Predecessor manifest differs from exact approval')
    old_receipt = read_json(backup / 'release_identity.json', 4096)
    if old_receipt != {'version': 1, 'manifest_sha256': plan['old_runtime_sha256']}:
        raise ValueError('Predecessor receipt differs from exact approval')
    manager = svc.OpenSCManager(None, None, svc.SC_MANAGER_CONNECT)
    service = None
    try:
        service = svc.OpenService(manager, SERVICE_NAME, svc.SERVICE_QUERY_CONFIG |
            svc.SERVICE_QUERY_STATUS | svc.SERVICE_START | 0x20000)
        with file_lock(directory / 'service-registration.lock'):
            assert_service_security(service)
            config = svc.QueryServiceConfig(service)
            if config[3] != binary_command() or config[7].lower() != 'localsystem':
                raise PermissionError('Service is not the exact owned helper')
            if svc.QueryServiceStatusEx(service)['CurrentState'] != svc.SERVICE_STOPPED:
                raise RuntimeError('Stop the exact helper before interrupted-code restoration')
            scheduler = win32com.client.Dispatch('Schedule.Service')
            scheduler.Connect()
            task = scheduler.GetFolder('\\').GetTask('DVielle')
            actions = list(task.Definition.Actions)
            if (len(actions) != 1 or Path(actions[0].Path).resolve() != app / '.venv' / 'Scripts' / 'pythonw.exe'
                    or actions[0].Arguments != '-m agent.main' or Path(actions[0].WorkingDirectory).resolve() != app
                    or task.Definition.Principal.RunLevel != 0 or bool(task.Enabled) or task.State == 4):
                raise PermissionError('Resident task is not the owned quiesced task')
            task_sid = win32security.LookupAccountName(None, task.Definition.Principal.UserId)[0]
            if win32security.ConvertSidToStringSid(task_sid) != sid:
                raise PermissionError('Resident user differs from the installed binding')
            journal['state'] = 'manual_recovery_required'
            atomic_text(backup / 'journal.json', json.dumps(journal, indent=2))
            receipt_now = read_json(directory / 'release_identity.json', 4096)
            if receipt_now.get('manifest_sha256') not in {plan['old_runtime_sha256'], plan['new_runtime_sha256']}:
                raise ValueError('External identity receipt edit prevents restoration')
            for name in reversed(intents):
                target = app / name
                assert_protected_path(target if target.exists() else target.parent)
                item = next(change for change in plan['changes'] if change['path'] == name)
                digest_now = hashlib.sha256(target.read_bytes()).hexdigest() if target.exists() else None
                if digest_now not in {item['old_sha256'], item['new_sha256']}:
                    raise ValueError('Application file changed after recovery preflight')
                if sources[name] is None:
                    (app / name).unlink(missing_ok=True)
                else:
                    atomic_text(app / name, sources[name].decode('utf-8'))
                    assert_protected_path(app / name)
            atomic_text(directory / 'runtime_manifest.json', old_manifest.read_bytes().decode('utf-8'))
            atomic_text(directory / 'release_identity.json', (backup / 'release_identity.json').read_bytes().decode('utf-8'))
            identity = verify_installed_identity(directory)
            if GrantStore(directory, sid).pending():
                raise RuntimeError('Code restored; pending network recovery prevents automatic restart')
            if journal['helper_was_running']:
                svc.StartService(service, None)
                deadline = time.monotonic() + 40
                while svc.QueryServiceStatusEx(service)['CurrentState'] != svc.SERVICE_RUNNING:
                    if time.monotonic() >= deadline:
                        raise TimeoutError('Restored helper did not reach running state')
                    time.sleep(.2)
            task.Enabled = journal['task_enabled']
            if journal['task_enabled']:
                task.Run(None)
            journal.update(state='interrupted_increment_predecessor_restored', identity=identity,
                           firewall_mutations=[], grants_preserved=True)
            atomic_text(backup / 'journal.json', json.dumps(journal, indent=2))
            atomic_text(app / ('recovery-result-' + backup_name + '.json'), json.dumps(journal, indent=2))
            return journal
    finally:
        if service is not None:
            svc.CloseServiceHandle(service)
        svc.CloseServiceHandle(manager)


if __name__ == '__main__':
    recover(PLAN, BACKUP_NAME)

"""Actual migration/exit-23 recovery on disposable copies of installed files.

Never stops a service or modifies the installed app. Controlled interruption is
confined to a new directory under the caller's explicitly selected output folder.
"""
import argparse
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('dependency_migration', ROOT / 'scripts/migrate_legacy_dependencies.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--child', type=Path)
    args = parser.parse_args()
    if args.child:
        folder = args.child.resolve()
        plan = json.loads((folder / 'plan.json').read_text())
        app, stage, backup = (folder / p for p in ('app', 'stage', 'backup'))
        def protect(path):
            if not path.resolve().is_relative_to(folder) or not path.exists() or path.is_symlink():
                raise ValueError('Copy acceptance path escaped workspace')
        payloads = m.prepare_files(app, stage, backup, plan, protect)
        intents = []
        def save():
            m.atomic_bytes(folder / 'intents.json', json.dumps(intents).encode())
            if len(intents) == 5:
                os._exit(23)
        m.apply_files(app, plan, payloads, intents, save, protect)
        raise RuntimeError('Interruption checkpoint was not reached')
    args.output.parent.mkdir(parents=True, exist_ok=True)
    working = ROOT / 'dist/dependency-migration-copy'
    working.mkdir(parents=True, exist_ok=True)
    folder = Path(tempfile.mkdtemp(prefix='dependency-copy-', dir=working))
    app, stage, backup = (folder / p for p in ('app', 'stage', 'backup'))
    with zipfile.ZipFile(args.archive) as archive:
        plan = json.loads(archive.read('dependency-migration-plan.json'))
        m.validate_plan(plan)
        for item in plan['changes']:
            name = item['path']
            if item['old_sha256'] is not None:
                original = Path(r'C:\Program Files\DVielle') / name
                data = original.read_bytes()
                if m.sha(data) != item['old_sha256']:
                    raise ValueError('Installed predecessor changed since planning')
                m.atomic_bytes(app / name, data)
            if item['new_sha256'] is not None:
                data = archive.read('migration-payload/' + name)
                if m.sha(data) != item['new_sha256']:
                    raise ValueError('Candidate payload changed')
                m.atomic_bytes(stage / 'migration-payload' / name, data)
    def protect(path):
        if not path.resolve().is_relative_to(folder) or not path.exists() or path.is_symlink():
            raise ValueError('Copy acceptance path escaped workspace')
    payloads = m.prepare_files(app, stage, backup, plan, protect)
    intents = []
    m.apply_files(app, plan, payloads, intents, lambda: None, protect)
    for item in plan['changes']:
        if m.file_digest(app / item['path']) != item['new_sha256']:
            raise ValueError('Actual copy migration differs from plan')
    m.restore_files(app, backup, plan, intents, protect)
    for item in plan['changes']:
        if m.file_digest(app / item['path']) != item['old_sha256']:
            raise ValueError('Copy round-trip did not restore exact predecessor')
    (folder / 'plan.json').write_text(json.dumps(plan))
    child = subprocess.run([sys.executable, '-B', str(Path(__file__).resolve()), '--archive', str(args.archive.resolve()),
                            '--output', str(args.output.resolve()), '--child', str(folder)], timeout=90)
    if child.returncode != 23:
        raise ValueError('Actual child did not stop at exit-23 checkpoint')
    interrupted = json.loads((folder / 'intents.json').read_text())
    changed_before_recovery = sum(m.file_digest(app / item['path']) != item['old_sha256'] for item in plan['changes'])
    if not changed_before_recovery:
        raise ValueError('Child stopped without any actual file mutation')
    m.restore_files(app, backup, plan, interrupted, protect)
    restored = all(m.file_digest(app / item['path']) == item['old_sha256'] for item in plan['changes'])
    result = {'state':'actual_installed_file_copy_round_trip_and_interruption_verified',
              'changes':len(plan['changes']), 'child_exit_code':child.returncode,
              'interrupted_intents':len(interrupted), 'actual_mutated_files_before_recovery':changed_before_recovery,
              'exact_predecessor_restored':restored, 'installed_runtime_changed':False,
              'isolated_copy_directory':str(folder), 'os_service_recovery_tested':False}
    args.output.write_text(json.dumps(result,indent=2))
    print(json.dumps(result))
    return int(not restored)

if __name__ == '__main__':
    raise SystemExit(main())

"""Real temporary-file retirement/recovery contracts; no system mutations."""
import importlib.util
from pathlib import Path
import pytest

spec = importlib.util.spec_from_file_location('migration', Path(__file__).resolve().parents[1] / 'scripts/migrate_legacy_dependencies.py')
migration = importlib.util.module_from_spec(spec)
spec.loader.exec_module(migration)

def fixture(tmp_path):
    app, stage, backup = (tmp_path / n for n in ('app', 'stage', 'backup'))
    old_name = '.venv/Lib/site-packages/win10toast/data/icon.bin'
    new_name = '.venv/Lib/site-packages/dvielle-2.5.0.dist-info/METADATA'
    old_data, new_data = bytes(range(256)), b'Name: dvielle\nVersion: 2.5.0\n'
    migration.atomic_bytes(app / old_name, old_data)
    migration.atomic_bytes(stage / 'migration-payload' / new_name, new_data)
    plan = {'old_runtime_sha256':'a'*64,'new_runtime_sha256':'b'*64,
            'changes':[{'path':old_name,'old_sha256':migration.sha(old_data),'new_sha256':None},
                       {'path':new_name,'old_sha256':None,'new_sha256':migration.sha(new_data)}]}
    def protect(path):
        assert path.resolve().is_relative_to(tmp_path.resolve())
        assert path.exists()
    return app, stage, backup, plan, protect, old_data

def test_binary_retirement_and_exact_restoration(tmp_path):
    app, stage, backup, plan, protect, old_data = fixture(tmp_path)
    payloads = migration.prepare_files(app, stage, backup, plan, protect)
    intents = []
    migration.apply_files(app, plan, payloads, intents, lambda: None, protect)
    assert not (app / plan['changes'][0]['path']).exists()
    assert not (app / '.venv/Lib/site-packages/win10toast').exists()
    migration.restore_files(app, backup, plan, intents, protect)
    assert (app / plan['changes'][0]['path']).read_bytes() == old_data
    assert not (app / '.venv/Lib/site-packages/dvielle-2.5.0.dist-info').exists()

def test_write_ahead_failure_restores_predecessor(tmp_path):
    app, stage, backup, plan, protect, old_data = fixture(tmp_path)
    payloads = migration.prepare_files(app, stage, backup, plan, protect)
    intents = []
    def save():
        if len(intents) == 2:
            raise OSError('Actual write-ahead callback failed before second mutation')
    with pytest.raises(OSError):
        migration.apply_files(app, plan, payloads, intents, save, protect)
    migration.restore_files(app, backup, plan, intents, protect)
    assert (app / plan['changes'][0]['path']).read_bytes() == old_data

def test_foreign_edit_blocks_all_restoration(tmp_path):
    app, stage, backup, plan, protect, _ = fixture(tmp_path)
    payloads = migration.prepare_files(app, stage, backup, plan, protect)
    intents = []
    migration.apply_files(app, plan, payloads, intents, lambda: None, protect)
    target = app / plan['changes'][1]['path']
    target.write_bytes(b'foreign edit')
    with pytest.raises(ValueError, match='Foreign edit'):
        migration.restore_files(app, backup, plan, intents, protect)
    assert not (app / plan['changes'][0]['path']).exists()
    assert target.read_bytes() == b'foreign edit'

@pytest.mark.parametrize('name', ['.venv/Lib/site-packages/pywin32/x', '../outside',
                                '.venv/Lib/site-packages/win10toast/../foreign',
                                '.venv/Lib/site-packages/COMTYPES/x'])
def test_unapproved_paths_rejected(name):
    plan = {'old_runtime_sha256':'a'*64,'new_runtime_sha256':'b'*64,
            'changes':[{'path':name,'old_sha256':'c'*64,'new_sha256':None}]}
    with pytest.raises(ValueError):
        migration.validate_plan(plan)

def test_standard_token_cannot_run_installed_migration():
    import os
    if os.name != 'nt':
        pytest.skip('Windows token boundary')
    import ctypes
    if ctypes.windll.shell32.IsUserAnAdmin():
        pytest.skip('Requires an actual standard token')
    with pytest.raises(PermissionError, match='Administrator approval'):
        migration.main({})

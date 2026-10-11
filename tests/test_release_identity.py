"""Real filesystem tampering contracts; no SCM mutation or service elevation."""
import hashlib
import json
from pathlib import Path

import pytest

from agent.privilege.release_identity import inventory, verify_manifest


def baseline(tmp_path):
    roots = {name: tmp_path / name for name in ('application', 'environment', 'python')}
    for root in roots.values():
        root.mkdir()
    source = roots['application'] / 'agent' / 'main.py'
    source.parent.mkdir()
    source.write_text('value = 1\n', encoding='utf-8')
    manifest = tmp_path / 'manifest.json'
    manifest.write_text(json.dumps(inventory(roots)), encoding='utf-8')
    digest = hashlib.sha256(manifest.read_bytes()).hexdigest()
    return roots, source, manifest, digest


def test_real_manifest_matches_exact_inventory_then_rejects_changed_file(tmp_path):
    roots, source, manifest, digest = baseline(tmp_path)
    result = verify_manifest(manifest, digest, roots, protected=False)
    assert result['files'] == 1 and result['publisher_authenticated'] is False
    source.write_text('value = 2\n', encoding='utf-8')
    with pytest.raises(ValueError, match='changed'):
        verify_manifest(manifest, digest, roots, protected=False)


@pytest.mark.parametrize('operation', ['added', 'removed', 'bytecode', 'manifest'])
def test_no_unlisted_inputs_or_unapproved_manifest(tmp_path, operation):
    roots, source, manifest, digest = baseline(tmp_path)
    if operation == 'added':
        (source.parent / 'extra.py').write_text('extra = 1')
    elif operation == 'removed':
        source.unlink()
    elif operation == 'bytecode':
        cache = source.parent / '__pycache__'
        cache.mkdir()
        (cache / 'main.cpython-312.pyc').write_bytes(b'contract bytecode')
    else:
        manifest.write_text('{}')
    with pytest.raises(ValueError):
        verify_manifest(manifest, digest, roots, protected=False)


@pytest.mark.parametrize('relative', ['../outside', '/absolute', 'agent/../outside', 'agent/a:stream', 'agent\\main.py'])
def test_approved_digest_does_not_authorize_unsafe_paths(tmp_path, relative):
    roots, source, manifest, digest = baseline(tmp_path)
    payload = json.loads(manifest.read_text())
    payload['files'][0]['path'] = relative
    manifest.write_text(json.dumps(payload))
    digest = hashlib.sha256(manifest.read_bytes()).hexdigest()
    with pytest.raises(ValueError, match='Unsafe'):
        verify_manifest(manifest, digest, roots, protected=False)


def test_actual_standard_user_cannot_register_start_or_remove_service():
    from agent.privilege.helper import _is_elevated
    from agent.privilege.service_install import main
    if _is_elevated():
        pytest.skip('Never mutate SCM under an elevated test token.')
    for command in ('start', 'remove'):
        with pytest.raises(PermissionError, match='Administrator'):
            main([command])


@pytest.mark.parametrize('access,accepted', [('CCLCRC', True), ('GA', False), ('RP', False), ('DC', False)])
def test_actual_windows_descriptor_restricts_service_control(monkeypatch, access, accepted):
    win32security = pytest.importorskip('win32security')
    win32service = pytest.importorskip('win32service')
    from agent.privilege.service_install import assert_service_security
    descriptor = win32security.ConvertStringSecurityDescriptorToSecurityDescriptor(
        f'O:BAG:BAD:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;{access};;;AU)', 1)
    monkeypatch.setattr(win32service, 'QueryServiceObjectSecurity', lambda *args: descriptor)
    if accepted:
        assert_service_security(None)
    else:
        with pytest.raises(PermissionError, match='untrusted principal'):
            assert_service_security(None)

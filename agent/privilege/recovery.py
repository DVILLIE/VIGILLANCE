"""Administrative reconciliation; never exposed through the user pipe."""
from __future__ import annotations

import json
import re

from agent.local_files import file_lock
from agent.modules.firewall_apply import apply_scope, restore_journal
from agent.privilege.grants import GrantStore
from agent.privilege.helper import _is_elevated


def reconcile(store: GrantStore, operation_id: str, *, runner=None) -> dict:
    if store.test_harness and runner is None:
        raise PermissionError("Contract recovery requires an explicit non-production executor.")
    if not store.test_harness:
        if runner is not None or not _is_elevated():
            raise PermissionError("Protected administrative recovery is required.")
    if not isinstance(operation_id, str) or re.fullmatch('[0-9a-f]{32}', operation_id) is None:
        raise ValueError("An exact protected operation identifier is required.")
    with file_lock(store.directory / 'service.lock'):
        store._preflight()
        operation = store.operation(operation_id)
        path = store.directory / (operation_id + '.firewall.json')
        try:
            if path.stat().st_size > 262144:
                raise ValueError('Oversized recovery journal')
            record = json.loads(path.read_text(encoding='utf-8'))
            if record.get('params') != operation['params']:
                raise ValueError('Recovery journal belongs to a different scope')
        except (OSError, ValueError, TypeError, AttributeError):
            return {'ok': False, 'code': 'recovery_required', 'performed': False,
                    'state_unknown': True, 'message': 'Recovery evidence is absent or mismatched; retain the unresolved operation.'}
        with apply_scope():
            result = restore_journal(path, runner)
        result['operation_id'] = operation_id
        store.record_recovery(operation_id, result)
        return result

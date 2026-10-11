"""Normal-user mediation client: no grant issuing and no elevation bypass."""
from __future__ import annotations
import base64
import json
import os
import subprocess
import threading
import time
from pathlib import Path
from uuid import uuid4

from agent.privilege.mediation import check_request, receipt_path
from agent.privilege.protected_paths import assert_protected_path


def request_consent(action, payload, *, stop=None, hwnd=0):
    import psutil
    import pywintypes
    import win32con
    import win32event
    import win32com.shell.shell as shell
    stop = stop if stop is not None else threading.Event()
    request = {'v': 1, 'action': action, 'payload': payload, 'nonce': uuid4().hex,
               'caller_pid': os.getpid(), 'caller_created': psutil.Process().create_time()}
    check_request(request)
    app = Path(__file__).resolve().parents[2]
    interpreter = app / '.venv' / 'Scripts' / 'python.exe'
    assert_protected_path(Path(__file__))
    assert_protected_path(interpreter)
    if stop.is_set():
        return {'state': 'canceled_before_consent', 'performed': False}
    encoded = base64.b64encode(json.dumps(request, allow_nan=False).encode()).decode()
    arguments = subprocess.list2cmdline(['-I', '-B', '-m', 'agent.privilege.mediation', '--request', encoded])
    try:
        launched = shell.ShellExecuteEx(fMask=0x40, hwnd=hwnd, lpVerb='runas',
            lpFile=str(interpreter), lpParameters=arguments, lpDirectory=str(app), nShow=win32con.SW_HIDE)
    except pywintypes.error as exc:
        if exc.winerror == 1223:
            return {'state': 'windows_consent_declined', 'performed': False}
        raise
    process = launched['hProcess']
    try:
        deadline = time.monotonic() + 300
        while win32event.WaitForSingleObject(process, 200) == win32con.WAIT_TIMEOUT:
            if time.monotonic() >= deadline:
                return {'state': 'consent_timeout_outcome_not_observed', 'performed': False,
                        'state_unknown': action == 'recover',
                        'consent_receipt': str(receipt_path(request['nonce'])),
                        'message': 'A late approval cannot apply a rule without client redemption; recovery may be in flight.'}
        destination = receipt_path(request['nonce'])
        assert_protected_path(destination)
        if destination.stat().st_size > 65536:
            raise ValueError('Oversized protected consent receipt')
        from agent.privilege.native_channel import _object, _nonfinite
        result = json.loads(destination.read_text(encoding='utf-8'), object_pairs_hook=_object,
                            parse_constant=_nonfinite)
        if (not isinstance(result, dict) or result.get('v') != 1
                or result.get('nonce') != request['nonce'] or result.get('action') != action):
            raise ValueError('Consent receipt belongs to a different request')
        if action == 'approve' and result.get('state') == 'approved':
            checked = check_request(request)
            if result.get('params') != checked:
                raise ValueError('Consent scope differs from the requested restriction')
            if stop.is_set():
                return {'state': 'canceled_unused_approval_expires', 'performed': False}
            from agent.privilege.native_client import submit
            # Once submission starts, transport failure is potentially unknown.
            try:
                applied = submit(checked, result['grant_id'])
            except Exception as exc:
                return {'state': 'submission_outcome_unknown', 'performed': False, 'state_unknown': True,
                        'error_type': type(exc).__name__,
                        'message': 'Request may have reached the helper; inspect protected recovery before retrying.'}
            return dict(applied, state='helper_result', requested_scope=checked)
        result.pop('grant_id', None)
        return result
    finally:
        process.Close()

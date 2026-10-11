"""Installed Administrator consent UI. Issues grants; never accepts commands.

Launched only with protected Python -I -B. Approval never applies a rule: the
bound normal-user client must redeem the resulting exact, five-minute grant.
Recovery is a separately confirmed administrative action on an exact journal.
"""
from __future__ import annotations
import argparse
import base64
import json
import math
import re
import time
from pathlib import Path

from agent.privilege.contract import validate_restrict_params


def check_request(request):
    if (not isinstance(request, dict) or set(request) != {
            'v', 'action', 'nonce', 'caller_pid', 'caller_created', 'payload'}
            or type(request['v']) is not int or request['v'] != 1
            or not isinstance(request['action'], str) or request['action'] not in {'approve', 'recover'}
            or not isinstance(request['nonce'], str) or not re.fullmatch('[0-9a-f]{32}', request['nonce'])
            or type(request['caller_pid']) is not int or request['caller_pid'] <= 0
            or type(request['caller_created']) not in {int, float}
            or not math.isfinite(request['caller_created'])
            or not isinstance(request['payload'], dict)):
        raise ValueError('Invalid closed administrative mediation request')
    payload = request['payload']
    if request['action'] == 'approve':
        if set(payload) != {'params'}:
            raise ValueError('Approval accepts only an exact restriction scope')
        checked, error = validate_restrict_params(payload['params'])
        if checked is None:
            raise ValueError(error)
        return checked
    if set(payload) != {'operation_id'} or not isinstance(payload['operation_id'], str) or not re.fullmatch(
            '[0-9a-f]{32}', payload['operation_id']):
        raise ValueError('Recovery accepts only an exact operation identifier')
    return payload['operation_id']


def receipt_path(nonce):
    # Windows Temp may deny the bound user READ_CONTROL on its ancestors.
    # The installed application directory permits trust inspection while only
    # Administrators and SYSTEM may create or replace these receipts.
    return Path(__file__).resolve().parents[2] / ('DVielleConsent-' + nonce + '.json')


def verify_caller(request, bound_sid):
    import psutil
    import win32api
    import win32con
    import win32security
    process = win32api.OpenProcess(0x1000, False, request['caller_pid'])
    try:
        token = win32security.OpenProcessToken(process, win32con.TOKEN_QUERY)
        try:
            sid = win32security.GetTokenInformation(token, win32security.TokenUser)[0]
            if win32security.ConvertSidToStringSid(sid) != bound_sid:
                raise PermissionError('Caller differs from the installed authorization user')
        finally:
            token.Close()
        if psutil.Process(request['caller_pid']).create_time() != request['caller_created']:
            raise PermissionError('Caller identity changed before consent')
        return process
    except BaseException:
        process.Close()
        raise


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--request', required=True)
    args = parser.parse_args(argv)
    if len(args.request) > 22000:
        raise ValueError('Oversized mediation request')
    from agent.privilege.native_channel import _object, _nonfinite
    request = json.loads(base64.b64decode(args.request, validate=True).decode('utf-8'),
                         object_pairs_hook=_object, parse_constant=_nonfinite)
    checked = check_request(request)
    from agent.privilege.helper import _is_elevated
    from agent.privilege.service_host import assert_runtime_trust, installed_configuration
    from agent.privilege.release_identity import verify_installed_identity
    from agent.privilege.protected_paths import assert_protected_path
    from agent.privilege.grants import GrantStore
    from agent.privilege.target import executable_lease
    if not _is_elevated():
        raise PermissionError('Explicit Windows Administrator consent is required')
    assert_runtime_trust(require_system=False)
    directory, sid = installed_configuration()
    identity = verify_installed_identity(directory)
    caller = verify_caller(request, sid)
    import pywintypes
    import win32con
    import win32file
    import win32security
    import tkinter as tk
    from tkinter import messagebox
    handle = root = None
    result = {'v': 1, 'nonce': request['nonce'], 'action': request['action'],
              'state': 'consent_not_completed', 'performed': False, 'identity': identity}
    try:
        destination = receipt_path(request['nonce'])
        attributes = pywintypes.SECURITY_ATTRIBUTES()
        attributes.SECURITY_DESCRIPTOR = win32security.ConvertStringSecurityDescriptorToSecurityDescriptor(
            'O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;' + sid + ')', 1)
        handle = win32file.CreateFile(str(destination), win32con.GENERIC_WRITE, win32con.FILE_SHARE_READ,
            attributes, win32con.CREATE_NEW, win32con.FILE_ATTRIBUTE_NORMAL, None)
        assert_protected_path(destination)
        store = GrantStore(directory, sid)
        root = tk.Tk()
        root.title("D'Vielle — review security scope")
        root.geometry('700x150')
        tk.Label(root, text='Windows consent was accepted. Review the exact scope in the confirmation dialog.\n'
                 'Approve only the action and executable you intend to authorize.',
                 wraplength=650, justify='left', padx=20, pady=25).pack(fill='both', expand=True)
        root.attributes('-topmost', True)
        root.update()
        root.lift()
        review_deadline = time.monotonic() + 240
        review_completed = False

        def watch_review():
            if review_completed:
                return
            import psutil
            try:
                alive = psutil.Process(request['caller_pid']).create_time() == request['caller_created']
            except psutil.Error:
                alive = False
            if not alive or time.monotonic() >= review_deadline:
                result['state'] = 'caller_exited_or_review_expired'
                root.destroy()  # closes unanswered dialog; never approves it
                return
            root.after(250, watch_review)

        root.after(250, watch_review)
        if request['action'] == 'approve':
            if store.pending():
                raise RuntimeError('Resolve pending recovery before approving another restriction')
            with executable_lease(checked['program']) as executable:
                scope = ('Program: ' + checked['program'] + '\nSHA256: ' + executable['sha256']
                    + '\nProfile: ' + checked['profile'] + '\nFamilies: ' + ', '.join(checked['address_families'])
                    + '\nRemote networks: ' + (', '.join(checked['remote_addresses']) or 'All addresses in selected families')
                    + '\n\nThis affects every instance of this executable, not one PID. '
                    'Launcher and child executables have separate paths.\n'
                    'Approval permits one firewall request within five minutes. '
                    'It does not prove packet containment or change other Windows controls.')
                approved = messagebox.askyesno("D'Vielle — approve exact network restriction?", scope,
                                              parent=root, default=messagebox.NO)
                review_completed = True
                if approved:
                    # Confirm the original caller still exists before issuing permission.
                    retained = verify_caller(request, sid)
                    retained.Close()
                    result.update(state='approved', grant_id=store.issue(checked), params=checked,
                                  expires_within_seconds=300)
                else:
                    result['state'] = 'declined'
        else:
            from agent.privilege.recovery import reconcile
            operation = store.operation(checked)
            approved = messagebox.askyesno("D'Vielle — restore owned restriction?",
                    'Operation: ' + checked + '\nRecorded state: ' + operation['state'] + '\n'
                    + json.dumps(operation['params'], indent=2)
                    + '\n\nRestore only matching D\'Vielle-owned rules. Conflicting or missing evidence remains unresolved.',
                    parent=root, default=messagebox.NO)
            review_completed = True
            if approved:
                result.update(state='recovery_result', result=reconcile(store, checked))
                result['performed'] = result['result'].get('performed', False)
            else:
                result['state'] = 'declined'
        return 0
    except Exception as exc:
        result.update(state='failed', error_type=type(exc).__name__,
                      state_unknown=request['action'] == 'recover',
                      message='Administrative consent did not complete; retain any existing recovery records.')
        return 2
    finally:
        if root is not None:
            try:
                root.destroy()
            except tk.TclError:
                pass
        if handle is not None:
            try:
                win32file.WriteFile(handle, json.dumps(result, allow_nan=False).encode('utf-8'))
                win32file.FlushFileBuffers(handle)
            finally:
                handle.Close()
        caller.Close()


if __name__ == '__main__':
    raise SystemExit(main())

"""Actual installed Protection actions component, with human consent and restore.

No consent is clicked or replaced. This shows production widgets using a separate
acceptance history directory; it does not start a second resident collector.
"""
import argparse
import json
import queue
import socket
import tempfile
import time
from pathlib import Path


def probe():
    try:
        with socket.create_connection(('151.101.0.223', 443), timeout=3):
            return {'state': 'connected'}
    except OSError as exc:
        return {'state': 'connection_failed', 'windows_error': getattr(exc, 'winerror', None),
                'error_type': type(exc).__name__}


def main(output):
    import customtkinter as ctk
    from dvielle.gui import theme as T
    from dvielle.gui.assessment import AssessmentWorkspace
    root = ctk.CTk()
    root.title("D'Vielle — actual approval and restoration acceptance")
    root.geometry('1180x850')
    T.install_day()
    T.apply('dark')
    events = queue.Queue()
    errors = []
    root.report_callback_exception = lambda *args: errors.append(str(args))
    workspace = AssessmentWorkspace(root, Path(tempfile.mkdtemp(prefix='DVielleActualGUI-')), events.put)
    workspace.pack(fill='both', expand=True, padx=15, pady=10)
    workspace.tabs.set('Protection actions')
    import psutil
    probe_image = psutil.Process().exe()
    workspace.action_program.insert(0, probe_image)
    workspace.action_remotes.insert(0, '151.101.0.223/32')
    workspace.action_profile.set('Any')
    workspace.action_family.set('IPv4')
    report = {'state': 'started', 'scope': 'Actual installed widgets, human Windows and exact-scope consent, one IPv4 TCP endpoint',
              'installed_component': str(Path(__import__('dvielle.gui.assessment', fromlist=['x']).__file__)),
              'probe_process_image': probe_image,
              'automated_consent': False, 'mutations': [], 'accessibility_acceptance': 'not_tested'}

    def save():
        output.write_text(json.dumps(report, indent=2, allow_nan=False), encoding='utf-8')

    def pump():
        while True:
            try:
                events.get_nowait()()
            except queue.Empty:
                break
        root.update()

    def wait():
        deadline = time.monotonic() + 360
        while workspace.action_worker is not None and workspace.action_worker.is_alive():
            if time.monotonic() >= deadline:
                raise TimeoutError('Actual consent/action outcome not observed before deadline')
            pump()
            time.sleep(.05)
        pump()
        return json.loads(workspace.action_result.get('1.0', 'end'))

    operation = None
    # Keep the actual controls alive until any submitted operation is restored.
    root.protocol('WM_DELETE_WINDOW', workspace.action_stop.set)
    try:
        pump()
        report['before'] = probe()
        save()
        if report['before']['state'] != 'connected':
            report['state'] = 'baseline_unavailable_no_action_requested'
            return
        workspace.apply_restriction()
        report['apply'] = wait()
        operation = report['apply'].get('operation_id')
        if operation:
            report['mutations'].append({'operation_id': operation, 'operation': 'restrict_network'})
        save()
        if report['apply'].get('ok') is not True:
            report['state'] = 'approval_or_apply_not_verified'
            return
        report['during'] = [probe(), probe()]
        report['state'] = 'applied_awaiting_restoration'
        save()
    except Exception as exc:
        report.update(state='action_outcome_not_observed', error_type=type(exc).__name__)
    finally:
        if operation:
            try:
                workspace.action_operation.delete(0, 'end')
                workspace.action_operation.insert(0, operation)
                workspace.recover_restriction()
                report['recovery'] = wait()
                restored = report['recovery'].get('result', {}).get('ok') is True
                if restored:
                    report['after'] = probe()
                    blocked = all(p.get('windows_error') == 10013 for p in report.get('during', [])) and len(report.get('during', [])) == 2
                    report['state'] = ('actual_gui_approval_apply_and_recovery_passed' if blocked
                        and report['after']['state'] == 'connected' else 'restored_traffic_acceptance_incomplete')
                else:
                    report['state'] = 'recovery_required'
            except Exception as exc:
                report.update(state='recovery_required', recovery_error_type=type(exc).__name__)
        report['callback_errors'] = errors
        save()
        workspace.close()
        root.destroy()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        parser.error('Use a fresh evidence output filename')
    main(args.output)

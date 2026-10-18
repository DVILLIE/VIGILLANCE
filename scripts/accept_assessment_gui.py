"""Real Tk action-key routing and scaling observations; no OS mutations."""
import argparse
import json
import sys
import tempfile
import time
from pathlib import Path

if '--installed-runtime' not in sys.argv:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import customtkinter as ctk
from dvielle.gui.assessment import AssessmentWorkspace
from agent.local_files import atomic_text


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--installed-runtime', action='store_true')
    args = parser.parse_args()
    if args.installed_runtime:
        import inspect
        expected = Path(r'C:\Program Files\DVielle\dvielle\gui\assessment.py')
        if Path(inspect.getfile(AssessmentWorkspace)).resolve() != expected.resolve():
            raise RuntimeError('--installed-runtime requires the protected installed interpreter and modules')
    root = ctk.CTk()
    root.geometry('1200x850')
    root.title("D'Vielle — keyboard and scaling acceptance")
    errors = []
    root.report_callback_exception = lambda kind, value, tb: errors.append(kind.__name__)
    scales = []
    with tempfile.TemporaryDirectory(prefix='DVielle-GUI-acceptance-') as directory:
        workspace = AssessmentWorkspace(root, Path(directory), lambda fn: root.after(0, fn))
        workspace.pack(fill='both', expand=True)
        root.update()
        # Drive actual Tk canvas keyboard events using a harmless command probe.
        button = workspace.local_button
        hits = []
        original = button.cget('command')
        button.configure(command=lambda: hits.append('activated'))
        button._canvas.focus_force()
        root.update()
        button._canvas.event_generate('<Return>')
        root.update()
        button._canvas.event_generate('<space>')
        root.update()
        button.configure(state='disabled')
        button._canvas.event_generate('<Return>')
        root.update()
        button.configure(command=original, state='normal')
        for scale in (1.0, 1.25, 1.5, 2.0):
            ctk.set_widget_scaling(scale)
            root.update()
            scales.append({'scale':scale, 'tab_width':workspace.tabs.winfo_width(),
                           'tab_header_requested_width':workspace.tabs._segmented_button.winfo_reqwidth(),
                           'tab_header_actual_width':workspace.tabs._segmented_button.winfo_width(),
                           'window_width':root.winfo_width(), 'window_height':root.winfo_height()})
        menu = workspace.tab_choice._dropdown_menu
        assert menu.entrycget(5, 'label').strip() == 'Attack paths'
        menu.invoke(5)
        root.update()
        selector_worked = workspace.tabs.get() == 'Attack paths'
        workspace.tabs.set('Quantum readiness')
        deadline = time.monotonic() + .25
        while time.monotonic() < deadline:
            root.update()
            time.sleep(.01)
        signer_state = workspace.check_signer()
        pending = list(workspace.signer_status.master.winfo_children())
        signer_buttons = []
        while pending:
            widget = pending.pop()
            pending.extend(widget.winfo_children())
            if isinstance(widget, ctk.CTkButton):
                widget._canvas.focus_force()
                root.update()
                viewport = workspace.quantum_content._parent_canvas
                top = widget.winfo_rooty() - viewport.winfo_rooty()
                signer_buttons.append({'label':widget.cget('text'), 'visible':bool(widget.winfo_viewable()),
                    'width':widget.winfo_width(), 'height':widget.winfo_height(),
                    'within_parent_width':widget.winfo_x() >= 0 and widget.winfo_x() + widget.winfo_width() <= widget.master.winfo_width(),
                    'keyboard_focus_revealed_center':0 <= top + widget.winfo_height() / 2 <= viewport.winfo_height()})
        signer_controls_worked = (len(signer_buttons) == 4 and all(
            row['visible'] and row['within_parent_width'] and row['keyboard_focus_revealed_center']
            for row in signer_buttons) and signer_state is None)
        workspace.close()
        root.destroy()
    import inspect
    result = {'state':'keyboard_routing_passed' if hits == ['activated','activated'] and selector_worked and signer_controls_worked and not errors else 'gui_acceptance_failed',
              'workspace_source':inspect.getfile(AssessmentWorkspace), 'full_name_tab_selector_worked':selector_worked,
              'enter_space_activations':len(hits), 'disabled_button_blocked':len(hits) == 2,
              'callback_errors':errors, 'scales':scales, 'mutations':[],
              'local_signer_controls':signer_buttons, 'missing_signer_observation_without_generation':signer_state is None,
              'limits':['Command probe verifies event routing, not actual Administrator consent.',
                        'Layout dimensions are measurements, not human visual/scaling acceptance.',
                        'Narrator and flash-area/contrast acceptance remain unmeasured.']}
    atomic_text(args.output, json.dumps(result, indent=2))
    print(json.dumps(result))
    return 0 if result['state'] == 'keyboard_routing_passed' else 1


if __name__ == '__main__':
    raise SystemExit(main())

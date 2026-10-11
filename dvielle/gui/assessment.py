"""Advanced ethical hacking workspace, backed by real scoped assessments."""
from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path
from tkinter import filedialog, messagebox

import customtkinter as ctk

from agent.assessment import AssessmentEngine, AssessmentScope
from agent.assessment.history import HistoryPrivacy
from agent.assessment.evidence import freshness, resolution_plan
from dvielle.gui import theme as T


class AssessmentWorkspace(ctk.CTkFrame):
    def __init__(self, master, directory: Path, dispatch):
        super().__init__(master, fg_color="transparent")
        self.engine = None
        self.engine_error = None
        try:
            self.engine = AssessmentEngine(directory)
        except (OSError, sqlite3.Error, ValueError) as exc:
            self.engine_error = type(exc).__name__
        self.dispatch = dispatch
        self.stop_event = threading.Event()
        self.worker: threading.Thread | None = None
        self.current_report: dict | None = None
        self.action_worker = None
        self.action_stop = threading.Event()
        self.closed = False
        ctk.CTkLabel(self, text="Advanced Ethical Hacking", font=("Segoe UI", 26, "bold"),
                     text_color=T.TEXT).pack(anchor="w", pady=(4, 8))
        ctk.CTkLabel(self, text="Investigate your computer or one authorized website. "
                     "Observed evidence, precise scope, no hidden changes.",
                     font=T.FONT_BODY, text_color=T.TEXT_DIM, wraplength=850,
                     justify="left").pack(anchor="w", pady=(0, 12))
        controls = ctk.CTkFrame(self, fg_color=T.BG_PANEL, corner_radius=14)
        controls.pack(fill="x", pady=6)
        self.local_button = ctk.CTkButton(controls, text="Assess this computer",
                                        command=self.start_local, font=T.FONT_BODY)
        self.local_button.pack(side="left", padx=12, pady=12)
        self.stop_button = ctk.CTkButton(controls, text="Stop assessment", command=self.stop,
                                       state="disabled", fg_color=T.BG_PANEL_ALT, text_color=T.TEXT)
        self.stop_button.pack(side="left", padx=8, pady=12)
        self.service_button = ctk.CTkButton(controls, text='Check protection service', command=self.start_readiness,
                                          fg_color=T.BG_PANEL_ALT, text_color=T.TEXT)
        self.service_button.pack(side='left', padx=8, pady=12)
        ctk.CTkButton(controls, text="Export redacted report", command=self.export,
                     fg_color=T.BG_PANEL_ALT, text_color=T.TEXT).pack(side="right", padx=12)
        self.share_versions = ctk.CTkCheckBox(self,
            text="For this run: share D'Vielle runtime package names/versions with OSV for vulnerability lookup")
        self.share_versions.pack(anchor="w", pady=6)
        self.sign_exports = ctk.CTkCheckBox(self, text='Sign exports locally with ML-DSA-65 (Windows-protected key; retain the signer fingerprint separately)')
        self.sign_exports.pack(anchor='w', pady=6)
        self.tabs = ctk.CTkTabview(self, fg_color=T.BG_PANEL)
        tab_names = ("Assessment", "Authorized website", "Protection actions", "Evidence", "Resolution plan", "Attack paths", "Quantum readiness", "History", "Privacy & costs")
        self.tab_choice = ctk.CTkOptionMenu(self, values=list(tab_names), command=self.tabs.set)
        self.tab_choice.set('Assessment')
        self.tab_choice.pack(anchor='w', pady=(4, 0))
        self.tabs.pack(fill="both", expand=True, pady=10)
        for title in tab_names:
            self.tabs.add(title)
        privacy = self.tabs.tab('Privacy & costs')
        self.retention_enabled = ctk.CTkCheckBox(privacy, text='Automatically clean old history after an assessment')
        self.retention_enabled.pack(anchor='w', pady=8)
        options = ctk.CTkFrame(privacy, fg_color='transparent')
        options.pack(fill='x', pady=6)
        ctk.CTkLabel(options, text='Keep days:').pack(side='left', padx=4)
        self.retention_days = ctk.CTkOptionMenu(options, values=['7', '30', '90', '365'])
        self.retention_days.set('30')
        self.retention_days.pack(side='left', padx=4)
        ctk.CTkLabel(options, text='Keep latest runs:').pack(side='left', padx=4)
        self.retention_runs = ctk.CTkOptionMenu(options, values=['20', '100', '500', '1000'])
        self.retention_runs.set('100')
        self.retention_runs.pack(side='left', padx=4)
        ctk.CTkButton(options, text='Save history policy', command=self.save_history_policy).pack(side='right', padx=4)
        actions = ctk.CTkFrame(privacy, fg_color='transparent')
        actions.pack(fill='x', pady=6)
        ctk.CTkButton(actions, text='Preview cleanup', command=self.preview_history_cleanup).pack(side='left', padx=4)
        ctk.CTkButton(actions, text='Delete previewed records', command=self.delete_history_preview).pack(side='left', padx=4)
        ctk.CTkLabel(privacy, text='Automatic cleanup is off initially. Running assessments are retained. '
            'Deleting database records does not erase exported reports, backups or storage snapshots.',
            text_color=T.TEXT_DIM, wraplength=800, justify='left').pack(anchor='w', pady=6)
        self.cleanup_preview = None
        history_controls = ctk.CTkFrame(self.tabs.tab("History"), fg_color="transparent")
        history_controls.pack(fill="x", pady=6)
        self.history_choice = ctk.CTkOptionMenu(history_controls, values=["No assessments"])
        self.history_choice.pack(side="left", fill="x", expand=True, padx=(0, 8))
        ctk.CTkButton(history_controls, text="Open saved assessment", command=self.open_history).pack(side="right")
        web = self.tabs.tab("Authorized website")
        ctk.CTkLabel(web, text="Exact origin (for example https://your-owned-domain)",
                     font=T.FONT_BODY, text_color=T.TEXT).pack(anchor="w", pady=6)
        self.origin = ctk.CTkEntry(web, placeholder_text="https://", height=38)
        self.origin.pack(fill="x", pady=6)
        self.authority = ctk.CTkEntry(web, placeholder_text="Owner / written authorization reference", height=38)
        self.authority.pack(fill="x", pady=6)
        self.confirm = ctk.CTkCheckBox(web, text="I own this origin or have explicit authority to assess it")
        self.confirm.pack(anchor="w", pady=12)
        self.web_button = ctk.CTkButton(web, text="Review authorized origin", command=self.start_web)
        self.web_button.pack(anchor="w", pady=8)
        self.exchange_button = ctk.CTkButton(web, text='Measure TLS key exchange',
            command=lambda: self.start_web(tls_handshake_only=True))
        self.exchange_button.pack(anchor='w', pady=8)
        self.hybrid_button = ctk.CTkButton(web, text='Test hybrid-only TLS gate',
            command=lambda: self.start_web(tls_handshake_only=True, require_hybrid=True))
        self.hybrid_button.pack(anchor='w', pady=8)
        ctk.CTkLabel(web, text="One HEAD request; certificate/TLS and security-header observations. "
                     "The TLS measurement button performs one verified handshake without HTTP and records the actual exchange group. "
                     "No crawl, redirects, exploitation or credential collection. Approval lasts five minutes for this run.",
                     wraplength=800, justify="left", text_color=T.TEXT_DIM).pack(anchor="w", pady=12)
        self.views = {}
        actions = ctk.CTkScrollableFrame(self.tabs.tab('Protection actions'), fg_color='transparent')
        actions.pack(fill='both', expand=True)
        ctk.CTkLabel(actions, text='Restrict an exact executable; restore an exact owned operation.',
            text_color=T.TEXT, wraplength=780, justify='left').pack(anchor='w', pady=8)
        ctk.CTkLabel(actions, text='Windows Administrator consent and a separate scope confirmation are required. '
            'Rules affect every instance of the selected executable. Launchers and child images differ. '
            'A verified rule is not proof that every network path is contained.',
            text_color=T.TEXT_DIM, wraplength=780, justify='left').pack(anchor='w', pady=8)
        self.action_program = ctk.CTkEntry(actions, placeholder_text='Full executable path', height=36)
        self.action_program.pack(fill='x', pady=4)
        ctk.CTkButton(actions, text='Choose executable', command=self.choose_action_program).pack(anchor='w', pady=4)
        self.action_profile = ctk.CTkOptionMenu(actions, values=['Any', 'Domain', 'Private', 'Public'])
        self.action_profile.pack(anchor='w', pady=4)
        self.action_family = ctk.CTkOptionMenu(actions, values=['IPv4', 'IPv6', 'IPv4 + IPv6'])
        self.action_family.pack(anchor='w', pady=4)
        self.action_remotes = ctk.CTkEntry(actions, placeholder_text='Specific remote IPs/CIDRs, comma separated', height=36)
        self.action_remotes.pack(fill='x', pady=4)
        self.action_apply = ctk.CTkButton(actions, text='Review and approve restriction', command=self.apply_restriction)
        self.action_apply.pack(anchor='w', pady=6)
        self.action_operation = ctk.CTkEntry(actions, placeholder_text='Exact operation ID to restore', height=36)
        self.action_operation.pack(fill='x', pady=4)
        self.action_recover = ctk.CTkButton(actions, text='Review and restore owned restriction', command=self.recover_restriction)
        self.action_recover.pack(anchor='w', pady=6)
        ctk.CTkButton(actions, text='Cancel pending approval', command=self.action_stop.set).pack(anchor='w', pady=6)
        self.action_result = ctk.CTkTextbox(actions, height=180, wrap='word', font=T.FONT_MONO)
        self.action_result.pack(fill='x', pady=8)
        self.action_result.insert('1.0', 'No protection action requested. Existing rules are unchanged.')
        self.action_result.configure(state='disabled')
        for title in ("Assessment", "Evidence", "Resolution plan", "Quantum readiness", "History", "Privacy & costs"):
            view = ctk.CTkTextbox(self.tabs.tab(title), height=310, wrap="word", font=T.FONT_MONO)
            view.pack(fill="both", expand=True)
            view.configure(state="disabled")
            self.views[title] = view
        self.status = ctk.CTkLabel(self, text="Ready — choose an assessment. No checks have run yet.",
                                  text_color=T.TEXT_DIM, wraplength=850, justify="left")
        self.status.pack(anchor="w", pady=8)
        self._text("Assessment", "Real local review: runtime software versions, cryptographic provider, "
                   "TCP listener observations and available Windows protection posture.\n\n"
                   "Missing coverage remains unknown. No automatic OS remediation is enabled here.")
        self.refresh_history()
        self._keyboard_controls()
        if self.engine is not None:
            try:
                policy = HistoryPrivacy(self.engine).policy()
                self.retention_days.configure(values=sorted(set(['7', '30', '90', '365', str(policy['days'])]), key=int))
                self.retention_days.set(str(policy['days']))
                self.retention_runs.configure(values=sorted(set(['20', '100', '500', '1000', str(policy['max_runs'])]), key=int))
                self.retention_runs.set(str(policy['max_runs']))
                if policy['enabled']:
                    self.retention_enabled.select()
            except (OSError, sqlite3.Error, ValueError):
                self._text('Privacy & costs', 'Saved retention policy is unreadable. History was retained.')
        if self.engine is None:
            self.local_button.configure(state="disabled")
            self.web_button.configure(state="disabled")
            self.exchange_button.configure(state='disabled')
            self.hybrid_button.configure(state='disabled')
            self.status.configure(text="Assessment storage unavailable (" + self.engine_error +
                                  "). Existing data was retained; the rest of the application remains available.")

    def _text(self, title: str, value: str):
        view = self.views[title]
        view.configure(state="normal")
        view.delete("1.0", "end")
        view.insert("1.0", value)
        view.configure(state="disabled")

    def choose_action_program(self):
        selected = filedialog.askopenfilename(parent=self.winfo_toplevel(),
            title='Choose the actual executable image', filetypes=[('Executable', '*.exe')])
        if selected:
            self.action_program.delete(0, 'end')
            self.action_program.insert(0, selected)

    def apply_restriction(self):
        from agent.privilege.contract import validate_restrict_params
        params = {'program': self.action_program.get().strip(), 'profile': self.action_profile.get(),
            'address_families': ['IPv4', 'IPv6'] if self.action_family.get() == 'IPv4 + IPv6'
                else [self.action_family.get()],
            'remote_addresses': [value.strip() for value in self.action_remotes.get().split(',') if value.strip()]}
        if not params['remote_addresses']:
            self._action_result({'state': 'scope_required', 'performed': False,
                'message': 'Enter at least one specific remote IP/network for this restriction.'})
            return
        checked, error = validate_restrict_params(params)
        if checked is None:
            self._action_result({'state': 'invalid_scope', 'performed': False, 'message': error})
            return
        self._action_start('approve', {'params': checked})

    def recover_restriction(self):
        import re
        operation = self.action_operation.get().strip()
        if not re.fullmatch('[0-9a-f]{32}', operation):
            self._action_result({'state': 'invalid_operation', 'performed': False,
                'message': 'Enter the exact recorded 32-character operation identifier.'})
            return
        self._action_start('recover', {'operation_id': operation})

    def _action_result(self, result):
        if self.closed:
            return
        self.action_result.configure(state='normal')
        self.action_result.delete('1.0', 'end')
        self.action_result.insert('1.0', json.dumps(result, indent=2))
        self.action_result.configure(state='disabled')
        if result.get('operation_id'):
            self.action_operation.delete(0, 'end')
            self.action_operation.insert(0, result['operation_id'])
        self.action_apply.configure(state='normal')
        self.action_recover.configure(state='normal')

    def _action_start(self, action, payload):
        if self.action_worker is not None and self.action_worker.is_alive():
            return
        self.action_stop = threading.Event()
        hwnd = self.winfo_toplevel().winfo_id()
        self._action_result({'state': 'waiting_for_windows_and_scope_consent', 'performed': False})
        self.action_apply.configure(state='disabled')
        self.action_recover.configure(state='disabled')
        def work():
            try:
                from agent.privilege.mediation_client import request_consent
                result = request_consent(action, payload, stop=self.action_stop, hwnd=hwnd)
            except Exception as exc:
                result = {'state': 'action_outcome_not_observed', 'state_unknown': True,
                    'error_type': type(exc).__name__,
                    'message': 'No successful action is inferred. Keep any recorded operation ID for recovery.'}
            if not self.closed:
                self.dispatch(lambda: self._action_result(result))
        self.action_worker = threading.Thread(target=work, daemon=True, name='dvielle-protection-action')
        self.action_worker.start()

    def start_local(self):
        share = self.share_versions.get() == 1
        self.share_versions.deselect()
        self._start(AssessmentScope(authorized=share, expires_at=time.time() + 300,
                                    share_runtime_versions=share))

    def start_web(self, *, tls_handshake_only=False, require_hybrid=False):
        scope = AssessmentScope(self.origin.get().strip(), self.authority.get().strip(),
                                self.confirm.get() == 1, time.time() + 300,
                                tls_handshake_only=tls_handshake_only, require_hybrid=require_hybrid)
        try:
            scope.origin()
        except (ValueError, UnicodeError) as exc:
            self.status.configure(text=str(exc))
            return
        self.confirm.deselect()  # an old checkbox cannot authorize another run
        self._start(scope)

    def _start(self, scope):
        if self.engine is None:
            self.status.configure(text="Assessment storage unavailable. No assessment started; existing data retained.")
            return
        if self.worker is not None and self.worker.is_alive():
            return
        self.stop_event = threading.Event()
        self.local_button.configure(state="disabled")
        self.web_button.configure(state="disabled")
        self.exchange_button.configure(state='disabled')
        self.hybrid_button.configure(state='disabled')
        self.service_button.configure(state='disabled')
        self.stop_button.configure(state="normal")
        self.status.configure(text="Assessment running — gathering actual observations…")
        self.tabs.set("Assessment")

        def work():
            try:
                report = self.engine.run(scope, self.stop_event)
                self.dispatch(lambda: self._finish(report))
            except Exception as exc:
                message = f"Assessment could not start: {type(exc).__name__}."
                self.dispatch(lambda: self._error(message))

        self.worker = threading.Thread(target=work, daemon=True, name="dvielle-assessment")
        self.worker.start()

    def _ready(self):
        self.local_button.configure(state="normal" if self.engine is not None else 'disabled')
        self.web_button.configure(state="normal" if self.engine is not None else 'disabled')
        self.exchange_button.configure(state='normal' if self.engine is not None else 'disabled')
        self.hybrid_button.configure(state='normal' if self.engine is not None else 'disabled')
        self.service_button.configure(state='normal')
        self.stop_button.configure(state="disabled")

    def start_readiness(self):
        if self.worker is not None and self.worker.is_alive():
            return
        self.stop_event = threading.Event()
        self.current_report = None
        self.local_button.configure(state='disabled')
        self.web_button.configure(state='disabled')
        self.service_button.configure(state='disabled')
        self.stop_button.configure(state='normal')
        self.status.configure(text='Checking actual service and protected installation prerequisites…')
        def work():
            try:
                from agent.privilege.readiness import inspect_readiness
                result = inspect_readiness()
                self.dispatch(lambda: self._finish_readiness(result))
            except Exception as exc:
                message = f'Readiness observation unavailable ({type(exc).__name__}); no protection state inferred.'
                self.dispatch(lambda: self._error(message))
        self.worker = threading.Thread(target=work, daemon=True, name='dvielle-service-readiness')
        self.worker.start()

    def _finish_readiness(self, result):
        if self.closed:
            return
        self._ready()
        if self.stop_event.is_set():
            self.status.configure(text='Readiness observation stopped; no activation or policy change performed.')
            return
        self.tabs.set('Assessment')
        self._text('Assessment', 'Service readiness: ' + result['state'] + '\n\n'
                   + '\n'.join(result['holds']) + '\n\nNo installation, elevation or Windows policy change performed.')
        self._text('Evidence', json.dumps(result, indent=2))
        self._text('Resolution plan', 'Resolve the recorded installation and validation prerequisites before activating protection.')
        self._text('Quantum readiness', 'This service-readiness check does not measure post-quantum protocol protection.')
        self.status.configure(text='Service readiness observed: ' + result['state'] + '. No system changes performed.')

    def _error(self, message):
        if self.closed:
            return
        self._ready()
        self.status.configure(text=message)

    def _finish(self, report):
        if self.closed:
            return
        self.current_report = report
        self._ready()
        findings = report["findings"]
        self.status.configure(text=f"{report['state'].capitalize()} — {len(findings)} evidence-based review items. "
                              "No system changes performed.")
        age = freshness(report)
        summary = f"Assessment state: {report['state']}\nEvidence freshness: {age['state']}\n" + report.get("detail", "")
        self._text("Assessment", summary + "\n\n" + ("\n\n".join(
            f"[{item['severity'].upper()}] {item['observation']}" for item in findings)
            or "No review items recorded. This is not a clean-machine certification.")
            + "\n\nCoverage:\n" + "\n".join(report["coverage"]))
        self._text("Evidence", json.dumps(report, indent=2, ensure_ascii=False))
        from agent.assessment.attack_paths import investigation_paths
        self._text('Attack paths', json.dumps(investigation_paths(report), indent=2, ensure_ascii=False))
        plan = resolution_plan(report)
        self._text("Resolution plan", '\n\n'.join(
            f"{index}. [{item['priority']}] {item['observation']}\n"
            f"Recommended next step: {item['recommendation']}\nEvidence: " + ', '.join(item['evidence_ids'])
            + f"\nFreshness: {item['freshness']}\nEvidence consistency: {item['evidence_integrity']}\nState: recommendation only; no action authorization."
            for index, item in enumerate(plan['items'], 1)) or 'No recommendations from these observations.')
        self._text("Quantum readiness", json.dumps(
            {'local_runtime': report['observations'].get('cryptography', {'state': 'not_observed'}),
             'authorized_peer_tls': report['observations'].get('tls', {'state': 'not_observed'})}, indent=2)
            + "\n\nLibrary support, negotiated key exchange and authentication are distinct. "
              "No post-quantum protection is claimed without measured protocol evidence.")
        self.refresh_history()
        self._text('Privacy & costs', json.dumps(report['observations'].get('assessment_resources',
                   {'coverage': 'not_recorded_in_this_saved_run'}), indent=2)
                   + '\n\nNo foreground-performance or zero-slowdown certification is inferred.')

    def _history_policy(self):
        return {'enabled': self.retention_enabled.get() == 1, 'days': int(self.retention_days.get()),
                'max_runs': int(self.retention_runs.get())}

    def save_history_policy(self):
        if self.engine is None or self.worker is not None and self.worker.is_alive():
            self.status.configure(text='Finish the assessment before changing history settings.')
            return
        policy = self._history_policy()
        if policy['enabled'] and not messagebox.askyesno('Enable history cleanup?',
                f"After future assessments, remove terminal records older than {policy['days']} days "
                f"or beyond {policy['max_runs']} saved runs, up to 200 per cleanup. "
                'Exports and backups remain separate. Enable this policy?', parent=self.winfo_toplevel()):
            if not HistoryPrivacy(self.engine).policy()['enabled']:
                self.retention_enabled.deselect()
            self.status.configure(text='History policy unchanged; no cleanup enabled by this dialog.')
            return
        try:
            HistoryPrivacy(self.engine).set_policy(policy)
            self.cleanup_preview = None
            self.status.configure(text='History policy saved. No records deleted by saving the policy.')
        except (OSError, sqlite3.Error, ValueError, TimeoutError):
            self.status.configure(text='History policy was not saved. Existing records were retained.')

    def preview_history_cleanup(self):
        if self.engine is None:
            return
        try:
            self.cleanup_preview = HistoryPrivacy(self.engine).preview(policy=self._history_policy())
            self._text('Privacy & costs', json.dumps(self.cleanup_preview, indent=2)
                       + '\n\nPreview only. No records deleted.')
        except (OSError, sqlite3.Error, ValueError):
            self.cleanup_preview = None
            self.status.configure(text='Cleanup preview unavailable; records retained.')

    def delete_history_preview(self):
        preview = self.cleanup_preview
        if self.engine is None or not preview or not preview['ids']:
            self.status.configure(text='Preview matching history records before deleting them.')
            return
        if self.worker is not None and self.worker.is_alive():
            self.status.configure(text='Finish the assessment before deleting history.')
            return
        if not messagebox.askyesno('Delete assessment history?',
                f"Delete exactly {len(preview['ids'])} previewed assessment records? "
                'Exports and backups are unaffected.', parent=self.winfo_toplevel()):
            return
        try:
            result = HistoryPrivacy(self.engine).delete(preview['ids'])
            if self.current_report and self.current_report['id'] in result['ids']:
                self.current_report = None
                for title in ('Assessment', 'Evidence', 'Resolution plan', 'Quantum readiness'):
                    self._text(title, 'The displayed history record was deleted.')
            self.cleanup_preview = None
            self.refresh_history()
            self._text('Privacy & costs', json.dumps(result, indent=2))
            self.status.configure(text=result['message'])
        except (OSError, sqlite3.Error, ValueError, TimeoutError):
            self.status.configure(text='History deletion was not completed; refresh the preview before retrying.')

    def refresh_history(self):
        try:
            if self.engine is None:
                raise ValueError("Assessment storage unavailable")
            rows = self.engine.history()
        except (OSError, sqlite3.Error, ValueError):
            self.history_choice.configure(values=["History unavailable"])
            self.history_choice.set("History unavailable")
            self._text("History", "History could not be read. Existing data was retained; no clean result is inferred.")
            return
        self.history_choice.configure(values=[row["id"] for row in rows] or ["No assessments"])
        self.history_choice.set(rows[0]["id"] if rows else "No assessments")
        self._text("History", "\n".join(f"{r['started']}  {r['state']}  {r['id']}" for r in rows)
                   or "No assessments have run.")

    def open_history(self):
        if self.worker is not None and self.worker.is_alive():
            self.status.configure(text="Stop or finish the current assessment before opening history.")
            return
        try:
            self._finish(self.engine.report(self.history_choice.get()))
            self.tabs.set("Assessment")
        except (ValueError, OSError, sqlite3.Error, KeyError, TypeError, AttributeError):
            self.status.configure(text="The selected assessment is unavailable.")

    def _keyboard_controls(self):
        """Expose actual action canvases to Tab, Enter and Space with a focus ring."""
        pending = list(self.winfo_children())
        while pending:
            widget = pending.pop()
            pending.extend(widget.winfo_children())
            if isinstance(widget, ctk.CTkButton):
                canvas = widget._canvas
                canvas.configure(takefocus=1, highlightthickness=2,
                                 highlightcolor=widget._apply_appearance_mode(T.ACCENT),
                                 highlightbackground=widget._apply_appearance_mode(T.BG_PANEL))
                def invoke(_event, button=widget):
                    button.invoke()  # CTkButton retains its disabled-state guard.
                    return 'break'
                widget.bind('<Return>', invoke, add=True)
                widget.bind('<space>', invoke, add=True)

    def stop(self):
        self.stop_event.set()
        self.status.configure(text="Stop requested. An in-flight OS query/request must finish or time out; "
                              "no further checks will start.")

    def export(self):
        if self.current_report is None:
            self.status.configure(text="Run an assessment before exporting evidence.")
            return
        destination = filedialog.asksaveasfilename(parent=self.winfo_toplevel(), defaultextension=".json",
            initialfile=f"DVielle-assessment-{self.current_report['id']}.json",
            filetypes=[("JSON evidence report", "*.json")])
        if destination:
            try:
                self.engine.export(self.current_report["id"], Path(destination))
                self.status.configure(text="Redacted report exported. Origin, addresses and process IDs removed.")
                if self.sign_exports.get() == 1:
                    try:
                        from agent.assessment.signatures import sign_report
                        from agent.local_files import atomic_text
                        signature = sign_report(Path(destination), self.engine.directory / 'security')
                        atomic_text(Path(destination + '.sig.json'), json.dumps(signature, indent=2))
                        self.status.configure(text='Redacted report and ML-DSA-65 signature exported. Signer fingerprint: ' + signature['key_fingerprint'])
                    except Exception as exc:
                        self.status.configure(text='Redacted report exported; signature unavailable (' + type(exc).__name__ + '). No signed-export claim.')
            except (OSError, sqlite3.Error, ValueError, KeyError, TypeError):
                self.status.configure(text="Report export failed; the assessment remains in local history.")

    def close(self):
        self.closed = True
        self.stop_event.set()
        self.action_stop.set()

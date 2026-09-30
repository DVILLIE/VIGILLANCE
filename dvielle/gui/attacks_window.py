"""Dedicated Attacks console — failed logons + browser/credential threats."""

from __future__ import annotations

from datetime import datetime

import customtkinter as ctk

from agent.store.db import AgentStore
from dvielle import APP_NAME
from dvielle.brand import apply_tk_window_icon
from dvielle.gui import theme as T
from dvielle.gui.observations import failed_logon_copy

_ATTACK_MODULES = ("attacks", "browser_guard", "connections", "security")


class AttacksWindow(ctk.CTkToplevel):
    """Separate window for attack / stealer / adware vigilance."""

    def __init__(
        self,
        master,
        store: AgentStore,
        *,
        review_window_hours: float = 24.0,
        summary_window_days: float = 14.0,
        coverage=None,
    ) -> None:
        super().__init__(master)
        self.store = store
        self.review_window_hours = float(review_window_hours)
        self.summary_window_days = float(summary_window_days)
        self._coverage = coverage or (lambda: "unavailable")
        self.title(f"{APP_NAME} — Attacks Console")
        self.geometry("1040x720")
        self.minsize(880, 600)
        self.configure(fg_color=T.BG_DARK)
        self._alive = True
        self.protocol("WM_DELETE_WINDOW", self._on_close)
        apply_tk_window_icon(self)

        rule = ctk.CTkFrame(self, fg_color=T.DANGER, height=3, corner_radius=0)
        rule.pack_propagate(False)
        rule.pack(fill="x")

        header = ctk.CTkFrame(self, fg_color=T.BG_PANEL, height=90)
        header.pack(fill="x")
        header.pack_propagate(False)
        ctk.CTkLabel(
            header, text="ATTACKS CONSOLE", font=T.FONT_TITLE, text_color=T.DANGER,
        ).pack(anchor="w", padx=16, pady=(12, 0))
        ctk.CTkLabel(
            header,
            text="Failed logons · browser stealer/adware watch · suspicious connections  |  Never captures your passwords or keystrokes",
            font=T.FONT_BODY, text_color=T.TEXT_DIM,
        ).pack(anchor="w", padx=16, pady=(4, 10))

        self.summary_lbl = ctk.CTkLabel(
            self, text="Loading…", font=T.FONT_BODY, text_color=T.TEXT,
        )
        self.summary_lbl.pack(anchor="w", padx=16, pady=(10, 4))

        tabs = ctk.CTkTabview(
            self,
            fg_color=T.BG_PANEL,
            border_color=T.BORDER,
            border_width=1,
            segmented_button_fg_color=T.BG_PANEL_ALT,
            segmented_button_selected_color=T.ACCENT,
            segmented_button_selected_hover_color=T.ACCENT_DIM,
            segmented_button_unselected_color=T.BG_PANEL_ALT,
            segmented_button_unselected_hover_color=T.BORDER,
            text_color=T.TEXT,
            command=self._paint_tabs,
        )
        tabs.pack(fill="both", expand=True, padx=16, pady=8)
        self.tabs = tabs
        self.tab_live = tabs.add("Live threats")
        self.tab_logons = tabs.add("Failed logons")
        self.tab_browser = tabs.add("Browser watch")
        self.tab_conn = tabs.add("Suspicious connections")

        self.live_box = self._make_box(self.tab_live)
        self.logon_box = self._make_box(self.tab_logons)
        self.browser_box = self._make_box(self.tab_browser)
        self.conn_box = self._make_box(self.tab_conn)
        self._paint_tabs()

        foot = ctk.CTkFrame(self, fg_color="transparent")
        foot.pack(fill="x", padx=16, pady=(0, 12))
        ctk.CTkButton(
            foot, text="Refresh now", width=140, height=40, command=self.refresh,
            fg_color=T.ACCENT_DIM, hover_color=T.ACCENT, text_color=T.ON_ACCENT,
            font=T.FONT_BODY,
        ).pack(side="left")
        ctk.CTkButton(
            foot, text="Close", width=120, height=40, command=self._on_close,
            fg_color=T.BORDER, hover_color=T.ACCENT_DIM, font=T.FONT_BODY,
        ).pack(side="right")

        self.refresh()
        self.after(5000, self._auto_refresh)

    def _paint_tabs(self) -> None:
        from dvielle.gui.theme import paint_selected_segment

        if getattr(self, "tabs", None) is None:
            return
        paint_selected_segment(self.tabs)

    def _make_box(self, parent) -> ctk.CTkTextbox:
        box = ctk.CTkTextbox(
            parent, font=T.FONT_MONO, fg_color=T.BG_DARK, text_color=T.TEXT,
            border_color=T.BORDER, border_width=1,
        )
        box.pack(fill="both", expand=True, padx=8, pady=8)
        return box

    def _on_close(self) -> None:
        self._alive = False
        self.destroy()

    def _auto_refresh(self) -> None:
        if not self._alive:
            return
        try:
            if self.winfo_exists():
                self.refresh()
                self.after(5000, self._auto_refresh)
        except Exception:
            self._alive = False

    def _set_box(self, box: ctk.CTkTextbox, text: str) -> None:
        box.configure(state="normal")
        box.delete("1.0", "end")
        box.insert("1.0", text)
        box.configure(state="disabled")

    def refresh(self) -> None:
        summary = self.store.attack_summary(window_days=self.summary_window_days)
        days = int(summary.get("summary_window_days") or self.summary_window_days)
        try:
            coverage = str(self._coverage() or "unavailable")
        except Exception:
            coverage = "unavailable"
        self.summary_lbl.configure(
            text=(
                f"Last {days} days stored — "
                f"Failed logon attempts: {summary['failed_logon_attempts']}  |  "
                f"Attack alerts: {summary['attack_events']}  |  "
                f"Browser/stealer alerts: {summary['browser_threat_events']}  |  "
                f"Blocked IPs: not shown (no gated writer)  |  "
                f"Logon coverage: {coverage}  |  "
                f"Display clock {datetime.now().strftime('%H:%M:%S')}"
            )
        )

        live_rows = self.store.recent_events(modules=_ATTACK_MODULES, limit=80)
        if not live_rows:
            live = (
                "No attack-related events yet.\n\n"
                "With the agent STARTED, DVielle records:\n"
                "  - Failed Windows logons (Event 4625)\n"
                "  - Browser watch (fake browsers, stealer/adware name hits, ad sidecars)\n"
                "  - Suspicious outbound connections\n"
            )
        else:
            lines = []
            for r in live_rows:
                ts = str(r["ts"])[:19].replace("T", " ")
                lines.append(f"[{ts}] [{r['severity']}] ({r['module']}) {r['message']}")
            live = "\n".join(lines)
        self._set_box(self.live_box, live)

        logons = [dict(row) for row in self.store.recent_failed_logons(60)]
        self._set_box(self.logon_box, failed_logon_copy(logons, coverage))

        browser_rows = self.store.recent_events(modules=("browser_guard",), limit=80)
        if not browser_rows:
            browser_txt = (
                "Browser watch has not reported yet.\n"
                "Open Chrome/Edge/Firefox and keep the agent STARTED — "
                "DVielle checks each cycle for lookalike browsers, stealer/adware "
                "process names, and non-browser ad-network connections.\n\n"
                "Honest limit: this is heuristic defense, not a full antivirus or EDR. "
                "We do not read your passwords or keystrokes."
            )
        else:
            lines = []
            for r in browser_rows:
                ts = str(r["ts"])[:19].replace("T", " ")
                lines.append(f"[{ts}] [{r['severity']}] {r['message']}")
            browser_txt = "\n".join(lines)
        self._set_box(self.browser_box, browser_txt)

        conns = self.store.recent_suspicious_connections(
            50, window_hours=self.review_window_hours
        )
        # Also pull recent connection INFO/WARNING events for smarter narrative
        conn_events = self.store.recent_events(modules=("connections",), limit=40)
        lines: list[str] = []
        lines.append("HOW TO READ THIS")
        lines.append("- router / lan_device  = phone, extender, printer, or your Wi‑Fi gear (usually fine)")
        lines.append("- cdn_cloud            = Cloudflare/Google/Amazon website plumbing (usually fine)")
        lines.append("- unknown_internet     = public IP we could not name — review the app")
        lines.append("- Process '?' fixed: we now resolve System / Protected / Ended when possible")
        lines.append(
            f"- FLAGGED = distinct (process, ip) peers in the last {int(self.review_window_hours)}h "
            "(not every pulse)"
        )
        lines.append("")
        if not conns and not conn_events:
            lines.append("No connection intel yet. Keep the agent STARTED and browse / use the network.")
        else:
            if conns:
                lines.append(
                    f"=== FLAGGED FOR REVIEW (last {int(self.review_window_hours)}h, peer-deduped) ==="
                )
                for r in conns:
                    ts = str(r["ts"])[:19].replace("T", " ")
                    proc = r["process_name"] or "Unknown process"
                    hits = int(r["hits"] or 1)
                    hit_bit = f"  ×{hits}" if hits > 1 else ""
                    lines.append(f"[{ts}] {proc}{hit_bit}")
                    lines.append(f"         → {r['remote_addr']}")
                    lines.append(f"         {r['reason'] or 'suspicious'}")
                    lines.append("")
            if conn_events:
                lines.append("=== RECENT CONNECTION INTEL ===")
                for r in conn_events[:25]:
                    ts = str(r["ts"])[:19].replace("T", " ")
                    lines.append(f"[{ts}] [{r['severity']}] {r['message']}")
        self._set_box(self.conn_box, "\n".join(lines))

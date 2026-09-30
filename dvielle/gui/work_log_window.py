"""Work log report viewer."""

from __future__ import annotations

from datetime import datetime

import customtkinter as ctk

from agent.store.db import AgentStore
from dvielle import APP_NAME, TAGLINE
from dvielle.brand import apply_tk_window_icon
from dvielle.gui import theme as T


def format_work_log_report(rows: list) -> str:
    lines = [
        f"{'=' * 56}",
        f"  {APP_NAME} — WORK LOG REPORT",
        f"  {TAGLINE}",
        f"  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"{'=' * 56}",
        "",
    ]
    if not rows:
        lines.append("  (No work log entries yet)")
    else:
        lines.append(f"  OPEN — Session log begins ({rows[0]['ts'][:19]})")
        lines.append("  " + "-" * 52)
        for i, row in enumerate(rows, 1):
            ts = row["ts"][:19].replace("T", " ")
            action = row["action"]
            msg = row["message"]
            lines.append(f"  {i:4}. [{ts}] {action:12} — {msg}")
        lines.append("  " + "-" * 52)
        lines.append(f"  CLOSE — Report end ({rows[-1]['ts'][:19]})")
        lines.append(f"  Total actions logged: {len(rows)}")
    lines.append("")
    return "\n".join(lines)


class WorkLogWindow(ctk.CTkToplevel):
    def __init__(self, master, store: AgentStore) -> None:
        super().__init__(master)
        self.title(f"{APP_NAME} — Work Log Report")
        self.geometry("820x580")
        self.configure(fg_color=T.BG_DARK)
        apply_tk_window_icon(self)

        rule = ctk.CTkFrame(self, fg_color=T.ACCENT, height=3, corner_radius=0)
        rule.pack_propagate(False)
        rule.pack(fill="x")

        ctk.CTkLabel(
            self, text="WORK LOG REPORT", font=T.FONT_TITLE, text_color=T.ACCENT,
        ).pack(pady=(12, 4))
        ctk.CTkLabel(
            self, text="Chronological list of all actions (open → close)",
            font=T.FONT_BODY, text_color=T.TEXT_DIM,
        ).pack(pady=(0, 8))

        self.text = ctk.CTkTextbox(
            self, font=T.FONT_MONO, fg_color=T.BG_PANEL, text_color=T.TEXT,
            border_color=T.BORDER, border_width=1,
        )
        self.text.pack(fill="both", expand=True, padx=16, pady=8)

        rows = store.get_work_log()
        self.text.insert("1.0", format_work_log_report(rows))
        self.text.configure(state="disabled")

        ctk.CTkButton(
            self, text="Close", command=self.destroy,
            fg_color=T.BORDER, hover_color=T.ACCENT_DIM,
        ).pack(pady=12)

"""WHY — the evidence surface. Renders each Level-2 recommendation the guardian
issued (from the durable `decisions` table) as an evidence card: what was
observed, the confidence, the target, and the honest rollback line (nothing was
changed at L2). This is the explainability moat — recommend only, no mutation.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

import customtkinter as ctk

from agent.store.db import AgentStore
from agent.twin import TwinStore
from dvielle import APP_NAME
from dvielle.brand import apply_tk_window_icon
from dvielle.gui import theme as T
from dvielle.gui.observations import why_measurement_line

_LEVEL_NAME = {0: "OBSERVE", 1: "EXPLAIN", 2: "RECOMMEND", 3: "REVERSIBLE", 4: "ADMIN", 5: "EMERGENCY"}


def _ago(ts: str) -> str:
    try:
        t = datetime.fromisoformat(ts)
        if t.tzinfo is None:
            t = t.replace(tzinfo=timezone.utc)
        secs = (datetime.now(timezone.utc) - t).total_seconds()
        if secs < 60:
            return f"{secs:.0f}s ago"
        if secs < 3600:
            return f"{secs / 60:.0f}m ago"
        if secs < 86400:
            return f"{secs / 3600:.0f}h ago"
        return f"{secs / 86400:.0f}d ago"
    except Exception:
        return (ts or "")[:19].replace("T", " ")


class WhyWindow(ctk.CTkToplevel):
    def __init__(self, master, store: AgentStore, twin: TwinStore | None = None) -> None:
        super().__init__(master)
        self.store = store
        self.twin = twin
        self.title(f"{APP_NAME} — Why (evidence)")
        self.geometry("720x640")
        self.configure(fg_color=T.BG_DARK)
        apply_tk_window_icon(self)

        rule = ctk.CTkFrame(self, fg_color=T.ACCENT, height=3, corner_radius=0)
        rule.pack_propagate(False)
        rule.pack(fill="x")

        ctk.CTkLabel(self, text="WHY — EVIDENCE LEDGER", font=T.FONT_TITLE, text_color=T.ACCENT).pack(pady=(12, 2))
        ctk.CTkLabel(
            self,
            text="Every Level-2 recommendation, with the evidence behind it — recommend only, no automatic action.",
            font=T.FONT_TAGLINE, text_color=T.TEXT_DIM, wraplength=660,
        ).pack(pady=(0, 6))

        self._twin_lbl = ctk.CTkLabel(self, text="", font=T.FONT_MONO, text_color=T.ACCENT_DIM)
        self._twin_lbl.pack(pady=(0, 6))

        self.scroll = ctk.CTkScrollableFrame(self, fg_color=T.BG_PANEL)
        self.scroll.pack(fill="both", expand=True, padx=14, pady=6)

        row = ctk.CTkFrame(self, fg_color="transparent")
        row.pack(fill="x", padx=14, pady=10)
        ctk.CTkButton(
            row, text="Refresh", command=self.refresh,
            fg_color=T.ACCENT_DIM, hover_color=T.ACCENT, text_color=T.ON_ACCENT,
        ).pack(side="left")
        ctk.CTkButton(
            row, text="Close", command=self.destroy, fg_color=T.BORDER, hover_color=T.ACCENT_DIM,
        ).pack(side="right")

        self.refresh()

    def refresh(self) -> None:
        for w in self.scroll.winfo_children():
            w.destroy()

        data = None
        if self.twin is not None:
            try:
                data = self.twin.as_dict()
            except Exception:
                data = None
        self._twin_lbl.configure(text=why_measurement_line(data))

        try:
            rows = self.store.recent_decisions(100)
        except Exception:
            rows = []

        if not rows:
            ctk.CTkLabel(
                self.scroll,
                text=(
                    "No recommendations yet.\n\nWhen the guardian observes something worth acting on "
                    "(Defender off, a failed-logon burst, memory pressure), it records the evidence "
                    "here — recommend only, nothing is changed."
                ),
                font=T.FONT_BODY, text_color=T.TEXT_DIM, justify="left", wraplength=640,
            ).pack(anchor="w", padx=10, pady=14)
            return

        for r in rows:
            self._card(dict(r))

    def _card(self, r: dict) -> None:
        level = int(r.get("action_level") or 0)
        card = ctk.CTkFrame(
            self.scroll, fg_color=T.BG_PANEL_ALT, corner_radius=6, border_color=T.BORDER, border_width=1
        )
        card.pack(fill="x", padx=6, pady=5)

        head = ctk.CTkFrame(card, fg_color="transparent")
        head.pack(fill="x", padx=10, pady=(8, 2))
        conf = r.get("confidence")
        conf_s = f"{conf:.0%}" if isinstance(conf, (int, float)) else "—"
        ctk.CTkLabel(
            head,
            text=f"{(r.get('initiator') or '?').upper()}  ·  {r.get('action')}  ·  L{level} {_LEVEL_NAME.get(level, '')}",
            font=T.FONT_TITLE, text_color=T.ACCENT,
        ).pack(side="left")
        ctk.CTkLabel(
            head, text=f"conf {conf_s}  ·  {_ago(r.get('ts', ''))}", font=T.FONT_MONO, text_color=T.TEXT_DIM
        ).pack(side="right")

        ctk.CTkLabel(
            card, text=f"target: {r.get('target') or '—'}", font=T.FONT_TAGLINE,
            text_color=T.TEXT_DIM, anchor="w",
        ).pack(fill="x", padx=10)

        try:
            evidence = json.loads(r.get("evidence") or "[]")
        except Exception:
            evidence = []
        for line in evidence:
            ctk.CTkLabel(
                card, text=f"•  {line}", font=T.FONT_BODY, text_color=T.TEXT,
                wraplength=640, anchor="w", justify="left",
            ).pack(fill="x", padx=16, pady=1)

        if level <= 2:
            rb = "rollback: N/A — Level-2 recommendation, nothing was changed"
        elif r.get("reversible"):
            rb = f"rollback: {r.get('rollback_plan') or '—'}"
        else:
            rb = "rollback: none (irreversible)"
        ctk.CTkLabel(
            card, text=rb, font=T.FONT_TAGLINE, text_color=T.ACCENT_DIM, anchor="w"
        ).pack(fill="x", padx=10, pady=(2, 8))

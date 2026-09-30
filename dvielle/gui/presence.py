"""Mission Console instruments. Static drawings and live text.

The brand mark in ``logo_mark.py`` is the only animation. These widgets
redraw when a measurement or the theme changes. The clock updates its
time string once a second; that is a readout, not a motion effect.
"""

from __future__ import annotations

import tkinter as tk

import customtkinter as ctk

from dvielle.gui import theme as T
from dvielle.gui.observations import collector_state


class LivingRadar(ctk.CTkFrame):
    """Static radar instrument. The sweep does not move."""

    def __init__(self, master, size: int = 120, **kwargs) -> None:
        super().__init__(master, fg_color="transparent", **kwargs)
        self.size = size
        self._running = False
        self.canvas = tk.Canvas(
            self,
            width=size,
            height=size,
            bg=T.hex_color("panel"),
            highlightthickness=0,
            bd=0,
        )
        self.canvas.pack()
        T.subscribe(self._on_theme)
        self._redraw_radar()

    def _on_theme(self, _mode: str) -> None:
        try:
            if not self.winfo_exists():
                T.unsubscribe(self._on_theme)
                return
            self.canvas.configure(bg=T.hex_color("panel"))
            self._redraw_radar()
        except Exception:
            T.unsubscribe(self._on_theme)

    def _redraw_radar(self) -> None:
        # Must not be named _draw — CTkFrame._draw(no_color_updates=...) owns that.
        self.canvas.delete("all")
        cx = cy = self.size // 2
        r = self.size // 2 - 6
        self.canvas.create_oval(
            cx - r - 2, cy - r - 2, cx + r + 2, cy + r + 2,
            outline=T.hex_color("accent_dim"), width=1,
        )
        for frac in (0.35, 0.6, 0.85, 1.0):
            rr = int(r * frac)
            self.canvas.create_oval(
                cx - rr, cy - rr, cx + rr, cy + rr,
                outline=T.hex_color("border"), width=1,
            )
        self.canvas.create_line(cx - r, cy, cx + r, cy, fill=T.hex_color("border"), width=1)
        self.canvas.create_line(cx, cy - r, cx, cy + r, fill=T.hex_color("border"), width=1)
        # Fixed arcs so the mark still reads as a radar. They do not sweep.
        self.canvas.create_arc(
            cx - r, cy - r, cx + r, cy + r,
            start=300, extent=48,
            style=tk.ARC, outline=T.hex_color("accent_hot"), width=2,
        )
        self.canvas.create_arc(
            cx - r + 8, cy - r + 8, cx + r - 8, cy + r - 8,
            start=128, extent=28,
            style=tk.ARC, outline=T.hex_color("accent"), width=2,
        )
        self.canvas.create_text(
            cx,
            cy,
            text="DV" if self._running else "WAIT",
            fill=T.hex_color("accent") if self._running else T.hex_color("mute"),
            font=("Segoe UI", 16, "bold"),
        )

    def set_running(self, running: bool) -> None:
        running = bool(running)
        if self._running == running:
            return
        self._running = running
        self._redraw_radar()

    def destroy(self) -> None:
        T.unsubscribe(self._on_theme)
        super().destroy()


class ActivityTicker(ctk.CTkFrame):
    """The latest measured collector summary, without invented activity."""

    def __init__(self, master, **kwargs) -> None:
        super().__init__(master, fg_color=T.BG_PANEL_ALT, corner_radius=4, height=36, **kwargs)
        self.pack_propagate(False)
        self._label = ctk.CTkLabel(
            self,
            text="Waiting for monitoring observations",
            font=T.FONT_MONO,
            text_color=T.TEXT,
            anchor="w",
        )
        self._label.pack(fill="x", padx=12, pady=6)

    def push(self, line: str) -> None:
        self._label.configure(text=line[:90], text_color=T.TEXT)


class NerveRail(ctk.CTkFrame):
    """Collector indicators driven only by the shared observation states."""

    def __init__(self, master, **kwargs) -> None:
        super().__init__(master, fg_color="transparent", height=28, **kwargs)
        self.pack_propagate(False)
        self._cells: list[ctk.CTkLabel] = []
        labels = ("Beat", "Pulse", "Net", "Privacy", "Shield", "Logons", "Scope")
        self._collector_names = (
            "heartbeat",
            "pulse",
            "connections",
            "privacy_guard",
            "security",
            "attacks",
            "capability",
        )
        for name in labels:
            cell = ctk.CTkLabel(
                self,
                text=name,
                font=("Consolas", 12, "bold"),
                text_color=T.TEXT_DIM,
                fg_color=T.BG_PANEL_ALT,
                corner_radius=4,
                width=78,
                height=24,
            )
            cell.pack(side="left", padx=3)
            self._cells.append(cell)

    def set_states(self, data: dict | None) -> None:
        colors = {
            "ok": T.SUCCESS,
            "running": T.ACCENT,
            "error": T.DANGER,
            "deferred": T.WARNING,
            "partial": T.WARNING,
            "stale": T.WARNING,
        }
        for cell, name in zip(self._cells, self._collector_names):
            cell.configure(
                text_color=colors.get(collector_state(data, name), T.TEXT_DIM),
                fg_color=T.BG_PANEL_ALT,
            )


class PressureGauge(ctk.CTkFrame):
    """Arc meter. The needle jumps to the measured value; it does not ease."""

    def __init__(self, master, title: str, **kwargs) -> None:
        super().__init__(master, fg_color=T.BG_PANEL_ALT, corner_radius=6, **kwargs)
        self.title = title
        self._value: float | None = None
        self._display = 0.0
        self._tone = "mute"
        self._size = 108
        self.canvas = tk.Canvas(
            self,
            width=self._size,
            height=self._size - 8,
            bg=T.hex_color("panel_alt"),
            highlightthickness=0,
            bd=0,
        )
        self.canvas.pack(pady=(8, 0))
        self.val_lbl = ctk.CTkLabel(
            self, text="—", font=("Segoe UI", 22, "bold"), text_color=T.TEXT_DIM,
        )
        self.val_lbl.pack()
        ctk.CTkLabel(self, text=title, font=T.FONT_TAGLINE, text_color=T.TEXT_DIM).pack(pady=(0, 8))
        T.subscribe(self._on_theme)
        self._redraw_gauge()

    def _on_theme(self, _mode: str) -> None:
        try:
            if not self.winfo_exists():
                T.unsubscribe(self._on_theme)
                return
            self.canvas.configure(bg=T.hex_color("panel_alt"))
            self._redraw_gauge()
        except Exception:
            T.unsubscribe(self._on_theme)

    def set_value(self, percent: float | None) -> None:
        if isinstance(percent, (int, float)) and not isinstance(percent, bool):
            try:
                numeric = float(percent)
            except (TypeError, ValueError):
                numeric = None
            else:
                if numeric != numeric or numeric in (float("inf"), float("-inf")):
                    numeric = None
                else:
                    numeric = max(0.0, min(100.0, numeric))
        else:
            numeric = None
        self._value = numeric
        if numeric is None:
            self._display = 0.0
            self._tone = "mute"
            self.val_lbl.configure(text="—", text_color=T.TEXT_DIM)
        else:
            self._display = numeric
            self._tone = self._tone_for(numeric)
            self.val_lbl.configure(text=f"{numeric:.0f}", text_color=T.pair(self._tone))
        self._redraw_gauge()

    @staticmethod
    def _tone_for(p: float) -> str:
        if p >= 90:
            return "crit"
        if p >= 75:
            return "warn"
        return "accent"

    def _redraw_gauge(self) -> None:
        self.canvas.delete("all")
        cx = self._size // 2
        cy = self._size // 2 + 4
        r = 42
        self.canvas.create_arc(
            cx - r, cy - r, cx + r, cy + r,
            start=200, extent=-220, style=tk.ARC, outline=T.hex_color("border"), width=8,
        )
        extent = -220 * (self._display / 100.0) if self._value is not None else 0
        self.canvas.create_arc(
            cx - r, cy - r, cx + r, cy + r,
            start=200, extent=extent, style=tk.ARC,
            outline=T.hex_color(self._tone if self._value is not None else "border"),
            width=8,
        )

    def destroy(self) -> None:
        T.unsubscribe(self._on_theme)
        super().destroy()


class ScanFeed(ctk.CTkFrame):
    """Intelligence feed. Text only — no moving scan line."""

    def __init__(self, master, **kwargs) -> None:
        super().__init__(master, fg_color=T.BG_DARK, **kwargs)
        self.text = ctk.CTkTextbox(
            self,
            font=T.FONT_MONO,
            fg_color=T.BG_DARK,
            text_color=T.TEXT,
            border_width=0,
            wrap="word",
        )
        self.text.pack(fill="both", expand=True)
        self.text.configure(state="disabled")

    def append(self, line: str) -> None:
        self.text.configure(state="normal")
        self.text.insert("end", line + "\n")
        lines = int(self.text.index("end-1c").split(".")[0])
        if lines > 600:
            self.text.delete("1.0", f"{lines - 600}.0")
        self.text.see("end")
        self.text.configure(state="disabled")


class MatrixRow(ctk.CTkFrame):
    """Protection-matrix row bound to a real signal via set_state().

    No fake cycling: the state is only ever what the caller sets from the twin /
    capability report / collector status. Defaults to an honest blank until data
    arrives. The dot uses the same color as the state word and does not blink.
    """

    def __init__(self, master, name: str, **kwargs) -> None:
        super().__init__(master, fg_color=T.BG_PANEL_ALT, corner_radius=4, **kwargs)
        self.name = name
        self.pip = ctk.CTkLabel(
            self, text="●", font=T.FONT_BODY, text_color=T.TEXT_DIM, width=18,
        )
        self.pip.pack(side="left", padx=(8, 0), pady=8)
        ctk.CTkLabel(self, text=name, font=T.FONT_BODY, text_color=T.TEXT).pack(
            side="left", padx=(4, 10), pady=8
        )
        self.state_lbl = ctk.CTkLabel(
            self, text="—", font=T.FONT_MONO, text_color=T.TEXT_DIM,
        )
        self.state_lbl.pack(side="right", padx=10, pady=8)

    def set_state(self, text: str, color: str) -> None:
        self.state_lbl.configure(text=text, text_color=color)
        self.pip.configure(text_color=color)


class ClockMono(ctk.CTkLabel):
    """Local and UTC clock. The digits change; the label does not move."""

    def __init__(self, master, **kwargs) -> None:
        super().__init__(master, text="", font=T.FONT_MONO, text_color=T.TEXT_DIM, **kwargs)
        self._tick()

    def _tick(self) -> None:
        from datetime import datetime, timezone

        try:
            if not self.winfo_exists():
                return
        except Exception:
            return
        local = datetime.now().strftime("%H:%M:%S")
        utc = datetime.now(timezone.utc).strftime("%H:%M:%S")
        self.configure(text=f"LOCAL {local}  ·  UTC {utc}")
        self.after(1000, self._tick)

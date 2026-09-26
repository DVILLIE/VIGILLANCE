"""Living Mission Console presence — always-on visual heartbeat (Phosphor Void).

Design refs (verified patterns, adapted to our tokens):
- Mission-control ops: live status pulse, mono telemetry, dark command density
- Phosphor Deck: instrument housings, scan zones, value-before-label
- Our DESIGN.md: one phosphor accent; motion for presence/heartbeat, not particle storms
"""

from __future__ import annotations

import math
import tkinter as tk

import customtkinter as ctk

from dvielle.gui import theme as T
from dvielle.gui.observations import collector_state

class LivingRadar(ctk.CTkFrame):
    """Slow radar DV core — continuous presence without frantic spin."""

    def __init__(self, master, size: int = 120, **kwargs) -> None:
        super().__init__(master, fg_color="transparent", **kwargs)
        self.size = size
        self._angle = 0.0
        self._pulse = 0.0
        self._sweep = 0.0
        self._running = False
        self.canvas = tk.Canvas(
            self,
            width=size,
            height=size,
            bg=T.BG_PANEL,
            highlightthickness=0,
            bd=0,
        )
        self.canvas.pack()
        self._redraw_radar()
        self._tick()

    def _redraw_radar(self) -> None:
        # Must not be named _draw — CTkFrame._draw(no_color_updates=...) owns that.
        self.canvas.delete("all")
        cx = cy = self.size // 2
        r = self.size // 2 - 6
        # Soft bloom ring
        bloom = 0.35 + 0.25 * (0.5 + 0.5 * math.sin(self._pulse))
        bloom_hex = T.ACCENT_DIM if bloom < 0.5 else T.ACCENT
        self.canvas.create_oval(
            cx - r - 2, cy - r - 2, cx + r + 2, cy + r + 2,
            outline=bloom_hex, width=1,
        )
        # Range rings
        for frac in (0.35, 0.6, 0.85, 1.0):
            rr = int(r * frac)
            self.canvas.create_oval(
                cx - rr, cy - rr, cx + rr, cy + rr,
                outline=T.BORDER, width=1,
            )
        # Crosshair
        self.canvas.create_line(cx - r, cy, cx + r, cy, fill=T.BORDER, width=1)
        self.canvas.create_line(cx, cy - r, cx, cy + r, fill=T.BORDER, width=1)
        # Sweep wedge (subtle arc)
        self.canvas.create_arc(
            cx - r, cy - r, cx + r, cy + r,
            start=self._sweep, extent=48,
            style=tk.ARC, outline=T.ACCENT_GLOW, width=2,
        )
        # Secondary arc opposite
        self.canvas.create_arc(
            cx - r + 8, cy - r + 8, cx + r - 8, cy + r - 8,
            start=self._angle, extent=28,
            style=tk.ARC, outline=T.ACCENT, width=2,
        )
        self.canvas.create_text(
            cx, cy, text="DV" if self._running else "WAIT", fill=T.ACCENT_GLOW if self._running else T.TEXT_DIM, font=("Segoe UI", 16, "bold"),
        )

    def set_running(self, running: bool) -> None:
        if self._running != bool(running):
            self._running = bool(running)
            self._redraw_radar()

    def _tick(self) -> None:
        try:
            if not self.winfo_viewable() or not self._running:
                self.after(500, self._tick)
                return
        except Exception:
            pass
        self._sweep = (self._sweep + 2.2) % 360
        self._angle = (self._angle - 1.1) % 360
        self._pulse += 0.12
        self._redraw_radar()
        self.after(120, self._tick)


class ActivityTicker(ctk.CTkFrame):
    """The latest measured collector summary, without invented activity."""

    def __init__(self, master, **kwargs) -> None:
        super().__init__(master, fg_color=T.BG_PANEL_ALT, corner_radius=4, height=36, **kwargs)
        self.pack_propagate(False)
        self._phase = 0
        self._label = ctk.CTkLabel(
            self,
            text="Waiting for monitoring observations",
            font=T.FONT_MONO,
            text_color=T.ACCENT,
            anchor="w",
        )
        self._label.pack(fill="x", padx=12, pady=6)
        self._dot = ctk.CTkLabel(self, text="▸", font=T.FONT_MONO, text_color=T.ACCENT_GLOW)
        self._dot.place(relx=0.97, rely=0.5, anchor="e")

    def push(self, line: str) -> None:
        self._label.configure(text=line[:90], text_color=T.ACCENT_GLOW)


class NerveRail(ctk.CTkFrame):
    """Collector indicators driven only by the shared observation states."""

    def __init__(self, master, **kwargs) -> None:
        super().__init__(master, fg_color="transparent", height=28, **kwargs)
        self.pack_propagate(False)
        self._idx = 0
        self._cells: list[ctk.CTkLabel] = []
        names = ("HB", "PULSE", "NET", "PRIV", "SEC", "AUTH", "DEEP")
        self._collector_names = ("heartbeat", "pulse", "connections", "privacy_guard", "security", "attacks", "capability")
        for name in names:
            cell = ctk.CTkLabel(
                self,
                text=name,
                font=("Consolas", 11, "bold"),
                text_color=T.TEXT_DIM,
                fg_color=T.BG_PANEL_ALT,
                corner_radius=3,
                width=64,
                height=22,
            )
            cell.pack(side="left", padx=3)
            self._cells.append(cell)

    def set_states(self, data: dict | None) -> None:
        colors = {"ok": T.SUCCESS, "running": T.ACCENT, "error": T.DANGER,
                  "deferred": T.WARNING, "partial": T.WARNING, "stale": T.WARNING}
        for cell, name in zip(self._cells, self._collector_names):
            cell.configure(text_color=colors.get(collector_state(data, name), T.TEXT_DIM), fg_color=T.BG_PANEL_ALT)


class PressureGauge(ctk.CTkFrame):
    """Large arc meter — value reads before label (Phosphor Deck grammar)."""

    def __init__(self, master, title: str, **kwargs) -> None:
        super().__init__(master, fg_color=T.BG_PANEL_ALT, corner_radius=4, **kwargs)
        self.title = title
        self._value: float | None = None
        self._display = 0.0
        self._size = 108
        self.canvas = tk.Canvas(
            self, width=self._size, height=self._size - 8,
            bg=T.BG_PANEL_ALT, highlightthickness=0, bd=0,
        )
        self.canvas.pack(pady=(8, 0))
        self.val_lbl = ctk.CTkLabel(self, text="—", font=("Segoe UI", 22, "bold"), text_color=T.ACCENT_GLOW)
        self.val_lbl.pack()
        ctk.CTkLabel(self, text=title, font=T.FONT_TAGLINE, text_color=T.TEXT_DIM).pack(pady=(0, 8))
        self._redraw_gauge()
        self._ease()

    def set_value(self, percent: float | None) -> None:
        self._value = max(0.0, min(100.0, percent)) if isinstance(percent, (int, float)) and not isinstance(percent, bool) and math.isfinite(percent) else None
        self.val_lbl.configure(text="—" if self._value is None else f"{self._value:.0f}", text_color=T.TEXT_DIM if self._value is None else self._color_for(self._value))
        if self._value is None:
            self._display = 0.0
            self._redraw_gauge()

    def _color_for(self, p: float) -> str:
        if p >= 90:
            return T.DANGER
        if p >= 75:
            return T.WARNING
        return T.ACCENT

    def _redraw_gauge(self) -> None:
        self.canvas.delete("all")
        cx = self._size // 2
        cy = self._size // 2 + 4
        r = 42
        # Track
        self.canvas.create_arc(
            cx - r, cy - r, cx + r, cy + r,
            start=200, extent=-220, style=tk.ARC, outline=T.BORDER, width=8,
        )
        extent = -220 * (self._display / 100.0) if self._value is not None else 0
        color = self._color_for(self._display)
        self.canvas.create_arc(
            cx - r, cy - r, cx + r, cy + r,
            start=200, extent=extent, style=tk.ARC, outline=color, width=8,
        )

    def _ease(self) -> None:
        try:
            if not self.winfo_viewable():
                self.after(500, self._ease)
                return
        except Exception:
            pass
        # Ease toward target so meters feel alive
        if self._value is None:
            self.after(500, self._ease)
            return
        delta = self._value - self._display
        if abs(delta) > 0.15:
            self._display += delta * 0.18
            self._redraw_gauge()
        self.after(150, self._ease)


class ScanFeed(ctk.CTkFrame):
    """Intelligence feed with moving scan line overlay for presence."""

    def __init__(self, master, **kwargs) -> None:
        super().__init__(master, fg_color=T.BG_DARK, **kwargs)
        self.text = ctk.CTkTextbox(
            self,
            font=T.FONT_MONO,
            fg_color=T.BG_DARK,
            text_color=T.ACCENT_GLOW,
            border_width=0,
            wrap="word",
        )
        self.text.pack(fill="both", expand=True)
        self.text.configure(state="disabled")
        self._scan = tk.Canvas(self, height=2, bg=T.BG_DARK, highlightthickness=0, bd=0)
        self._scan.place(relx=0, rely=0.08, relwidth=1, height=2)
        self._y = 0.06
        self._dir = 1
        self._animate_scan()

    def append(self, line: str) -> None:
        self.text.configure(state="normal")
        self.text.insert("end", line + "\n")
        lines = int(self.text.index("end-1c").split(".")[0])
        if lines > 600:
            self.text.delete("1.0", f"{lines - 600}.0")
        self.text.see("end")
        self.text.configure(state="disabled")

    def _animate_scan(self) -> None:
        try:
            if not self.winfo_viewable():
                self.after(500, self._animate_scan)
                return
        except Exception:
            pass
        self._y += 0.012 * self._dir
        if self._y > 0.92:
            self._dir = -1
        elif self._y < 0.06:
            self._dir = 1
        self._scan.configure(bg=T.ACCENT if self._dir > 0 else T.ACCENT_DIM)
        self._scan.place(relx=0, rely=self._y, relwidth=1, height=2)
        self.after(55, self._animate_scan)


class MatrixRow(ctk.CTkFrame):
    """Protection-matrix row bound to a REAL signal via set_state().

    No fake cycling: the state is only ever what the caller sets from the twin /
    capability report / collector status (audit C3 honesty). Defaults to an
    honest 'unknown' until data arrives.
    """

    def __init__(self, master, name: str, **kwargs) -> None:
        super().__init__(master, fg_color=T.BG_PANEL_ALT, corner_radius=4, **kwargs)
        self.name = name
        ctk.CTkLabel(self, text=name, font=T.FONT_BODY, text_color=T.TEXT).pack(
            side="left", padx=10, pady=8
        )
        self.state_lbl = ctk.CTkLabel(
            self, text="—", font=T.FONT_MONO, text_color=T.TEXT_DIM,
        )
        self.state_lbl.pack(side="right", padx=10, pady=8)

    def set_state(self, text: str, color: str) -> None:
        self.state_lbl.configure(text=text, text_color=color)


class ClockMono(ctk.CTkLabel):
    """UTC / local ticking clock for ops credibility."""

    def __init__(self, master, **kwargs) -> None:
        super().__init__(master, text="", font=T.FONT_MONO, text_color=T.TEXT_DIM, **kwargs)
        self._tick()

    def _tick(self) -> None:
        from datetime import datetime, timezone

        local = datetime.now().strftime("%H:%M:%S")
        utc = datetime.now(timezone.utc).strftime("%H:%M:%S")
        self.configure(text=f"LOCAL {local}  ·  UTC {utc}")
        self.after(1000, self._tick)

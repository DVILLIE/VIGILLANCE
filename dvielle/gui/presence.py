"""Living Mission Console presence — always-on visual heartbeat (Phosphor Void).

Design refs (verified patterns, adapted to our tokens):
- Mission-control ops: live status pulse, mono telemetry, dark command density
- Phosphor Deck: instrument housings, scan zones, value-before-label
- Our DESIGN.md: one phosphor accent; motion for presence/heartbeat, not particle storms
"""

from __future__ import annotations

import math
import random
import tkinter as tk
from itertools import cycle

import customtkinter as ctk

from dvielle.gui import theme as T

# Verbs that make the console feel like Nerve is working (not fake threats)
_NERVE_LINES = (
    "NERVE · heartbeat · pressure counters",
    "TWIN · memory vector refresh",
    "SCAN · process forest sample",
    "TRAFFIC · purpose classify",
    "SURFACE · defender posture skim",
    "SELF · budget check · footprint OK",
    "CORTEX · correlate contention",
    "IDLE-DEEP · deferred until quiet",
    "VISION · capability gaps honest",
    "WHY · evidence chain ready",
)


class LivingRadar(ctk.CTkFrame):
    """Slow radar DV core — continuous presence without frantic spin."""

    def __init__(self, master, size: int = 120, **kwargs) -> None:
        super().__init__(master, fg_color="transparent", **kwargs)
        self.size = size
        self._angle = 0.0
        self._pulse = 0.0
        self._sweep = 0.0
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
        # Blip
        br = math.radians(self._sweep + 20)
        bx = cx + (r * 0.62) * math.cos(br)
        by = cy - (r * 0.62) * math.sin(br)
        self.canvas.create_oval(bx - 3, by - 3, bx + 3, by + 3, fill=T.ACCENT_GLOW, outline="")
        self.canvas.create_text(
            cx, cy, text="DV", fill=T.ACCENT_GLOW, font=("Segoe UI", 16, "bold"),
        )

    def _tick(self) -> None:
        self._sweep = (self._sweep + 2.2) % 360
        self._angle = (self._angle - 1.1) % 360
        self._pulse += 0.12
        self._redraw_radar()
        self.after(40, self._tick)


class ActivityTicker(ctk.CTkFrame):
    """Scrolling nerve activity — feels always busy, stays truthful."""

    def __init__(self, master, **kwargs) -> None:
        super().__init__(master, fg_color=T.BG_PANEL_ALT, corner_radius=4, height=36, **kwargs)
        self.pack_propagate(False)
        self._lines = cycle(_NERVE_LINES)
        self._phase = 0
        self._label = ctk.CTkLabel(
            self,
            text=next(self._lines),
            font=T.FONT_MONO,
            text_color=T.ACCENT,
            anchor="w",
        )
        self._label.pack(fill="x", padx=12, pady=6)
        self._dot = ctk.CTkLabel(self, text="▸", font=T.FONT_MONO, text_color=T.ACCENT_GLOW)
        self._dot.place(relx=0.97, rely=0.5, anchor="e")
        self._advance()

    def push(self, line: str) -> None:
        self._label.configure(text=line[:90], text_color=T.ACCENT_GLOW)
        self.after(1200, lambda: self._label.configure(text_color=T.ACCENT))

    def _advance(self) -> None:
        self._phase = (self._phase + 1) % 2
        self._dot.configure(text_color=T.ACCENT_GLOW if self._phase else T.ACCENT_DIM)
        if self._phase == 0:
            self._label.configure(text=next(self._lines))
        self.after(1800, self._advance)


class NerveRail(ctk.CTkFrame):
    """Horizontal collector LEDs that chase — heartbeat / pulse / deep."""

    def __init__(self, master, **kwargs) -> None:
        super().__init__(master, fg_color="transparent", height=28, **kwargs)
        self.pack_propagate(False)
        self._idx = 0
        self._cells: list[ctk.CTkLabel] = []
        names = ("HB", "PULSE", "NET", "PRIV", "SEC", "TWIN", "WHY")
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
        self._chase()

    def _chase(self) -> None:
        for i, cell in enumerate(self._cells):
            if i == self._idx:
                cell.configure(text_color=T.BG_DARK, fg_color=T.ACCENT)
            elif i == (self._idx - 1) % len(self._cells):
                cell.configure(text_color=T.ACCENT_GLOW, fg_color=T.BG_PANEL_ALT)
            else:
                cell.configure(text_color=T.TEXT_DIM, fg_color=T.BG_PANEL_ALT)
        self._idx = (self._idx + 1) % len(self._cells)
        self.after(420, self._chase)


class PressureGauge(ctk.CTkFrame):
    """Large arc meter — value reads before label (Phosphor Deck grammar)."""

    def __init__(self, master, title: str, **kwargs) -> None:
        super().__init__(master, fg_color=T.BG_PANEL_ALT, corner_radius=4, **kwargs)
        self.title = title
        self._value = 0.0
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

    def set_value(self, percent: float) -> None:
        self._value = max(0.0, min(100.0, percent))

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
        extent = -220 * (self._display / 100.0)
        color = self._color_for(self._display)
        self.canvas.create_arc(
            cx - r, cy - r, cx + r, cy + r,
            start=200, extent=extent, style=tk.ARC, outline=color, width=8,
        )

    def _ease(self) -> None:
        # Ease toward target so meters feel alive
        delta = self._value - self._display
        if abs(delta) > 0.15:
            self._display += delta * 0.18
            self.val_lbl.configure(text=f"{self._display:.0f}", text_color=self._color_for(self._display))
            self._redraw_gauge()
        self.after(50, self._ease)


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
        self.text.see("end")
        self.text.configure(state="disabled")

    def _animate_scan(self) -> None:
        self._y += 0.012 * self._dir
        if self._y > 0.92:
            self._dir = -1
        elif self._y < 0.06:
            self._dir = 1
        self._scan.configure(bg=T.ACCENT if self._dir > 0 else T.ACCENT_DIM)
        self._scan.place(relx=0, rely=self._y, relwidth=1, height=2)
        self.after(55, self._animate_scan)


class MatrixRow(ctk.CTkFrame):
    """Protection matrix row with cycling SCAN → LIVE states."""

    _STATES = ("IDLE", "SCAN", "LIVE", "SYNC")

    def __init__(self, master, name: str, delay_ms: int = 0, **kwargs) -> None:
        super().__init__(master, fg_color=T.BG_PANEL_ALT, corner_radius=4, **kwargs)
        self.name = name
        self._i = random.randint(0, len(self._STATES) - 1)
        ctk.CTkLabel(self, text=name, font=T.FONT_BODY, text_color=T.TEXT).pack(
            side="left", padx=10, pady=8
        )
        self.state_lbl = ctk.CTkLabel(
            self, text=self._STATES[self._i], font=T.FONT_MONO, text_color=T.ACCENT_DIM,
        )
        self.state_lbl.pack(side="right", padx=10, pady=8)
        self.after(delay_ms + 800, self._cycle)

    def _cycle(self) -> None:
        self._i = (self._i + 1) % len(self._STATES)
        st = self._STATES[self._i]
        color = {
            "IDLE": T.TEXT_DIM,
            "SCAN": T.WARNING,
            "LIVE": T.SUCCESS,
            "SYNC": T.ACCENT_GLOW,
        }[st]
        self.state_lbl.configure(text=st, text_color=color)
        self.after(1600 + random.randint(0, 900), self._cycle)


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

"""Rotating holographic ring animation — Jarvis-style core visual."""

from __future__ import annotations

import math
import tkinter as tk

import customtkinter as ctk

from dvielle.gui import theme as T


class HologramRing(ctk.CTkFrame):
    """Animated cyan ring that rotates continuously."""

    def __init__(self, master, size: int = 88, **kwargs) -> None:
        super().__init__(master, fg_color="transparent", **kwargs)
        self.size = size
        self._angle = 0.0
        self.canvas = tk.Canvas(
            self,
            width=size,
            height=size,
            bg=T.BG_PANEL,
            highlightthickness=0,
            bd=0,
        )
        self.canvas.pack()
        self._redraw_ring()
        self._animate()

    def _redraw_ring(self) -> None:
        self.canvas.delete("all")
        cx = cy = self.size // 2
        r_outer = self.size // 2 - 4
        r_inner = r_outer - 10

        self.canvas.create_oval(
            cx - r_outer, cy - r_outer, cx + r_outer, cy + r_outer,
            outline=T.BORDER, width=1,
        )
        self.canvas.create_oval(
            cx - r_inner + 6, cy - r_inner + 6, cx + r_inner - 6, cy + r_inner - 6,
            outline=T.ACCENT_DIM, width=1,
        )

        for i, span in enumerate((70, 50, 40)):
            start = self._angle + i * 120
            color = T.ACCENT_GLOW if i == 0 else T.ACCENT if i == 1 else T.ACCENT_DIM
            self.canvas.create_arc(
                cx - r_outer + 2, cy - r_outer + 2,
                cx + r_outer - 2, cy + r_outer - 2,
                start=start, extent=span,
                style=tk.ARC, outline=color, width=2,
            )

        self.canvas.create_text(cx, cy, text="DV", fill=T.ACCENT_GLOW, font=("Segoe UI", 11, "bold"))

        rad = math.radians(self._angle)
        x2 = cx + r_outer * math.cos(rad)
        y2 = cy + r_outer * math.sin(rad)
        self.canvas.create_line(cx, cy, x2, y2, fill=T.ACCENT_GLOW, width=1)

    def _animate(self) -> None:
        self._angle = (self._angle + 4) % 360
        self._redraw_ring()
        self.after(50, self._animate)

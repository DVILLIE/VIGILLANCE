"""Brand mark. This is the only animated widget in the console.

Startup rotates the mark in over a handful of frames, then a slow
brightness pulse runs about once a second. Gauges, lists, tabs, and
backgrounds do not move.
"""

from __future__ import annotations

import customtkinter as ctk

from dvielle.brand import brand_png
from dvielle.gui import theme as T

# Six frames, then idle. Idle is intentionally slow so the pulse stays cheap.
INTRO_ANGLES = (-16, -11, -7, -4, -2, 0)
INTRO_MS = 70
IDLE_MS = 1100
IDLE_GAINS = (1.0, 1.07)


def motion_plan() -> dict:
    return {
        "intro_angles": INTRO_ANGLES,
        "intro_ms": INTRO_MS,
        "idle_ms": IDLE_MS,
        "idle_gains": IDLE_GAINS,
        "intro_frames": len(INTRO_ANGLES),
        "animates": "logo",
    }


def _render_frame(base, image_module, enhance, angle: float, gain: float):
    image = base.rotate(angle, resample=image_module.Resampling.BICUBIC, expand=False)
    if abs(gain - 1.0) > 0.001:
        image = enhance.Brightness(image).enhance(gain)
    return image


class LogoMark(ctk.CTkFrame):
    def __init__(self, master, size: int = 68, **kwargs) -> None:
        super().__init__(
            master,
            fg_color="transparent",
            width=size,
            height=size,
            **kwargs,
        )
        self.pack_propagate(False)
        self.size = size
        self._alive = True
        self._intro_i = 0
        self._idle_i = 0
        self._intro: list = []
        self._idle: list = []
        self._photo = None
        self._label = ctk.CTkLabel(self, text="", text_color=T.ACCENT)
        self._label.pack(expand=True)
        self._prepare()
        if self._intro:
            self._show(self._intro[0])
            self._intro_i = 1
        self.after(INTRO_MS, self._tick)

    def _prepare(self) -> None:
        path = brand_png(128)
        if not path.exists():
            self._label.configure(text="DV", font=T.FONT_TITLE, text_color=T.ACCENT)
            return
        try:
            from PIL import Image, ImageEnhance
        except ImportError:
            self._label.configure(text="DV", font=T.FONT_TITLE, text_color=T.ACCENT)
            return
        try:
            base = Image.open(path).convert("RGBA")
            base = base.resize((self.size, self.size), Image.Resampling.LANCZOS)
        except Exception:
            self._label.configure(text="DV", font=T.FONT_TITLE, text_color=T.ACCENT)
            return
        steps = max(1, len(INTRO_ANGLES) - 1)
        for index, angle in enumerate(INTRO_ANGLES):
            gain = 0.82 + 0.18 * (index / steps)
            self._intro.append(_render_frame(base, Image, ImageEnhance, angle, gain))
        for gain in IDLE_GAINS:
            self._idle.append(_render_frame(base, Image, ImageEnhance, 0, gain))

    def _show(self, image) -> None:
        self._photo = ctk.CTkImage(
            light_image=image,
            dark_image=image,
            size=(self.size, self.size),
        )
        self._label.configure(image=self._photo, text="")

    def _tick(self) -> None:
        if not self._alive:
            return
        try:
            if not self.winfo_exists():
                self._alive = False
                return
        except Exception:
            self._alive = False
            return
        if self._intro and self._intro_i < len(self._intro):
            self._show(self._intro[self._intro_i])
            self._intro_i += 1
            self.after(INTRO_MS, self._tick)
            return
        if self._idle:
            self._show(self._idle[self._idle_i % len(self._idle)])
            self._idle_i += 1
            self.after(IDLE_MS, self._tick)
            return
        # Text fallback when the PNG could not be read. Still the logo only.
        tone = T.hex_color("accent") if self._idle_i % 2 == 0 else T.hex_color("accent_dim")
        self._idle_i += 1
        self._label.configure(text="DV", text_color=tone)
        self.after(IDLE_MS, self._tick)

    def destroy(self) -> None:
        self._alive = False
        super().destroy()

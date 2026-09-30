"""DVielle emblem. This is the only animated widget in the console.

The mark is a deep disc, two orbits, and a D/V monogram with a nucleus.
Startup scales and turns it in over a handful of frames, and the orbits
draw themselves in during that same short intro. Then a slow brightness
pulse runs about once a second. Nothing else in the console moves.
"""

from __future__ import annotations

import math

import customtkinter as ctk

from dvielle.gui import theme as T

# Six frames, then idle. Idle is intentionally slow so the pulse stays cheap.
INTRO_ANGLES = (-16, -11, -7, -4, -2, 0)
INTRO_REVEAL = (0.34, 0.52, 0.68, 0.82, 0.93, 1.0)
INTRO_SCALES = (0.74, 0.84, 0.91, 0.96, 0.99, 1.0)
INTRO_MS = 70
IDLE_MS = 1100
IDLE_GAINS = (1.0, 1.05)

_INK = (236, 244, 246, 255)
_MINT = (126, 196, 186, 235)
_LILAC = (186, 176, 224, 220)
_SKY = (156, 198, 214, 210)
_DISC = (12, 16, 30, 255)
_DISC_INNER = (22, 28, 48, 255)


def motion_plan() -> dict:
    return {
        "intro_angles": INTRO_ANGLES,
        "intro_ms": INTRO_MS,
        "idle_ms": IDLE_MS,
        "idle_gains": IDLE_GAINS,
        "intro_frames": len(INTRO_ANGLES),
        "animates": "logo",
    }


def draw_emblem(size: int, reveal: float = 1.0):
    """Still emblem. ``reveal`` only shortens the orbits for the intro frames."""
    from PIL import Image, ImageDraw

    reveal = max(0.0, min(1.0, float(reveal)))
    src = max(int(size) * 4, 96)
    image = Image.new("RGBA", (src, src), (0, 0, 0, 0))
    draw = ImageDraw.Draw(image)
    margin = src * 0.06
    draw.ellipse((margin, margin, src - margin, src - margin), fill=_DISC)
    inner = src * 0.12
    draw.ellipse((inner, inner, src - inner, src - inner), fill=_DISC_INNER)
    rim = max(2, src // 64)
    draw.ellipse((margin, margin, src - margin, src - margin), outline=_SKY, width=rim)
    draw.ellipse((inner, inner, src - inner, src - inner), outline=_LILAC, width=max(1, rim - 1))

    extent = 36 + 250 * reveal
    wide = (src * 0.16, src * 0.34, src * 0.84, src * 0.66)
    tall = (src * 0.30, src * 0.14, src * 0.70, src * 0.86)
    stroke = max(2, src // 46)
    draw.arc(wide, 200, 200 + extent, fill=_MINT, width=stroke)
    draw.arc(tall, 18, 18 + extent * 0.9, fill=_LILAC, width=stroke)
    _electron(draw, wide, 200 + extent, src)
    if reveal > 0.45:
        _electron(draw, tall, 18 + extent * 0.9, src)

    pen = max(3, src // 18)
    spine = src * 0.36
    draw.line((spine, src * 0.30, spine, src * 0.72), fill=_INK, width=pen)
    draw.arc((src * 0.30, src * 0.28, src * 0.58, src * 0.74), 292, 68, fill=_INK, width=pen)
    draw.line((src * 0.50, src * 0.32, src * 0.62, src * 0.70), fill=_INK, width=pen)
    draw.line((src * 0.74, src * 0.32, src * 0.62, src * 0.70), fill=_INK, width=pen)
    nucleus = src * 0.62, src * 0.70
    halo = src * 0.055
    core = src * 0.028
    draw.ellipse(
        (nucleus[0] - halo, nucleus[1] - halo, nucleus[0] + halo, nucleus[1] + halo),
        fill=(126, 196, 186, 80),
    )
    draw.ellipse(
        (nucleus[0] - core, nucleus[1] - core, nucleus[0] + core, nucleus[1] + core),
        fill=(248, 252, 250, 255),
    )
    return image.resize((int(size), int(size)), Image.Resampling.LANCZOS)


def _electron(draw, box, angle: float, src: int) -> None:
    cx = (box[0] + box[2]) / 2
    cy = (box[1] + box[3]) / 2
    rx = (box[2] - box[0]) / 2
    ry = (box[3] - box[1]) / 2
    theta = math.radians(angle)
    # Pillow arcs run counter-clockwise from the 3 o'clock point.
    ex = cx + rx * math.cos(theta)
    ey = cy - ry * math.sin(theta)
    rad = max(2, src // 40)
    draw.ellipse((ex - rad, ey - rad, ex + rad, ey + rad), fill=_MINT)


def _render_frame(base, image_module, enhance, angle: float, gain: float, scale: float = 1.0):
    image = base
    if scale < 0.999:
        width = max(1, int(base.width * scale))
        height = max(1, int(base.height * scale))
        small = base.resize((width, height), image_module.Resampling.BICUBIC)
        canvas = image_module.new("RGBA", base.size, (0, 0, 0, 0))
        canvas.paste(small, ((base.width - width) // 2, (base.height - height) // 2), small)
        image = canvas
    image = image.rotate(angle, resample=image_module.Resampling.BICUBIC, expand=False)
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
        try:
            from PIL import Image, ImageEnhance
        except ImportError:
            self._label.configure(text="DV", font=T.FONT_TITLE, text_color=T.ACCENT)
            return
        try:
            steps = max(1, len(INTRO_ANGLES) - 1)
            for index, angle in enumerate(INTRO_ANGLES):
                mark = draw_emblem(self.size, reveal=INTRO_REVEAL[index])
                gain = 0.9 + 0.1 * (index / steps)
                self._intro.append(
                    _render_frame(mark, Image, ImageEnhance, angle, gain, INTRO_SCALES[index])
                )
            settled = draw_emblem(self.size, reveal=1.0)
            for gain in IDLE_GAINS:
                self._idle.append(_render_frame(settled, Image, ImageEnhance, 0, gain, 1.0))
        except Exception:
            self._intro.clear()
            self._idle.clear()
            self._label.configure(text="DV", font=T.FONT_TITLE, text_color=T.ACCENT)

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
        tone = T.hex_color("accent") if self._idle_i % 2 == 0 else T.hex_color("accent_dim")
        self._idle_i += 1
        self._label.configure(text="DV", text_color=tone)
        self.after(IDLE_MS, self._tick)

    def destroy(self) -> None:
        self._alive = False
        super().destroy()

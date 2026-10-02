"""DVielle emblem. This is the only animated widget in the console.

Prefers the shipped brand GIF (chrome D + orbital ring) when present under
``assets/brand/dvielle-logo-animated.gif``. Falls back to a drawn D/V monogram
with intro orbits when the GIF is missing.

Frames advance only once the mark is viewable (CustomTkinter title-bar setup
withdraws the window and calls ``update()`` first). Nothing else in the console
moves. Product spelling in UI text is always **DVielle**; the GIF is the visual
mark only.
"""

from __future__ import annotations

import math
import tkinter as tk

import customtkinter as ctk

from dvielle.gui import theme as T

# Drawn-fallback intro (used only when the brand GIF is absent).
INTRO_ANGLES = (-16, -11, -7, -4, -2, 0)
INTRO_REVEAL = (0.34, 0.52, 0.68, 0.82, 0.93, 1.0)
INTRO_SCALES = (0.74, 0.84, 0.91, 0.96, 0.99, 1.0)
INTRO_MS = 70
IDLE_MS = 1100
IDLE_GAINS = (1.0, 1.12)
HIDDEN_MS = 200
# Brand GIF: short intro from the first frames, then loop the rest.
GIF_INTRO_FRAMES = 6
GIF_FRAME_MS = 70

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
        "hidden_ms": HIDDEN_MS,
        "intro_frames": len(INTRO_ANGLES),
        "gif_intro_frames": GIF_INTRO_FRAMES,
        "gif_frame_ms": GIF_FRAME_MS,
        "animates": "logo",
        "starts_when": "viewable",
        "source": "brand_gif_or_drawn",
    }


def draw_emblem(size: int, reveal: float = 1.0):
    """Still drawn emblem. ``reveal`` only shortens the orbits for intro frames."""
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


def build_frames(size: int) -> tuple[list, list]:
    """Drawn intro + idle pulse. Used when the brand GIF is unavailable."""
    from PIL import Image, ImageEnhance

    intro: list = []
    steps = max(1, len(INTRO_ANGLES) - 1)
    for index, angle in enumerate(INTRO_ANGLES):
        mark = draw_emblem(size, reveal=INTRO_REVEAL[index])
        gain = 0.9 + 0.1 * (index / steps)
        intro.append(_render_frame(mark, Image, ImageEnhance, angle, gain, INTRO_SCALES[index]))
    settled = draw_emblem(size, reveal=1.0)
    idle = [
        _render_frame(settled, Image, ImageEnhance, 0, gain, 1.0)
        for gain in IDLE_GAINS
    ]
    return intro, idle


def build_brand_gif_frames(size: int) -> tuple[list, list] | None:
    """Brand GIF split into a short intro and a looping idle. None if missing."""
    from dvielle.brand import load_brand_gif_frames

    frames = load_brand_gif_frames(size)
    if not frames or len(frames) < 2:
        return None
    intro_n = min(GIF_INTRO_FRAMES, max(1, len(frames) // 4))
    intro = frames[:intro_n]
    idle = frames[intro_n:] if len(frames) > intro_n else frames
    return intro, idle


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
        self.size = int(size)
        self._alive = True
        self._intro_i = 0
        self._idle_i = 0
        self._intro: list = []
        self._idle: list = []
        self._using_gif = False
        self._frame_ms = INTRO_MS
        self._idle_ms = IDLE_MS
        self._current = None
        self._photo = None
        self._image_item = None
        self._text_item = None
        self._using_text = False
        self._job = None
        self._job_owner = None
        self._canvas = tk.Canvas(
            self,
            width=self.size,
            height=self.size,
            bg=T.hex_color("panel"),
            highlightthickness=0,
            bd=0,
        )
        self._canvas.pack(expand=True)
        self._prepare()
        self._paint_initial()
        try:
            self.bind("<Map>", self._on_map, add="+")
        except Exception:
            pass
        T.subscribe(self._on_theme)
        self._schedule(1)

    def _set_scaling(self, new_widget_scaling, new_window_scaling) -> None:
        super()._set_scaling(new_widget_scaling, new_window_scaling)
        if getattr(self, "_canvas", None) is None:
            return
        try:
            self._repaint()
        except Exception:
            pass

    def _pixel_size(self) -> int:
        try:
            scale = float(self._get_widget_scaling())
        except Exception:
            scale = 1.0
        return max(1, int(round(self.size * scale)))

    def _fit_canvas(self) -> None:
        px = self._pixel_size()
        self._canvas.configure(width=px, height=px, bg=T.hex_color("panel"))

    def _prepare(self) -> None:
        try:
            gif = build_brand_gif_frames(self.size)
        except Exception:
            gif = None
        if gif is not None:
            self._intro, self._idle = gif
            self._using_gif = True
            self._frame_ms = GIF_FRAME_MS
            self._idle_ms = GIF_FRAME_MS
            self._using_text = False
            return
        try:
            intro, idle = build_frames(self.size)
        except Exception:
            self._using_text = True
            self._intro = []
            self._idle = []
            return
        if not intro or not idle:
            self._using_text = True
            return
        self._intro = intro
        self._idle = idle
        self._using_gif = False
        self._frame_ms = INTRO_MS
        self._idle_ms = IDLE_MS

    def _paint_initial(self) -> None:
        if self._intro and not self._using_text:
            try:
                self._show(self._intro[0])
                return
            except Exception:
                self._using_text = True
                self._intro = []
                self._idle = []
        self._show_text(T.hex_color("accent"))

    def _show(self, image) -> None:
        from PIL import Image, ImageTk

        px = self._pixel_size()
        shown = image
        if shown.size != (px, px):
            shown = shown.resize((px, px), Image.Resampling.LANCZOS)
        photo = ImageTk.PhotoImage(shown)
        self._fit_canvas()
        if self._image_item is None:
            self._canvas.delete("all")
            self._text_item = None
            self._image_item = self._canvas.create_image(px // 2, px // 2, image=photo)
        else:
            self._canvas.coords(self._image_item, px // 2, px // 2)
            self._canvas.itemconfig(self._image_item, image=photo)
        self._photo = photo
        self._current = image

    def _show_text(self, color: str) -> None:
        px = self._pixel_size()
        self._fit_canvas()
        self._image_item = None
        self._photo = None
        self._current = None
        if self._text_item is None:
            self._canvas.delete("all")
            self._text_item = self._canvas.create_text(
                px // 2,
                px // 2,
                text="DV",
                fill=color,
                font=("Segoe UI", max(12, px // 3), "bold"),
            )
        else:
            self._canvas.coords(self._text_item, px // 2, px // 2)
            self._canvas.itemconfig(self._text_item, fill=color)

    def _pulse_text(self) -> None:
        tone = T.hex_color("accent") if self._idle_i % 2 == 0 else T.hex_color("accent_dim")
        self._idle_i += 1
        self._show_text(tone)

    def _repaint(self) -> None:
        if self._current is not None and not self._using_text:
            self._show(self._current)
            return
        if self._text_item is not None or self._using_text:
            tone = T.hex_color("accent") if self._idle_i % 2 == 0 else T.hex_color("accent_dim")
            self._show_text(tone)

    def _on_map(self, _event=None) -> None:
        if not self._alive:
            return
        try:
            self._repaint()
        except Exception:
            pass
        if self._intro and self._intro_i < len(self._intro):
            self._schedule(1)

    def _on_theme(self, _mode: str) -> None:
        if not self._alive:
            return
        try:
            if not self.winfo_exists():
                T.unsubscribe(self._on_theme)
                return
            self._canvas.configure(bg=T.hex_color("panel"))
            self._repaint()
        except Exception:
            T.unsubscribe(self._on_theme)

    def _schedule(self, ms: int) -> None:
        self._cancel()
        if not self._alive:
            return
        try:
            owner = self.winfo_toplevel()
            self._job_owner = owner
            self._job = owner.after(int(ms), self._tick)
        except Exception:
            self._job = None
            self._job_owner = None

    def _cancel(self) -> None:
        job, owner = self._job, self._job_owner
        self._job = None
        self._job_owner = None
        if job is None or owner is None:
            return
        try:
            owner.after_cancel(job)
        except Exception:
            pass

    def _give_up_to_text(self) -> None:
        self._using_text = True
        self._intro = []
        self._idle = []
        self._current = None
        self._pulse_text()

    def _advance(self) -> None:
        if self._using_text or (not self._intro and not self._idle):
            self._pulse_text()
            self._schedule(self._idle_ms)
            return
        try:
            if self._intro and self._intro_i < len(self._intro):
                self._show(self._intro[self._intro_i])
                self._intro_i += 1
                self._schedule(self._frame_ms)
                return
            if self._idle:
                self._show(self._idle[self._idle_i % len(self._idle)])
                self._idle_i += 1
                self._schedule(self._idle_ms)
                return
        except Exception:
            self._give_up_to_text()
            self._schedule(self._idle_ms)
            return
        self._pulse_text()
        self._schedule(self._idle_ms)

    def _tick(self) -> None:
        self._job = None
        self._job_owner = None
        if not self._alive:
            return
        try:
            if not self.winfo_exists():
                self._alive = False
                return
        except Exception:
            self._alive = False
            return
        try:
            visible = bool(self.winfo_viewable())
        except Exception:
            visible = False
        if not visible:
            self._schedule(HIDDEN_MS)
            return
        try:
            self._advance()
        except Exception:
            try:
                self._give_up_to_text()
            except Exception:
                return
            self._schedule(self._idle_ms)

    def destroy(self) -> None:
        self._alive = False
        self._cancel()
        T.unsubscribe(self._on_theme)
        super().destroy()

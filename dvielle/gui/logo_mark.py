"""D\'Vielle dimensional emblem with optional motion and bounded frame caching.

Prefers the approved Quantum Key artwork and native electrical effects, then a GIF under
``assets/brand/dvielle-logo-animated.gif``. Falls back to a drawn D/V monogram
with intro orbits when both image assets are missing.

Frames advance only once the mark is viewable (CustomTkinter title-bar setup
withdraws the window and calls ``update()`` first). Nothing else in the console
moves in this module. The application separately supports short interaction
transitions. Product spelling in UI text is always **D\'Vielle**; the image is the visual
mark only.
"""

from __future__ import annotations

import math
import time
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
        "source": "quantum_key_or_brand_gif_or_drawn",
        "circuit_seconds": 45,
        "thunder_seconds": 5,
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


def build_nexus_frames(size: int):
    """Animate the approved dimensional bitmap with visible depth/lighting changes.

    This is a 2D rendering of the chrome 3D artwork, not a new 3D mesh.
    The mark is never replaced by a newly drawn monogram.
    """
    from PIL import Image, ImageEnhance
    from dvielle.brand import NEXUS_LOGO
    if not NEXUS_LOGO.is_file():
        return None
    with Image.open(NEXUS_LOGO) as source:
        base = source.convert("RGBA")
        bounds = base.getbbox()
        if bounds:
            base = base.crop(bounds)
        base.thumbnail((size-4, size-4), Image.Resampling.LANCZOS)
        square = Image.new("RGBA", (size, size))
        square.alpha_composite(base, ((size-base.width)//2, (size-base.height)//2))
        base = square
    # Full turn about the vertical axis: front, edge, mirrored back, edge, front.
    # A bitmap projection preserves the approved artwork; no 3D mesh is implied.
    intro = []
    for index in range(40):
        phase = index * math.tau / 39
        facing = math.cos(phase)
        width = max(2, round(size * abs(facing)))
        frame = Image.new("RGBA", (size, size))
        surface = base if facing >= 0 else base.transpose(Image.Transpose.FLIP_LEFT_RIGHT)
        tilted = surface.resize((width, size), Image.Resampling.BICUBIC)
        frame.alpha_composite(tilted, ((size-width)//2, 0))
        frame = ImageEnhance.Brightness(frame).enhance(.75+.25*abs(facing))
        frame.info["nexus_stage"] = "turn"
        intro.append(frame)
    idle = []
    for index in range(60):
        frame = base.copy()
        frame.info["nexus_stage"] = "orbit"
        frame.info["orbit_angle"] = index * math.tau / 60
        idle.append(frame)
    return intro, idle


class LogoMark(ctk.CTkFrame):
    def __init__(self, master, size: int = 68, motion: bool = True, **kwargs) -> None:
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
        self._motion_enabled = bool(motion)
        self._photos = {}
        self._photo_size = None
        self._intro_i = 0
        self._idle_i = 0
        self._quantum = False
        self._quantum_time = 0.0
        self._quantum_last = None
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
            self.bind("<Unmap>", lambda _event: self._cancel(), add="+")
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
        from dvielle.gui.quantum import MASTER, render
        if MASTER.is_file():
            self._quantum = True
            self._intro = [render(self.size, 0)]
            self._idle = self._intro
            self._idle_ms = 50
            return
        try:
            nexus = build_nexus_frames(self.size)
        except (OSError, ValueError):
            nexus = None
        if nexus is not None:
            self._intro, self._idle = nexus
            self._using_text = False
            self._frame_ms = 80
            self._idle_ms = 80
            return
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
                self._show(self._intro[0] if self._motion_enabled else self._idle[0])
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
        if self._photo_size != px:
            self._photos.clear()
            self._photo_size = px
        if self._quantum:
            self._photos.clear()
        key = id(image)
        photo = self._photos.get(key)
        if photo is None:
            photo = ImageTk.PhotoImage(shown, master=self._canvas)
            self._photos[key] = photo
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
        self._paint_orbit(px)

    def _paint_orbit(self, px):
        """Lights follow the artwork's tilted oval after the D completes its turn."""
        self._canvas.delete("motion_orbit")
        if not self._motion_enabled or self._current is None or self._current.info.get("nexus_stage") != "orbit":
            return
        angle = self._current.info["orbit_angle"]
        tilt = math.radians(-22)
        for offset, color in ((0, "accent"), (math.pi, "orbit")):
            u = px*.46*math.cos(angle+offset)
            v = px*.12*math.sin(angle+offset)
            x = px*.50 + u*math.cos(tilt)-v*math.sin(tilt)
            y = px*.55 + u*math.sin(tilt)+v*math.cos(tilt)
            dot = max(2, px*.032)
            self._canvas.create_oval(x-dot, y-dot, x+dot, y+dot,
                                     fill=T.hex_color(color), outline="", tags="motion_orbit")

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
        if self._motion_enabled:
            self._schedule(1)

    def set_motion_enabled(self, enabled: bool) -> None:
        self._motion_enabled = bool(enabled)
        self._quantum_last = None
        self._cancel()
        if enabled:
            if self.winfo_viewable():
                self._schedule(1)
        elif self._idle and not self._quantum:
            self._show(self._idle[0])

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
        if not self._alive or not self._motion_enabled:
            return
        try:
            owner = self.winfo_toplevel()
            self._job_owner = owner
            self._job = owner.after(int(ms), self._tick)
        except Exception:
            self._job = None
            self._job_owner = None

    def _cancel(self) -> None:
        self._quantum_last = None
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
        self._quantum = False
        self._using_text = True
        self._intro = []
        self._idle = []
        self._current = None
        self._pulse_text()

    def _advance(self) -> None:
        if self._quantum:
            from dvielle.gui.quantum import render
            now = time.monotonic()
            if self._quantum_last is not None:
                self._quantum_time += now - self._quantum_last
            self._show(render(self._pixel_size(), self._quantum_time))
            self._idle_i += 1
            self._schedule(self._idle_ms)
            self._quantum_last = now
            return
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
        if not self._alive or not self._motion_enabled:
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
        self._photos.clear()
        T.unsubscribe(self._on_theme)
        super().destroy()

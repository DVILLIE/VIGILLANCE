"""Static console drawings. Pillow only — no timers and no motion.

Rings, icons, the status orb, and the network map redraw when a
measurement or the theme changes. They do not sweep, ease, or pulse.
"""

from __future__ import annotations

import math
from functools import lru_cache
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

from dvielle.gui import theme as T

RING_SIZE = (332, 158)
NAV_ICON = 26
GLYPH_SIZE = 36
ORB_SIZE = 32
MAP_SIZE = (1040, 88)

_FONT_PATHS = {
    False: (
        "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
        "/usr/share/fonts/truetype/liberation/LiberationSans-Regular.ttf",
        "C:/Windows/Fonts/segoeui.ttf",
    ),
    True: (
        "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
        "/usr/share/fonts/truetype/liberation/LiberationSans-Bold.ttf",
        "C:/Windows/Fonts/segoeuib.ttf",
    ),
}


def tone_name(percent: float | None) -> str:
    """Accent, warn, or crit for a 0–100 reading. Missing stays mute."""
    if percent is None:
        return "mute"
    if percent >= 90:
        return "crit"
    if percent >= 75:
        return "warn"
    return "accent"


def ring_pair(title: str, percent: float | None) -> tuple[Image.Image, Image.Image]:
    return _ring("light", title, percent), _ring("dark", title, percent)


def icon_pair(name: str, size: int = NAV_ICON) -> tuple[Image.Image, Image.Image]:
    return _icon(name, "light", size), _icon(name, "dark", size)


def glyph_pair(kind: str) -> tuple[Image.Image, Image.Image]:
    return _glyph(kind, "light"), _glyph(kind, "dark")


def orb_pair(tone: str) -> tuple[Image.Image, Image.Image]:
    return _orb(tone, "light"), _orb(tone, "dark")


def map_pair(nodes: list[tuple[str, str, str]]) -> tuple[Image.Image, Image.Image]:
    return _network("light", nodes), _network("dark", nodes)


def rule_pair(width: int = 1360) -> tuple[Image.Image, Image.Image]:
    return _rule("light", width), _rule("dark", width)


def dial_pair(percent: float | None, diameter: int = 52) -> tuple[Image.Image, Image.Image]:
    return _dial("light", percent, diameter), _dial("dark", percent, diameter)


def _book(mode: str) -> dict[str, str]:
    return T.LIGHT if mode == "light" else T.DARK


def _rgb(hex_color: str) -> tuple[int, int, int]:
    raw = hex_color.lstrip("#")
    return int(raw[0:2], 16), int(raw[2:4], 16), int(raw[4:6], 16)


def _rgba(hex_color: str, alpha: int = 255) -> tuple[int, int, int, int]:
    return _rgb(hex_color) + (alpha,)


@lru_cache(maxsize=16)
def _font(size: int, bold: bool) -> ImageFont.ImageFont:
    for path in _FONT_PATHS[bold]:
        if Path(path).exists():
            return ImageFont.truetype(path, size)
    return ImageFont.load_default()


def _vertical_gradient(size: tuple[int, int], top: str, bottom: str) -> Image.Image:
    width, height = size
    image = Image.new("RGBA", size)
    pixels = image.load()
    start, end = _rgb(top), _rgb(bottom)
    span = max(1, height - 1)
    for y in range(height):
        blend = y / span
        row = tuple(int(start[i] * (1 - blend) + end[i] * blend) for i in range(3)) + (255,)
        for x in range(width):
            pixels[x, y] = row
    return image


def _glass(mode: str, width: int, height: int, radius: int = 18) -> Image.Image:
    """Soft panel: vertical fade, corner glow, hairline, dot grid."""
    book = _book(mode)
    if mode == "dark":
        top, bottom = "#1A3348", book["panel"]
    else:
        top, bottom = "#FFFFFF", "#E5EEF3"
    gradient = _vertical_gradient((width, height), top, bottom)
    mask = Image.new("L", (width, height), 0)
    ImageDraw.Draw(mask).rounded_rectangle((0, 0, width - 1, height - 1), radius=radius, fill=255)
    panel = Image.new("RGBA", (width, height), (0, 0, 0, 0))
    panel.paste(gradient, (0, 0), mask)

    glow = Image.new("RGBA", (width, height), (0, 0, 0, 0))
    glow_draw = ImageDraw.Draw(glow)
    accent = _rgb(book["accent"])
    for step in range(36):
        alpha = int(22 * (1 - step / 36))
        glow_draw.ellipse((-30, -36, 70 - step, 64 - step), fill=accent + (alpha,))
    panel = Image.alpha_composite(panel, glow)

    draw = ImageDraw.Draw(panel)
    dot = _rgba(book["accent"], 55 if mode == "dark" else 40)
    for x in range(18, width - 10, 16):
        for y in range(18, height - 10, 16):
            draw.ellipse((x, y, x + 1, y + 1), fill=dot)
    draw.rounded_rectangle(
        (0, 0, width - 1, height - 1),
        radius=radius,
        outline=_rgba(book["border"]),
        width=1,
    )
    # Top edge catch-light, so the panel reads as glass rather than a flat fill.
    draw.arc((8, 1, width - 9, 22), 200, 340, fill=_rgba(book["accent_hot"], 90), width=1)
    return panel


def _dial(mode: str, percent: float | None, diameter: int) -> Image.Image:
    book = _book(mode)
    image = Image.new("RGBA", (diameter, diameter), (0, 0, 0, 0))
    draw = ImageDraw.Draw(image)
    pad = 6
    box = (pad, pad, diameter - pad - 1, diameter - pad - 1)
    center = diameter / 2
    radius = (diameter - pad * 2) / 2
    track = _rgba(book["border"])
    draw.arc(box, 0, 360, fill=track, width=5)
    for mark in range(12):
        angle = math.radians(mark * 30 - 90)
        inner = radius + 1
        outer = radius + 4
        draw.line(
            (
                center + inner * math.cos(angle),
                center + inner * math.sin(angle),
                center + outer * math.cos(angle),
                center + outer * math.sin(angle),
            ),
            fill=_rgba(book["mute"], 160),
            width=1,
        )
    tone = tone_name(percent)
    color = book["accent"] if tone == "accent" else book[tone]
    if percent is not None and percent > 0:
        extent = max(4.0, 360.0 * percent / 100.0)
        draw.arc(box, -90, -90 + extent, fill=_rgba(color, 80), width=9)
        draw.arc(box, -90, -90 + extent, fill=_rgba(color), width=5)
    return image


def _ring(mode: str, title: str, percent: float | None) -> Image.Image:
    width, height = RING_SIZE
    panel = _glass(mode, width, height)
    book = _book(mode)
    dial = _dial(mode, percent, 112)
    panel.alpha_composite(dial, (18, 24))
    draw = ImageDraw.Draw(panel)
    tone = tone_name(percent)
    color = book["mute"] if tone == "mute" else book[tone]
    number = "—" if percent is None else f"{percent:.0f}"
    draw.text((74, 78), number, font=_font(26, True), fill=_rgba(color), anchor="mm")
    draw.text((150, 52), title, font=_font(18, True), fill=_rgba(book["ink"]), anchor="lm")
    caption = "No reading yet" if percent is None else "In use"
    draw.text((150, 82), caption, font=_font(13, False), fill=_rgba(book["mute"]), anchor="lm")
    draw.rounded_rectangle((150, 108, 300, 114), radius=3, fill=_rgba(book["border"]))
    if percent is not None:
        fill_to = 150 + int(150 * percent / 100.0)
        draw.rounded_rectangle((150, 108, max(156, fill_to), 114), radius=3, fill=_rgba(color))
    return panel


def _icon(name: str, mode: str, size: int) -> Image.Image:
    book = _book(mode)
    image = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(image)
    ink = _rgba(book["accent"])
    hot = _rgba(book["accent_hot"])
    edge = size - 1
    if name == "now":
        draw.ellipse((3, 3, edge - 3, edge - 3), outline=ink, width=2)
        draw.arc((6, 6, edge - 6, edge - 6), 300, 40, fill=hot, width=2)
        mid = size // 2
        draw.ellipse((mid - 2, mid - 2, mid + 2, mid + 2), fill=ink)
    elif name == "pc":
        draw.rounded_rectangle((4, 5, edge - 4, edge - 6), radius=3, outline=ink, width=2)
        draw.line((7, edge - 8, edge - 7, edge - 8), fill=hot, width=2)
    elif name == "network":
        points = ((5, size // 2), (size // 2, 4), (edge - 5, size // 2), (size // 2, edge - 4))
        draw.line((*points, points[0]), fill=_rgba(book["mute"]), width=1)
        for point in points:
            draw.ellipse((point[0] - 2, point[1] - 2, point[0] + 2, point[1] + 2), fill=ink)
    elif name == "findings":
        for index, y in enumerate((7, 13, 19)):
            mark = ink if index == 0 else _rgba(book["mute"])
            draw.ellipse((4, y - 2, 8, y + 2), fill=mark)
            draw.line((11, y, edge - 4, y), fill=_rgba(book["ink"]), width=2)
    elif name == "protection":
        mid = size // 2
        draw.polygon(
            [(mid, 3), (edge - 4, 8), (edge - 6, 15), (mid, edge - 3), (6, 15), (4, 8)],
            outline=ink,
        )
        draw.line((mid, 9, mid, edge - 8), fill=hot, width=2)
    else:
        draw.rounded_rectangle((3, 7, edge - 8, edge - 3), radius=2, outline=ink, width=2)
        draw.rounded_rectangle((7, 3, edge - 3, edge - 8), radius=2, outline=hot, width=2)
    return image


def _glyph(kind: str, mode: str) -> Image.Image:
    book = _book(mode)
    token = {"noted": "accent", "caution": "warn", "look": "crit", "settled": "ok"}.get(kind, "accent")
    color = book[token]
    size = GLYPH_SIZE
    image = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(image)
    draw.ellipse((1, 1, size - 2, size - 2), fill=_rgba(color, 48), outline=_rgba(color), width=2)
    if kind == "settled":
        draw.line((10, 19, 16, 25, 26, 12), fill=_rgba(color), width=3)
    elif kind == "caution":
        draw.polygon([(18, 8), (29, 28), (7, 28)], outline=_rgba(color))
        draw.line((18, 15, 18, 22), fill=_rgba(color), width=2)
        draw.ellipse((17, 24, 19, 26), fill=_rgba(color))
    elif kind == "look":
        draw.ellipse((11, 11, 25, 25), outline=_rgba(color), width=2)
        draw.line((23, 23, 28, 28), fill=_rgba(color), width=2)
    else:
        draw.ellipse((16, 9, 20, 13), fill=_rgba(color))
        draw.line((18, 16, 18, 27), fill=_rgba(color), width=2)
    return image


def _orb(tone: str, mode: str) -> Image.Image:
    book = _book(mode)
    token = tone if tone in {"ok", "warn", "crit", "mute", "accent"} else "warn"
    color = book[token]
    size = ORB_SIZE
    image = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(image)
    draw.ellipse((0, 0, size - 1, size - 1), outline=_rgba(book["border"]), width=1)
    draw.ellipse((4, 4, size - 5, size - 5), outline=_rgba(color, 110), width=3)
    draw.ellipse((11, 11, size - 12, size - 12), fill=_rgba(color))
    mid = size // 2
    tick = _rgba(book["accent_hot"])
    draw.line((2, mid, 6, mid), fill=tick, width=1)
    draw.line((size - 7, mid, size - 3, mid), fill=tick, width=1)
    draw.line((mid, 2, mid, 6), fill=tick, width=1)
    draw.line((mid, size - 7, mid, size - 3), fill=tick, width=1)
    return image


def _network(mode: str, nodes: list[tuple[str, str, str]]) -> Image.Image:
    width, height = MAP_SIZE
    panel = _glass(mode, width, height, radius=16)
    book = _book(mode)
    draw = ImageDraw.Draw(panel)
    count = max(1, len(nodes))
    centers = [int(width * (index + 1) / (count + 1)) for index in range(count)]
    y = 46
    for left, right in zip(centers, centers[1:]):
        draw.line((left + 16, y, right - 16, y), fill=_rgba(book["accent"], 170), width=2)
    ink = _rgba(book["ink"])
    mute = _rgba(book["mute"])
    for center, node in zip(centers, nodes):
        title, detail, token = node
        color = book[token] if token in book else book["accent"]
        draw.ellipse((center - 12, y - 12, center + 12, y + 12), outline=_rgba(color), width=2)
        draw.ellipse((center - 4, y - 4, center + 4, y + 4), fill=_rgba(color))
        draw.text((center, 14), title[:16], font=_font(12, True), fill=ink, anchor="mm")
        draw.text((center, 72), detail[:22], font=_font(11, False), fill=mute, anchor="mm")
    return panel


def _rule(mode: str, width: int) -> Image.Image:
    book = _book(mode)
    image = Image.new("RGBA", (width, 3), (0, 0, 0, 0))
    draw = ImageDraw.Draw(image)
    accent = _rgb(book["accent"])
    for x in range(width):
        alpha = int(210 * (1 - x / max(1, width - 1)))
        draw.line((x, 0, x, 2), fill=accent + (alpha,))
    return image

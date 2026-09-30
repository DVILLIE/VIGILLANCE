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


_SLOTS = {"Processor": 0, "Memory": 1, "Disk": 2}


def ring_pair(title: str, percent: float | None) -> tuple[Image.Image, Image.Image]:
    slot = _SLOTS.get(title, 0)
    return _ring("light", title, percent, slot), _ring("dark", title, percent, slot)


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


def _mix(left: str, right: str, amount: float) -> str:
    a, b = _rgb(left), _rgb(right)
    mixed = tuple(int(a[i] * (1 - amount) + b[i] * amount) for i in range(3))
    return "#{:02X}{:02X}{:02X}".format(*mixed)


def _corner_orbits(draw: ImageDraw.ImageDraw, width: int, height: int, mode: str, slot: int) -> None:
    """Static orbits in the free corner. The angle comes from the day's seed."""
    book = _book(mode)
    motif = T.current_motif()
    phase = int(motif["phase"]) + slot * 47
    accent_alpha = 200 if mode == "dark" else 120
    orbit_alpha = 220 if mode == "dark" else 130
    accent = _rgba(book["accent"], accent_alpha)
    orbit = _rgba(book["orbit"], orbit_alpha)
    draw.arc((width - 78, -8, width + 10, 62), phase, phase + 130, fill=orbit, width=2)
    if slot % 2 == 0:
        draw.arc((width - 62, 4, width - 8, 50), phase + 24, phase + 100, fill=accent, width=2)
    else:
        draw.arc((width - 96, 6, width - 18, 68), phase + 12, phase + 90, fill=accent, width=1)
    ang = math.radians(phase)
    ex = width - 36 + 16 * math.cos(ang)
    ey = 22 + 8 * math.sin(ang)
    if 4 <= ex <= width - 4 and 4 <= ey <= height - 4:
        draw.ellipse((ex - 2.5, ey - 2.5, ex + 2.5, ey + 2.5), fill=orbit)
    if height >= 140 and slot % 3 == 1:
        base = height - 28
        for wave in range(int(motif["waves"])):
            y = base - wave * 4
            color = orbit if wave % 2 else accent
            draw.arc((8, y, width - 8, y + 22), 200, 340, fill=color, width=1)


def _glass(mode: str, width: int, height: int, radius: int = 18, slot: int = 0) -> Image.Image:
    """Soft panel tinted with the day's accent, plus a still orbit mark."""
    book = _book(mode)
    if mode == "dark":
        top = _mix(book["panel"], book["accent"], 0.38)
    else:
        top = _mix("#F4F7FA", book["accent"], 0.05)
    gradient = _vertical_gradient((width, height), top, book["panel"])
    mask = Image.new("L", (width, height), 0)
    ImageDraw.Draw(mask).rounded_rectangle((0, 0, width - 1, height - 1), radius=radius, fill=255)
    panel = Image.new("RGBA", (width, height), (0, 0, 0, 0))
    panel.paste(gradient, (0, 0), mask)
    draw = ImageDraw.Draw(panel)
    _corner_orbits(draw, width, height, mode, slot)
    draw.rounded_rectangle(
        (0, 0, width - 1, height - 1),
        radius=radius,
        outline=_rgba(book["border"]),
        width=1,
    )
    sheen = 120 if mode == "dark" else 70
    draw.arc((10, 1, width // 2, 18), 200, 340, fill=_rgba(book["accent"], sheen), width=1)
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
    phase = int(T.current_motif()["phase"])
    orbit_alpha = 230 if mode == "dark" else 140
    draw.ellipse(
        (pad + 1, pad + 9, diameter - pad - 3, diameter - pad - 11),
        outline=_rgba(book["orbit"], orbit_alpha),
        width=2,
    )
    ang = math.radians(phase)
    ex = center + (radius - 8) * math.cos(ang)
    ey = center + (radius - 12) * math.sin(ang)
    draw.ellipse((ex - 3, ey - 3, ex + 3, ey + 3), fill=_rgba(book["orbit"]))
    if percent is not None and percent > 0:
        extent = max(4.0, 360.0 * percent / 100.0)
        draw.arc(box, -90, -90 + extent, fill=_rgba(color, 80), width=9)
        draw.arc(box, -90, -90 + extent, fill=_rgba(color), width=5)
    return image


def _ring(mode: str, title: str, percent: float | None, slot: int) -> Image.Image:
    width, height = RING_SIZE
    panel = _glass(mode, width, height, slot=slot)
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
    hot = _rgba(book["orbit"])
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
    draw.ellipse((1, 7, size - 2, size - 8), outline=_rgba(book["orbit"], 230), width=2)
    draw.ellipse((11, 11, size - 12, size - 12), fill=_rgba(color))
    phase = int(T.current_motif()["phase"])
    mid = size / 2
    for extra in (0, 170):
        ang = math.radians(phase + extra)
        ex = mid + (mid - 5) * math.cos(ang)
        ey = mid + (mid - 10) * math.sin(ang)
        draw.ellipse((ex - 2, ey - 2, ex + 2, ey + 2), fill=_rgba(book["orbit"]))
    return image


def _network(mode: str, nodes: list[tuple[str, str, str]]) -> Image.Image:
    width, height = MAP_SIZE
    panel = _glass(mode, width, height, radius=16, slot=0)
    book = _book(mode)
    draw = ImageDraw.Draw(panel)
    count = max(1, len(nodes))
    centers = [int(width * (index + 1) / (count + 1)) for index in range(count)]
    y = 46
    for index, (left, right) in enumerate(zip(centers, centers[1:])):
        color = book["orbit"] if index % 2 else book["accent"]
        link_alpha = 220 if mode == "dark" else 140
        draw.arc((left, y - 16, right, y + 16), 206, 334, fill=_rgba(color, link_alpha), width=2)
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
    orbit = _rgb(book["orbit"])
    for x in range(width):
        color = accent if x < width * 0.62 else orbit
        alpha = (230 if x < width * 0.62 else 200) if mode == "dark" else 150
        draw.line((x, 0, x, 2), fill=color + (alpha,))
    return image

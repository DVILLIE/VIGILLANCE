"""Console colors for Dark and Light.

CustomTkinter selects ``(light, dark)`` tuple colors from the appearance
mode. Verified against CustomTkinter 6.0
``CTkAppearanceModeBaseClass._apply_appearance_mode`` (index 0 light,
index 1 dark) and the color docs:
https://customtkinter.tomschimansky.com/documentation/color/

``system`` mode is not used. On Linux, CustomTkinter documents that
system mode stays light:
https://github.com/TomSchimansky/CustomTkinter/wiki/AppearanceMode

Default is dark, the console that shipped before 2.4.0. Canvas widgets
cannot take tuples; they read ``hex_color`` and subscribe to ``apply``.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import date

# Cool paper for Light. Accents stay calm (sky, mint, lilac), never neon on white.
# Dark stays rich. The day's name still changes. See SPECTRA.
LIGHT: dict[str, str] = {
    "void": "#F4F7FA",
    "panel": "#FFFFFF",
    "panel_alt": "#E8EEF4",
    "border": "#D2DCE6",
    "accent": "#5C5280",
    "accent_dim": "#4C4570",
    "accent_hot": "#736A96",
    "orbit": "#3E756C",
    "ink": "#1A2733",
    "mute": "#526070",
    "ok": "#0C7040",
    "warn": "#8A5600",
    "crit": "#B4233A",
    "on_accent": "#F6F5FA",
    "on_crit": "#FFFFFF",
}

DARK: dict[str, str] = {
    "void": "#090712",
    "panel": "#14101C",
    "panel_alt": "#1C1728",
    "border": "#342C44",
    "accent": "#DDD6FE",
    "accent_dim": "#C4B5FD",
    "accent_hot": "#EDE9FE",
    "orbit": "#FDBA74",
    "ink": "#F6F1FB",
    "mute": "#B7A9C8",
    "ok": "#3DDC9A",
    "warn": "#E2A93B",
    "crit": "#FF5C74",
    "on_accent": "#1E1033",
    "on_crit": "#1A070C",
}

# Five readable pairs. The date picks one so the console is not the same hue every morning.
# ``orbit`` is the second drawn color. It is not used for body text.
SPECTRA: tuple[dict, ...] = (
    {
        "name": "Violet",
        "light": {"accent": "#5C5280", "accent_dim": "#4C4570", "accent_hot": "#736A96", "on_accent": "#F6F5FA", "orbit": "#3E756C"},
        "dark": {"accent": "#DDD6FE", "accent_dim": "#C4B5FD", "accent_hot": "#EDE9FE", "on_accent": "#1E1033", "orbit": "#FDBA74"},
    },
    {
        "name": "Coral",
        "light": {"accent": "#8A5A68", "accent_dim": "#735060", "accent_hot": "#A07886", "on_accent": "#FAF6F7", "orbit": "#4A6A86"},
        "dark": {"accent": "#FDBA74", "accent_dim": "#FB923C", "accent_hot": "#FFEDD5", "on_accent": "#2A1008", "orbit": "#93C5FD"},
    },
    {
        "name": "Gold",
        "light": {"accent": "#6E6244", "accent_dim": "#5C5238", "accent_hot": "#8A7C58", "on_accent": "#FAF8F3", "orbit": "#5E5A86"},
        "dark": {"accent": "#FDE047", "accent_dim": "#FACC15", "accent_hot": "#FEF9C3", "on_accent": "#1C1404", "orbit": "#D8B4FE"},
    },
    {
        "name": "Sky",
        "light": {"accent": "#3E5A74", "accent_dim": "#334C64", "accent_hot": "#5A7894", "on_accent": "#F4F7FA", "orbit": "#3E7568"},
        "dark": {"accent": "#BFDBFE", "accent_dim": "#93C5FD", "accent_hot": "#DBEAFE", "on_accent": "#0B1730", "orbit": "#FDA4AF"},
    },
    {
        "name": "Rose",
        "light": {"accent": "#86566A", "accent_dim": "#704858", "accent_hot": "#A0788C", "on_accent": "#FAF6F8", "orbit": "#5A7090"},
        "dark": {"accent": "#FBCFE8", "accent_dim": "#F9A8D4", "accent_hot": "#FCE7F3", "on_accent": "#2A0A18", "orbit": "#FBBF24"},
    },
)

DEFAULT_MODE = "dark"

FONT_DISPLAY = ("Segoe UI", 28, "bold")
FONT_TITLE = ("Segoe UI", 20, "bold")
FONT_BODY = ("Segoe UI", 15)
FONT_MONO = ("Consolas", 14)
FONT_TAGLINE = ("Segoe UI", 13)
FONT_ITALIC = ("Segoe UI", 14, "italic")
FONT_STATUS_DOT = ("Segoe UI", 16)

_mode = DEFAULT_MODE
_listeners: list[Callable[[str], None]] = []
_motif: dict = {"name": "Violet", "index": 0, "phase": 20, "waves": 3, "shift": 4}


def normalize_mode(mode: str) -> str:
    value = str(mode).strip().lower()
    if value not in {"dark", "light"}:
        raise ValueError(f"appearance must be dark or light, got {mode!r}")
    return value


def current_mode() -> str:
    return _mode


def current_motif() -> dict:
    """Day seed for static orbits. A copy, so callers cannot change the live seed."""
    return dict(_motif)


def install_spectrum(index: int) -> str:
    """Copy one spectrum into the live books and refresh tuple aliases."""
    spec = SPECTRA[index % len(SPECTRA)]
    LIGHT.update(spec["light"])
    DARK.update(spec["dark"])
    _motif["name"] = spec["name"]
    _motif["index"] = index % len(SPECTRA)
    _rebind()
    return spec["name"]


def install_day(when: date | None = None) -> dict:
    """Pick the day's colors and orbit angle from the local date. Nothing animates."""
    when = when or date.today()
    ordinal = when.toordinal()
    _motif["phase"] = (ordinal * 47) % 360
    _motif["waves"] = 2 + (ordinal % 3)
    _motif["shift"] = (ordinal * 13) % 20
    install_spectrum(ordinal % len(SPECTRA))
    return current_motif()


def pair(token: str) -> tuple[str, str]:
    """``(light, dark)`` for a CustomTkinter color argument."""
    return (LIGHT[token], DARK[token])


def hex_color(token: str) -> str:
    """Single hex for the active mode. Tk Canvas needs this."""
    book = LIGHT if _mode == "light" else DARK
    return book[token]


def subscribe(callback: Callable[[str], None]) -> Callable[[str], None]:
    _listeners.append(callback)
    return callback


def unsubscribe(callback: Callable[[str], None]) -> None:
    try:
        _listeners.remove(callback)
    except ValueError:
        pass


def apply(mode: str) -> str:
    """Switch the active palette and CustomTkinter appearance mode."""
    global _mode
    normalized = normalize_mode(mode)
    _mode = normalized
    try:
        import customtkinter as ctk

        ctk.set_appearance_mode(normalized)
    except Exception:
        pass
    for callback in list(_listeners):
        try:
            callback(normalized)
        except Exception:
            pass
    return _mode


def paint_selected_segment(tabview) -> None:
    """Give the selected tab readable text on the accent fill.

    CustomTkinter uses one text color for every segment. Selected and
    unselected fills differ, so the selected label is set to ``on_accent``
    and the others stay ``ink``. Missing private attributes are ignored.
    """
    segmented = getattr(tabview, "_segmented_button", None)
    buttons = getattr(segmented, "_buttons_dict", None) if segmented is not None else None
    if not isinstance(buttons, dict) or not buttons:
        return
    try:
        current = tabview.get()
    except Exception:
        return
    for name, button in buttons.items():
        button.configure(text_color=ON_ACCENT if name == current else TEXT)


def _rebind() -> None:
    """Refresh tuple aliases after a spectrum change. Widgets read these at build time."""
    global BG_DARK, BG_PANEL, BG_PANEL_ALT, BORDER
    global ACCENT, ACCENT_DIM, ACCENT_GLOW, TEXT, TEXT_DIM
    global SUCCESS, WARNING, DANGER, ON_ACCENT, ON_CRIT
    BG_DARK = pair("void")
    BG_PANEL = pair("panel")
    BG_PANEL_ALT = pair("panel_alt")
    BORDER = pair("border")
    ACCENT = pair("accent")
    ACCENT_DIM = pair("accent_dim")
    ACCENT_GLOW = pair("accent_hot")
    TEXT = pair("ink")
    TEXT_DIM = pair("mute")
    SUCCESS = pair("ok")
    WARNING = pair("warn")
    DANGER = pair("crit")
    ON_ACCENT = pair("on_accent")
    ON_CRIT = pair("on_crit")


# Tuple aliases. CustomTkinter widgets update these when the mode changes.
BG_DARK = pair("void")
BG_PANEL = pair("panel")
BG_PANEL_ALT = pair("panel_alt")
BORDER = pair("border")
ACCENT = pair("accent")
ACCENT_DIM = pair("accent_dim")
ACCENT_GLOW = pair("accent_hot")
TEXT = pair("ink")
TEXT_DIM = pair("mute")
SUCCESS = pair("ok")
WARNING = pair("warn")
DANGER = pair("crit")
ON_ACCENT = pair("on_accent")
ON_CRIT = pair("on_crit")

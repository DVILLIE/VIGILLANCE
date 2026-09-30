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

# Cool paper. Ink and status colors stay dark enough to read on white.
LIGHT: dict[str, str] = {
    "void": "#F3F6F8",
    "panel": "#FFFFFF",
    "panel_alt": "#E7EEF3",
    "border": "#D2DCE3",
    "accent": "#0C6B5C",
    "accent_dim": "#0A574B",
    "accent_hot": "#128674",
    "ink": "#132028",
    "mute": "#4A5C6A",
    "ok": "#0C7040",
    "warn": "#8A5600",
    "crit": "#B4233A",
    "on_accent": "#F4FFFB",
    "on_crit": "#FFFFFF",
}

# Phosphor void, calmed so status text is not a glow field.
DARK: dict[str, str] = {
    "void": "#070B12",
    "panel": "#0E1520",
    "panel_alt": "#15202C",
    "border": "#243244",
    "accent": "#3DE8C8",
    "accent_dim": "#1FAE96",
    "accent_hot": "#7DFFE8",
    "ink": "#E7F2F0",
    "mute": "#8FA3B0",
    "ok": "#3DDC9A",
    "warn": "#E2A93B",
    "crit": "#FF5C74",
    "on_accent": "#07140F",
    "on_crit": "#1A070C",
}

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


def normalize_mode(mode: str) -> str:
    value = str(mode).strip().lower()
    if value not in {"dark", "light"}:
        raise ValueError(f"appearance must be dark or light, got {mode!r}")
    return value


def current_mode() -> str:
    return _mode


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

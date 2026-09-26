"""System tray integration — minimize/maximize DVielle from taskbar / notification area."""

from __future__ import annotations

import threading
from typing import Callable

from dvielle import APP_NAME, TAGLINE
from dvielle.brand import load_brand_pil_image

_tray_icon = None


def _create_icon_image():
    """Same brand mark as the window/taskbar (.ico), not a separate PNG glyph."""
    img = load_brand_pil_image(64)
    if img is not None:
        return img
    try:
        from PIL import Image, ImageDraw

        size = 64
        fallback = Image.new("RGBA", (size, size), (5, 8, 16, 255))
        draw = ImageDraw.Draw(fallback)
        draw.ellipse([4, 4, size - 4, size - 4], outline=(0, 229, 255, 255), width=3)
        draw.ellipse([18, 18, size - 18, size - 18], fill=(0, 229, 255, 80))
        draw.text((20, 22), "DV", fill=(0, 255, 247, 255))
        return fallback
    except ImportError:
        return None


def setup_tray(
    on_show: Callable[[], None],
    on_hide: Callable[[], None],
    on_quit: Callable[[], None],
    on_toggle_vigilance: Callable[[], None] | None = None,
) -> bool:
    global _tray_icon
    try:
        import pystray
    except ImportError:
        return False

    image = _create_icon_image()
    if image is None:
        return False

    def _show(icon, item):
        on_show()

    def _hide(icon, item):
        on_hide()

    def _quit(icon, item):
        icon.stop()
        on_quit()

    def _toggle(icon, item):
        if on_toggle_vigilance:
            on_toggle_vigilance()

    menu_items = [
        pystray.MenuItem(f"Open {APP_NAME}", _show, default=True),
        pystray.MenuItem("Minimize to tray", _hide),
    ]
    if on_toggle_vigilance:
        menu_items.append(pystray.MenuItem("Toggle vigilance", _toggle))
    menu_items.append(pystray.MenuItem("Exit", _quit))

    menu = pystray.Menu(*menu_items)
    _tray_icon = pystray.Icon(
        APP_NAME.lower(),
        image,
        f"{APP_NAME} — {TAGLINE}",
        menu,
    )

    thread = threading.Thread(target=_tray_icon.run, daemon=True)
    thread.start()
    return True


def notify_tray(title: str, message: str) -> None:
    if _tray_icon:
        try:
            _tray_icon.notify(message, title)
        except Exception:
            pass

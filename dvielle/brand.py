"""Brand asset paths + one standard Windows icon for window / taskbar / tray."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

# Repo root assets/brand/...  (this file lives at dvielle/brand.py)
BRAND_DIR = Path(__file__).resolve().parents[1] / "assets" / "brand"
LOGO_PNG = BRAND_DIR / "dvielle_logo.png"
LOGO_88_PNG = BRAND_DIR / "dvielle_88.png"
LOGO_64_PNG = BRAND_DIR / "dvielle_64.png"
LOGO_128_PNG = BRAND_DIR / "dvielle_128.png"
LOGO_STILL_PNG = BRAND_DIR / "dvielle-logo-still.png"
LOGO_ANIMATED_GIF = BRAND_DIR / "dvielle-logo-animated.gif"
ICON_ICO = BRAND_DIR / "dvielle.ico"

# Stable Windows identity so the taskbar does not inherit the Python interpreter icon.
APP_USER_MODEL_ID = "DVILLIE.VIGILLANCE.MissionConsole.1.5"


def brand_png(preferred: int = 88) -> Path:
    """Return best available PNG for UI branding (in-window logos)."""
    candidates = {
        64: LOGO_64_PNG,
        88: LOGO_88_PNG,
        128: LOGO_128_PNG,
    }
    path = candidates.get(preferred, LOGO_88_PNG)
    if path.exists():
        return path
    if LOGO_STILL_PNG.exists():
        return LOGO_STILL_PNG
    if LOGO_PNG.exists():
        return LOGO_PNG
    return path


def configure_windows_app_identity() -> None:
    """Tell Windows this process is DVielle — required for a stable taskbar icon.

    Must run before any Tk / CustomTkinter window is created. Without an explicit
    AppUserModelID, Windows groups the app under python.exe and shows that icon
    when minimized / on the taskbar.
    """
    if sys.platform != "win32":
        return
    try:
        import ctypes

        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(APP_USER_MODEL_ID)
    except Exception:
        pass


def load_brand_pil_image(size: int = 64):
    """Load the canonical brand mark as a PIL image (prefer multi-size ICO)."""
    try:
        from PIL import Image
    except ImportError:
        return None

    if ICON_ICO.exists():
        try:
            with Image.open(ICON_ICO) as ico:
                best = None
                for i in range(getattr(ico, "n_frames", 1)):
                    ico.seek(i)
                    frame = ico.copy().convert("RGBA")
                    if best is None or frame.size[0] > best.size[0]:
                        best = frame
                if best is not None:
                    if best.size != (size, size):
                        best = best.resize((size, size), Image.Resampling.LANCZOS)
                    return best
        except Exception:
            pass

    for path in (LOGO_STILL_PNG, LOGO_64_PNG, LOGO_128_PNG, brand_png(64), LOGO_PNG):
        if path.exists():
            try:
                img = Image.open(path).convert("RGBA")
                if img.size != (size, size):
                    img = img.resize((size, size), Image.Resampling.LANCZOS)
                return img
            except Exception:
                continue
    return None


def load_brand_gif_frames(size: int) -> list | None:
    """Load animated logo GIF frames scaled to ``size``. None if missing/unreadable."""
    try:
        from PIL import Image
    except ImportError:
        return None
    if not LOGO_ANIMATED_GIF.exists():
        return None
    try:
        frames: list = []
        with Image.open(LOGO_ANIMATED_GIF) as im:
            n = int(getattr(im, "n_frames", 1) or 1)
            duration = int(im.info.get("duration", 70) or 70)
            for i in range(n):
                im.seek(i)
                frame = im.convert("RGBA")
                if frame.size != (size, size):
                    frame = frame.resize((size, size), Image.Resampling.LANCZOS)
                frames.append(frame.copy())
        if not frames:
            return None
        # Attach per-load metadata for the GUI scheduler.
        for frame in frames:
            frame.info["dvielle_duration_ms"] = max(40, min(120, duration))
        return frames
    except Exception:
        return None


def apply_tk_window_icon(window: Any) -> None:
    """Apply the same standard DVielle icon to a Tk / CTk window (title bar + taskbar).

    Uses both ``iconbitmap`` (.ico) and ``iconphoto`` (PNG/PhotoImage). Keeps a
    strong reference on the window so Tk does not garbage-collect the image.
    """
    try:
        if ICON_ICO.exists():
            path = str(ICON_ICO.resolve())
            try:
                window.iconbitmap(default=path)
            except Exception:
                pass
            try:
                window.iconbitmap(path)
            except Exception:
                pass
    except Exception:
        pass

    try:
        from PIL import Image, ImageTk

        img = load_brand_pil_image(64)
        if img is None and ICON_ICO.exists():
            img = Image.open(ICON_ICO).convert("RGBA").resize((64, 64), Image.Resampling.LANCZOS)
        if img is None:
            return
        photo = ImageTk.PhotoImage(img)
        refs = getattr(window, "_dvielle_icon_refs", None)
        if refs is None:
            refs = []
            setattr(window, "_dvielle_icon_refs", refs)
        refs.append(photo)
        window.iconphoto(True, photo)
    except Exception:
        pass

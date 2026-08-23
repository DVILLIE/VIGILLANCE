"""Brand asset paths for DVielle logo / icons."""

from __future__ import annotations

from pathlib import Path

# C:\DVILLIE\assets\brand\...  (this file lives at dvielle/brand.py)
BRAND_DIR = Path(__file__).resolve().parents[1] / "assets" / "brand"
LOGO_PNG = BRAND_DIR / "dvielle_logo.png"
LOGO_88_PNG = BRAND_DIR / "dvielle_88.png"
LOGO_64_PNG = BRAND_DIR / "dvielle_64.png"
LOGO_128_PNG = BRAND_DIR / "dvielle_128.png"
ICON_ICO = BRAND_DIR / "dvielle.ico"


def brand_png(preferred: int = 88) -> Path:
    """Return best available PNG for UI branding."""
    candidates = {
        64: LOGO_64_PNG,
        88: LOGO_88_PNG,
        128: LOGO_128_PNG,
    }
    path = candidates.get(preferred, LOGO_88_PNG)
    if path.exists():
        return path
    if LOGO_PNG.exists():
        return LOGO_PNG
    return path

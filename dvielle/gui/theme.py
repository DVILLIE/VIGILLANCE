"""Phosphor Void theme — VIGILLANCE Mission Console (see docs/DESIGN.md)."""

# Core palette
BG_DARK = "#070B12"       # void
BG_PANEL = "#0C121C"      # panel
BG_PANEL_ALT = "#111925"  # panel-2
BORDER = "#1E2A3A"        # stroke
ACCENT = "#3DE8C8"        # phosphor
ACCENT_DIM = "#1FAE96"    # phosphor-dim
ACCENT_GLOW = "#7DFFE8"   # phosphor-hot
TEXT = "#E7F2F0"          # ink
TEXT_DIM = "#7A8B99"      # ink-mute
SUCCESS = "#3DFFB0"       # ok
WARNING = "#F0B429"       # warn
DANGER = "#FF4D6A"        # crit

# Font scale — glasses-friendly / mission console
FONT_DISPLAY = ("Segoe UI", 40, "bold")
FONT_TITLE = ("Segoe UI", 20, "bold")
FONT_BODY = ("Segoe UI", 15)
FONT_MONO = ("Consolas", 14)
FONT_TAGLINE = ("Segoe UI", 13)
FONT_ITALIC = ("Segoe UI", 14, "italic")
FONT_STATUS_DOT = ("Segoe UI", 28)

CTK_THEME = {
    "CTk": {"fg_color": BG_DARK},
    "CTkFrame": {"fg_color": BG_PANEL, "border_color": BORDER, "border_width": 1},
    "CTkLabel": {"text_color": TEXT, "font": FONT_BODY},
    "CTkButton": {
        "fg_color": BORDER,
        "hover_color": ACCENT_DIM,
        "text_color": TEXT,
        "border_color": ACCENT,
        "border_width": 1,
        "font": FONT_BODY,
        "height": 40,
    },
    "CTkProgressBar": {
        "progress_color": ACCENT,
        "fg_color": BG_PANEL_ALT,
        "border_color": BORDER,
    },
}

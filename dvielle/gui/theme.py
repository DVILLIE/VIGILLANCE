"""Jarvis-inspired futuristic theme for DVielle — larger readable type."""

# Core palette — holographic cyan on deep space black
BG_DARK = "#050810"
BG_PANEL = "#0a1220"
BG_PANEL_ALT = "#0d1a2d"
BORDER = "#1a3a5c"
ACCENT = "#00e5ff"
ACCENT_DIM = "#0099b3"
ACCENT_GLOW = "#00fff7"
TEXT = "#e0f7ff"
TEXT_DIM = "#6b8fa3"
SUCCESS = "#00ff9d"
WARNING = "#ffb020"
DANGER = "#ff3366"

# Font scale — tuned for readability (glasses-friendly)
FONT_DISPLAY = ("Segoe UI", 34, "bold")
FONT_TITLE = ("Segoe UI", 18, "bold")
FONT_BODY = ("Segoe UI", 15)
FONT_MONO = ("Consolas", 14)
FONT_TAGLINE = ("Segoe UI", 13)
FONT_ITALIC = ("Segoe UI", 13, "italic")
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
        "height": 36,
    },
    "CTkProgressBar": {
        "progress_color": ACCENT,
        "fg_color": BG_PANEL_ALT,
        "border_color": BORDER,
    },
}

"""Theme persistence, contrast, and logo-only motion."""

from __future__ import annotations

import inspect
import json
from pathlib import Path

import pytest

from dvielle.gui import theme as T
from dvielle.gui.logo_mark import motion_plan
from dvielle.gui.theme import paint_selected_segment
from dvielle.gui.theme_store import load_appearance, preference_path, save_appearance

ROOT = Path(__file__).resolve().parents[1]


def _luminance(hex_color: str) -> float:
    raw = hex_color.lstrip("#")
    red, green, blue = int(raw[0:2], 16), int(raw[2:4], 16), int(raw[4:6], 16)

    def channel(value: int) -> float:
        scaled = value / 255
        if scaled <= 0.04045:
            return scaled / 12.92
        return ((scaled + 0.055) / 1.055) ** 2.4

    return 0.2126 * channel(red) + 0.7152 * channel(green) + 0.0722 * channel(blue)


def _contrast(left: str, right: str) -> float:
    lighter = max(_luminance(left), _luminance(right))
    darker = min(_luminance(left), _luminance(right))
    return (lighter + 0.05) / (darker + 0.05)


@pytest.fixture(autouse=True)
def _restore_dark_mode():
    T.apply("dark")
    yield
    T.apply("dark")


def test_missing_preference_stays_dark(tmp_path: Path) -> None:
    assert load_appearance(tmp_path) == "dark"
    assert not preference_path(tmp_path).exists()


def test_theme_choice_persists_in_the_data_directory(tmp_path: Path) -> None:
    path = save_appearance(tmp_path, "light")
    assert path == tmp_path / "console_ui.json"
    assert json.loads(path.read_text(encoding="utf-8")) == {"appearance": "light"}
    assert load_appearance(tmp_path) == "light"
    save_appearance(tmp_path, "DARK")
    assert load_appearance(tmp_path) == "dark"


def test_broken_preference_falls_back_to_dark(tmp_path: Path) -> None:
    path = preference_path(tmp_path)
    path.write_text("{", encoding="utf-8")
    assert load_appearance(tmp_path) == "dark"
    path.write_text('{"appearance": "neon"}', encoding="utf-8")
    assert load_appearance(tmp_path) == "dark"
    path.write_text("[]", encoding="utf-8")
    assert load_appearance(tmp_path) == "dark"
    with pytest.raises(ValueError):
        save_appearance(tmp_path, "neon")


def test_tuple_order_is_light_then_dark_and_apply_switches_canvas_hex() -> None:
    assert T.pair("void") == (T.LIGHT["void"], T.DARK["void"])
    assert T.LIGHT["void"] != T.DARK["void"]
    T.apply("light")
    assert T.current_mode() == "light"
    assert T.hex_color("void") == T.LIGHT["void"]
    seen: list[str] = []
    T.subscribe(seen.append)
    try:
        T.apply("dark")
        assert seen == ["dark"]
        assert T.hex_color("ink") == T.DARK["ink"]
    finally:
        T.unsubscribe(seen.append)


@pytest.mark.parametrize("book", [T.LIGHT, T.DARK])
def test_body_and_status_colors_stay_readable(book: dict[str, str]) -> None:
    assert _contrast(book["ink"], book["void"]) >= 7
    assert _contrast(book["ink"], book["panel"]) >= 7
    assert _contrast(book["accent"], book["panel"]) >= 4.5
    assert _contrast(book["mute"], book["void"]) >= 4.5
    assert _contrast(book["on_accent"], book["accent"]) >= 4.5
    assert _contrast(book["on_accent"], book["accent_dim"]) >= 4.5
    assert _contrast(book["on_crit"], book["crit"]) >= 4.5
    assert book["ok"] != book["warn"] != book["crit"]


def test_selected_tab_label_uses_on_accent() -> None:
    class _Button:
        def __init__(self) -> None:
            self.text_color = None

        def configure(self, **kwargs) -> None:
            self.text_color = kwargs.get("text_color")

    live, old = _Button(), _Button()

    class _Tabs:
        _segmented_button = type("Seg", (), {"_buttons_dict": {"Live": live, "Old": old}})()

        def get(self) -> str:
            return "Live"

    paint_selected_segment(_Tabs())
    assert live.text_color == T.ON_ACCENT
    assert old.text_color == T.TEXT
    paint_selected_segment(object())


def test_only_the_logo_animates() -> None:
    plan = motion_plan()
    assert plan["animates"] == "logo"
    assert plan["intro_angles"][0] != 0
    assert plan["intro_angles"][-1] == 0
    assert plan["intro_frames"] <= 8
    assert plan["intro_ms"] >= 50
    assert plan["idle_ms"] >= 1000

    from dvielle.gui.presence import ClockMono, LivingRadar, PressureGauge, ScanFeed

    for cls in (LivingRadar, PressureGauge, ScanFeed):
        assert "self.after" not in inspect.getsource(cls)
    assert "self.after" in inspect.getsource(ClockMono)

    presence = (ROOT / "dvielle" / "gui" / "presence.py").read_text(encoding="utf-8")
    app = (ROOT / "dvielle" / "gui" / "app.py").read_text(encoding="utf-8")
    assert "_animate_scan" not in presence
    assert "def _ease" not in presence
    assert "_pulse_status" not in app
    assert "LogoMark" in app
    assert "_show_page" in app
    assert "columnconfigure(3" not in app
    for label in ("Now", "This PC", "Network", "Findings", "Protection", "Apps"):
        assert label in app

    from dvielle.gui.shell import CARD_HEIGHT, line_status

    assert CARD_HEIGHT <= 64
    assert line_status("[WARN] One check is only partial.")[0] == "Caution"
    assert line_status("[sample] Layout preview.")[0] == "Noted"
    assert line_status("CRITICAL hold")[0] == "Needs a look"
    assert line_status("RESOLVED item")[0] == "Settled"

"""Header emblem motion. Brand GIF preferred; drawn fallback kept. Watch/hologram stay gone."""

from __future__ import annotations

import time
from pathlib import Path

import pytest

from dvielle.gui import theme as T
from dvielle.gui.logo_mark import IDLE_GAINS, build_frames, motion_plan

ROOT = Path(__file__).resolve().parents[1]
BRAND = ROOT / "assets" / "brand"


def _changed_pixels(left, right) -> int:
    count = 0
    for a, b in zip(left.getdata(), right.getdata()):
        if any(a[i] != b[i] for i in range(min(len(a), len(b), 4))):
            count += 1
    return count


def test_brand_assets_present() -> None:
    assert (BRAND / "dvielle.ico").is_file()
    assert (BRAND / "dvielle-logo-still.png").is_file()
    assert (BRAND / "dvielle-logo-animated.gif").is_file()
    assert (BRAND / "dvielle.ico").stat().st_size > 10_000
    assert (BRAND / "dvielle-logo-animated.gif").stat().st_size > 100_000
    docs = ROOT / "docs" / "images"
    assert (docs / "dvielle-logo.png").is_file()
    assert (docs / "github-social-preview.png").is_file()


def test_motion_plan_waits_until_the_mark_is_visible() -> None:
    plan = motion_plan()
    assert plan["animates"] == "logo"
    assert plan["starts_when"] == "viewable"
    assert plan["intro_angles"][0] != 0
    assert plan["intro_angles"][-1] == 0
    assert plan["idle_ms"] >= 1000
    assert plan["hidden_ms"] >= 50
    assert IDLE_GAINS[0] == 1.0
    assert IDLE_GAINS[1] > 1.05
    assert plan["source"] == "brand_gif_or_drawn"


def test_intro_turns_and_idle_pulse_changes_pixels() -> None:
    intro, idle = build_frames(56)
    assert len(intro) == motion_plan()["intro_frames"]
    assert len(idle) == 2
    assert intro[0].size == (56, 56)
    assert _changed_pixels(intro[0], intro[-1]) > 400
    assert _changed_pixels(idle[0], idle[1]) > 400
    assert intro[0].getextrema()[3][1] > 200
    assert idle[1].getextrema()[3][1] > 200
    mint = 0
    for pixel in idle[0].getdata():
        if pixel[1] > pixel[0] + 20 and pixel[1] > 140 and pixel[3] > 180:
            mint += 1
    assert mint > 20


def test_brand_gif_builds_intro_and_idle() -> None:
    from dvielle.gui.logo_mark import build_brand_gif_frames

    pair = build_brand_gif_frames(56)
    assert pair is not None
    intro, idle = pair
    assert len(intro) >= 2
    assert len(idle) >= 2
    assert intro[0].size == (56, 56)
    assert _changed_pixels(intro[0], idle[min(5, len(idle) - 1)]) > 50


def test_logo_module_does_not_use_the_removed_radar() -> None:
    source = (ROOT / "dvielle" / "gui" / "logo_mark.py").read_text(encoding="utf-8")
    assert "hologram" not in source
    assert "LivingRadar" not in source
    assert not (ROOT / "dvielle" / "gui" / "hologram.py").exists()


def test_readme_and_docs_use_dvielle_spelling_and_logo() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "docs/images/dvielle-logo.png" in readme
    assert "DVielle" in readme
    # Forbidden product misspellings as UI/docs text (GIF baked wordmark is not markdown).
    assert "diville" not in readme.lower().replace("dvielle", "")
    ug = (ROOT / "docs" / "USER_GUIDE.md").read_text(encoding="utf-8")
    assert "images/dvielle-logo.png" in ug


def _pump(root, seconds: float) -> None:
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        root.update()
        time.sleep(0.01)


@pytest.fixture
def emblem_root():
    try:
        import customtkinter as ctk
    except Exception as exc:
        pytest.skip(f"customtkinter unavailable: {exc}")
    try:
        root = ctk.CTk()
    except Exception as exc:
        pytest.skip(f"Tk display unavailable: {exc}")
    root.withdraw()
    root.geometry("240x180+40+40")
    try:
        root.update()
    except Exception as exc:
        root.destroy()
        pytest.skip(f"Tk display unavailable: {exc}")
    yield root
    try:
        root.destroy()
    except Exception:
        pass


def test_intro_waits_for_a_visible_window_then_plays(monkeypatch, emblem_root) -> None:
    import dvielle.gui.logo_mark as logo_mark

    monkeypatch.setattr(logo_mark, "INTRO_MS", 20)
    monkeypatch.setattr(logo_mark, "IDLE_MS", 30)
    monkeypatch.setattr(logo_mark, "HIDDEN_MS", 10)
    monkeypatch.setattr(logo_mark, "GIF_FRAME_MS", 20)

    mark = logo_mark.LogoMark(emblem_root, size=56)
    mark.pack()
    emblem_root.update()
    assert not mark.winfo_viewable()
    hidden = mark._current.tobytes()
    _pump(emblem_root, 0.28)
    assert mark._intro_i == 0
    assert mark._current.tobytes() == hidden

    emblem_root.deiconify()
    emblem_root.lift()
    emblem_root.update()
    assert mark.winfo_viewable()
    _pump(emblem_root, 0.45)
    assert mark._intro_i >= 3
    assert mark._current.tobytes() != hidden
    assert mark._photo is not None
    mark._set_scaling(1.5, 1.5)
    emblem_root.update()
    assert int(float(mark._canvas.cget("width"))) == round(56 * 1.5)
    assert mark._photo.width() == round(56 * 1.5)
    mark._set_scaling(1.0, 1.0)


def test_dark_and_light_keep_the_emblem(monkeypatch, emblem_root) -> None:
    import dvielle.gui.logo_mark as logo_mark

    monkeypatch.setattr(logo_mark, "INTRO_MS", 20)
    monkeypatch.setattr(logo_mark, "HIDDEN_MS", 10)
    monkeypatch.setattr(logo_mark, "GIF_FRAME_MS", 20)
    mark = logo_mark.LogoMark(emblem_root, size=56)
    mark.pack()
    emblem_root.deiconify()
    emblem_root.update()
    _pump(emblem_root, 0.08)

    T.apply("light")
    emblem_root.update()
    light_bg = str(mark._canvas.cget("bg")).lower()
    assert mark._current is not None
    assert mark._photo is not None

    T.apply("dark")
    emblem_root.update()
    dark_bg = str(mark._canvas.cget("bg")).lower()
    assert mark._current is not None
    assert light_bg != dark_bg
    mark.destroy()
    emblem_root.update()


def test_missing_image_falls_back_to_letters(monkeypatch, emblem_root) -> None:
    import dvielle.gui.logo_mark as logo_mark

    def _boom(_size: int):
        raise OSError("brand image missing")

    monkeypatch.setattr(logo_mark, "build_brand_gif_frames", lambda _size: None)
    monkeypatch.setattr(logo_mark, "build_frames", _boom)
    monkeypatch.setattr(logo_mark, "IDLE_MS", 20)
    monkeypatch.setattr(logo_mark, "HIDDEN_MS", 10)
    mark = logo_mark.LogoMark(emblem_root, size=56)
    mark.pack()
    emblem_root.deiconify()
    emblem_root.update()
    assert mark._using_text
    assert mark._text_item is not None
    text = mark._canvas.itemcget(mark._text_item, "text")
    assert text == "DV"
    _pump(emblem_root, 0.12)
    assert mark._idle_i >= 1
    mark.destroy()

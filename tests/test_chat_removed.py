"""Chat assistant stays removed. Console voice stays."""

from __future__ import annotations

import importlib
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def test_chat_package_and_window_stay_gone() -> None:
    with pytest.raises(ModuleNotFoundError):
        importlib.import_module("agent.chat")
    with pytest.raises(ModuleNotFoundError):
        importlib.import_module("dvielle.gui.chat_window")
    assert not (ROOT / "dvielle" / "gui" / "chat_window.py").exists()
    assert not (ROOT / "agent" / "chat").exists()


def test_console_and_config_have_no_chat_surface() -> None:
    app = (ROOT / "dvielle" / "gui" / "app.py").read_text(encoding="utf-8")
    assert "chat_window" not in app
    assert "agent.chat" not in app
    config = (ROOT / "config" / "config.yaml").read_text(encoding="utf-8")
    assert "\nchat:" not in config
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    lowered = pyproject.lower()
    assert "duckduckgo" not in lowered
    assert "speechrecognition" not in lowered
    assert "pyttsx3" in pyproject


def test_console_voice_toasts_stay() -> None:
    voice = importlib.import_module("dvielle.gui.voice")
    assert callable(voice.speak_async)
    assert callable(voice.greet_on_startup)
    text = (ROOT / "dvielle" / "gui" / "voice.py").read_text(encoding="utf-8")
    assert "pyttsx3" in text
    assert "speak_async" in (ROOT / "dvielle" / "gui" / "app.py").read_text(encoding="utf-8")

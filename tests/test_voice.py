"""Tests for Jarvis voice module."""

from unittest.mock import MagicMock, patch

from dvielle.gui import voice


def test_random_greeting_returns_string() -> None:
    text = voice.random_greeting()
    assert isinstance(text, str)
    assert len(text) > 10


def test_speak_async_queues_on_windows(monkeypatch) -> None:
    monkeypatch.setattr(voice, "_ON_WINDOWS", True)
    voice._worker_started = False
    voice._speech_queue = None

    with patch.object(voice, "_ensure_worker") as mock_ensure:
        mock_q = MagicMock()
        voice._speech_queue = mock_q
        voice.speak_async("Hello operator", persona="kt")
        mock_ensure.assert_called_once()
        mock_q.put.assert_called_once_with(("Hello operator", "kt"))


def test_greet_on_startup_returns_and_speaks(monkeypatch) -> None:
    spoken: list[str] = []
    monkeypatch.setattr(voice, "speak_async", lambda t, persona="jarvis": spoken.append(t))
    text = voice.greet_on_startup()
    assert text in voice.GREETINGS
    assert spoken == [text]

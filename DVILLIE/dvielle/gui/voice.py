"""Jarvis-style voice greetings — optional TTS on Windows."""

from __future__ import annotations

import logging
import random
import threading

from dvielle import APP_NAME, TAGLINE

logger = logging.getLogger("dvielle.voice")

GREETINGS = [
    f"Good to see you. {APP_NAME} online. {TAGLINE} active.",
    "All systems nominal. Your machine is under deep vigilance.",
    "At your service. Monitoring network, memory, and privacy channels.",
    "Vigilance protocols engaged. I will alert you to any threat.",
    "Welcome back. I have been watching over your system.",
    "Deep vigilance mode active. Your internet belongs to you alone.",
    "Scanning complete. No immediate threats detected.",
    "I am DVielle. Every connection, every process — under my watch.",
]

_ON_WINDOWS = False
_engine = None

try:
    import platform
    if platform.system() == "Windows":
        _ON_WINDOWS = True
except Exception:
    pass


def _get_engine():
    global _engine
    if _engine is not None:
        return _engine
    if not _ON_WINDOWS:
        return None
    try:
        import pyttsx3
        _engine = pyttsx3.init()
        _engine.setProperty("rate", 165)
        voices = _engine.getProperty("voices")
        for v in voices:
            if "david" in v.name.lower() or "male" in v.name.lower():
                _engine.setProperty("voice", v.id)
                break
        return _engine
    except Exception as exc:
        logger.debug("TTS unavailable: %s", exc)
        return None


def speak_async(text: str) -> None:
    """Speak in background thread — never blocks GUI."""
    def _run() -> None:
        engine = _get_engine()
        if engine:
            try:
                engine.say(text)
                engine.runAndWait()
            except Exception as exc:
                logger.debug("TTS failed: %s", exc)
        else:
            logger.info("[DVIELLE speaks] %s", text)

    threading.Thread(target=_run, daemon=True, name="DVielle-TTS").start()


def random_greeting() -> str:
    return random.choice(GREETINGS)


def greet_on_startup() -> str:
    text = random_greeting()
    speak_async(text)
    return text

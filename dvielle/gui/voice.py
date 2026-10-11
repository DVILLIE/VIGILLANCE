"""Jarvis-style voice — persona-specific US/UK TTS."""

from __future__ import annotations

import logging
import sys
import queue
import random
import threading
from typing import Literal

from dvielle import APP_NAME, TAGLINE

logger = logging.getLogger("dvielle.voice")

PersonaId = Literal["jarvis", "kt"]

GREETINGS = [
    f"{APP_NAME} console is open. Checking the monitoring agent's current status.",
    "Welcome back. The console will show observations as they arrive.",
]

_ON_WINDOWS = sys.platform == "win32"
_speech_queue: queue.Queue[tuple[str, PersonaId] | None] | None = None
_worker_started = False
_worker_lock = threading.Lock()

# Windows SAPI language codes
_LANG_US = 1033
_LANG_GB = 2057

_PERSONA_NAME_HINTS: dict[PersonaId, tuple[str, ...]] = {
    "jarvis": ("david", "mark", "guy", "james", "richard"),
    "kt": ("hazel", "sonia", "susan", "zira", "linda", "heera"),
}


def _voice_matches_persona(desc: str, persona: PersonaId) -> bool:
    name = desc.lower()
    hints = _PERSONA_NAME_HINTS.get(persona, ())
    if persona == "jarvis":
        return any(h in name for h in hints) or ("english" in name and "united states" in name)
    return any(h in name for h in hints) or ("english" in name and "great britain" in name)


def _pick_sapi_voice(speaker, persona: PersonaId) -> None:
    want_lang = _LANG_US if persona == "jarvis" else _LANG_GB
    best = None
    fallback = None
    for voice in speaker.GetVoices():
        try:
            languages = str(voice.GetAttribute("Language")).split(";")
            lang = next((int(value, 16) for value in languages
                         if int(value, 16) == want_lang), 0)
        except Exception:
            lang = 0
        desc = str(voice.GetDescription())
        if lang == want_lang and _voice_matches_persona(desc, persona):
            best = voice
            break
        if lang == want_lang and fallback is None:
            fallback = voice
    chosen = best or fallback
    if chosen is not None:
        speaker.Voice = chosen


def _speak_sapi_com(text: str, persona: PersonaId) -> bool:
    try:
        import pythoncom
        import win32com.client  # type: ignore[import-untyped]

        pythoncom.CoInitialize()
        try:
            speaker = win32com.client.Dispatch("SAPI.SpVoice")
            speaker.Volume = 100
            speaker.Rate = 2 if persona == "jarvis" else 1
            _pick_sapi_voice(speaker, persona)
            # SVSFIsNotXML: observations are text, never speech markup.
            speaker.Speak(text, 16)
            return True
        finally:
            pythoncom.CoUninitialize()
    except Exception as exc:
        logger.warning("SAPI COM speech failed: %s", exc)
        return False


def _speak_blocking(text: str, persona: PersonaId) -> None:
    if not _ON_WINDOWS:
        logger.info("[%s speaks] %s", persona.upper(), text)
        return
    if _speak_sapi_com(text, persona):
        return
    logger.error("Voice unavailable for %s — check Windows sound output", persona)


def _speech_worker() -> None:
    assert _speech_queue is not None
    while True:
        item = _speech_queue.get()
        try:
            if item is None:
                break
            text, persona = item
            _speak_blocking(text, persona)
        except Exception:
            logger.exception("Speech worker error")
        finally:
            _speech_queue.task_done()


def _ensure_worker() -> None:
    global _speech_queue, _worker_started
    with _worker_lock:
        if _worker_started:
            return
        _speech_queue = queue.Queue(maxsize=16)
        threading.Thread(
            target=_speech_worker,
            daemon=True,
            name="DVielle-TTS-Worker",
        ).start()
        _worker_started = True


def speak_async(text: str, persona: PersonaId = "jarvis") -> None:
    """Queue speech with Jarvis (US) or KT (British) voice."""
    if not text.strip():
        return
    if not _ON_WINDOWS:
        logger.info("[%s speaks] %s", persona.upper(), text)
        return
    _ensure_worker()
    assert _speech_queue is not None
    try:
        _speech_queue.put_nowait((text[:2048], persona))
    except queue.Full:
        logger.warning("Speech queue full; message retained in log: %s", text)


def random_greeting() -> str:
    return random.choice(GREETINGS)


def greet_on_startup(persona: PersonaId = "jarvis") -> str:
    text = random_greeting()
    speak_async(text, persona=persona)
    return text

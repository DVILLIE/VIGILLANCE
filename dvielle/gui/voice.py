"""Jarvis-style voice greetings — Windows SAPI TTS with reliable worker thread."""

from __future__ import annotations

import logging
import platform
import queue
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

_ON_WINDOWS = platform.system() == "Windows"
_speech_queue: queue.Queue[str | None] | None = None
_worker_started = False
_worker_lock = threading.Lock()

_VOICE_PREFS = (
    "david",
    "mark",
    "george",
    "james",
    "male",
    "zira",  # fallback female if no male voice
)


def _pick_voice_id(engine) -> None:
    try:
        voices = engine.getProperty("voices") or []
        lowered = [(v, v.name.lower()) for v in voices]
        for pref in _VOICE_PREFS:
            for voice, name in lowered:
                if pref in name:
                    engine.setProperty("voice", voice.id)
                    return
        if voices:
            engine.setProperty("voice", voices[0].id)
    except Exception as exc:
        logger.debug("Voice selection skipped: %s", exc)


def _speak_sapi_com(text: str) -> bool:
    """Primary path: Windows SAPI via win32com (most reliable in worker threads)."""
    try:
        import pythoncom
        import win32com.client  # type: ignore[import-untyped]

        pythoncom.CoInitialize()
        try:
            speaker = win32com.client.Dispatch("SAPI.SpVoice")
            speaker.Volume = 100
            speaker.Rate = 2
            for voice in speaker.GetVoices():
                name = str(voice.GetDescription()).lower()
                if any(p in name for p in _VOICE_PREFS[:5]):
                    speaker.Voice = voice
                    break
            speaker.Speak(text, 0)
            return True
        finally:
            pythoncom.CoUninitialize()
    except Exception as exc:
        logger.warning("SAPI COM speech failed: %s", exc)
        return False


def _speak_pyttsx3(text: str) -> bool:
    """Fallback: fresh pyttsx3 engine per utterance in this thread."""
    try:
        import pyttsx3

        engine = pyttsx3.init("sapi5")
        engine.setProperty("rate", 165)
        engine.setProperty("volume", 1.0)
        _pick_voice_id(engine)
        engine.say(text)
        engine.runAndWait()
        try:
            engine.stop()
        except Exception:
            pass
        return True
    except Exception as exc:
        logger.warning("pyttsx3 speech failed: %s", exc)
        return False


def _speak_blocking(text: str) -> None:
    if not _ON_WINDOWS:
        logger.info("[DVIELLE speaks] %s", text)
        return
    if _speak_sapi_com(text):
        return
    if _speak_pyttsx3(text):
        return
    logger.error("Jarvis voice unavailable — check Windows sound output and pywin32 install")


def _speech_worker() -> None:
    assert _speech_queue is not None
    while True:
        text = _speech_queue.get()
        try:
            if text is None:
                break
            _speak_blocking(text)
        except Exception:
            logger.exception("Speech worker error")
        finally:
            _speech_queue.task_done()


def _ensure_worker() -> None:
    global _speech_queue, _worker_started
    with _worker_lock:
        if _worker_started:
            return
        _speech_queue = queue.Queue()
        threading.Thread(
            target=_speech_worker,
            daemon=True,
            name="DVielle-TTS-Worker",
        ).start()
        _worker_started = True


def speak_async(text: str) -> None:
    """Queue speech on a dedicated TTS thread — safe from GUI threads."""
    if not text.strip():
        return
    if not _ON_WINDOWS:
        logger.info("[DVIELLE speaks] %s", text)
        return
    _ensure_worker()
    assert _speech_queue is not None
    _speech_queue.put(text)


def random_greeting() -> str:
    return random.choice(GREETINGS)


def greet_on_startup() -> str:
    text = random_greeting()
    speak_async(text)
    return text

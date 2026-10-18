"""Native speech language selection, COM cleanup and queue backpressure."""
import queue
import sys
import pytest
from types import SimpleNamespace
from dvielle.gui import voice


def test_sapi_language_codes_are_hexadecimal_and_multilingual():
    class Token:
        def __init__(self, language, description):
            self.language, self.description = language, description
        def GetAttribute(self, name):
            return self.language
        def GetDescription(self):
            return self.description
    us = Token("409", "Microsoft David")
    gb = Token("409;809", "Microsoft Hazel")
    speaker = SimpleNamespace(GetVoices=lambda: [us, gb], Voice=None)
    voice._pick_sapi_voice(speaker, "kt")
    assert speaker.Voice is gb
    voice._pick_sapi_voice(speaker, "jarvis")
    assert speaker.Voice is us


def test_speech_failure_releases_com_and_reports_failure(monkeypatch):
    client = pytest.importorskip("win32com.client")
    calls = []
    monkeypatch.setitem(sys.modules, "pythoncom", SimpleNamespace(
        CoInitialize=lambda: calls.append("init"),
        CoUninitialize=lambda: calls.append("uninit")))
    def fail(*args):
        raise RuntimeError("audio unavailable")
    monkeypatch.setattr(client, "Dispatch", fail)
    assert voice._speak_sapi_com("message", "jarvis") is False
    assert calls == ["init", "uninit"]


def test_queue_backpressure_keeps_gui_nonblocking(monkeypatch, caplog):
    pending = queue.Queue(maxsize=1)
    pending.put(("previous", "jarvis"))
    monkeypatch.setattr(voice, "_ON_WINDOWS", True)
    monkeypatch.setattr(voice, "_speech_queue", pending)
    monkeypatch.setattr(voice, "_ensure_worker", lambda: None)
    voice.speak_async("new message")
    assert pending.qsize() == 1
    assert "new message" in caplog.text

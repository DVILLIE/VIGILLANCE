"""Failure, backpressure and tray reuse contracts; no desktop popups."""
import queue
from agent import notifications
from dvielle.gui import tray


def test_existing_tray_is_reused_without_creating_another_icon(monkeypatch):
    calls = []
    class Icon:
        visible = True
        def notify(self, message, title):
            calls.append((message, title))
    monkeypatch.setattr(tray, "_tray_icon", Icon())
    notifications._deliver("title", "message", 1)
    assert calls == [("message", "title")]


def test_failed_or_not_ready_tray_does_not_claim_submission(monkeypatch):
    class Icon:
        visible = False
        def notify(self, *args):
            raise AssertionError("Not ready")
    monkeypatch.setattr(tray, "_tray_icon", Icon())
    assert tray.notify_tray("title", "message") is False
    Icon.visible = True
    assert tray.notify_tray("title", "message") is False


def test_full_queue_never_blocks_or_spawns_more_workers(monkeypatch, caplog):
    class Worker:
        def is_alive(self):
            return True
    pending = queue.Queue(maxsize=1)
    pending.put(("previous", "message", 1))
    monkeypatch.setattr(notifications, "_pending", pending)
    monkeypatch.setattr(notifications, "_worker", Worker())
    assert notifications.submit_notification("new", "message") is False
    assert pending.qsize() == 1
    assert "queue full" in caplog.text


def test_duration_is_bounded(monkeypatch):
    class Worker:
        def is_alive(self):
            return True
    pending = queue.Queue(maxsize=2)
    monkeypatch.setattr(notifications, "_pending", pending)
    monkeypatch.setattr(notifications, "_worker", Worker())
    assert notifications.submit_notification("title", "message", 999)
    assert pending.get_nowait()[2] == 30
    assert notifications.submit_notification("title", "message", -999)
    assert pending.get_nowait()[2] == 1

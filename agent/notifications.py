"""Bounded Windows notifications using the existing pystray backend.

Notification submission is best effort, never proof of on-screen delivery.
One worker serializes a bounded queue; failures retain the message in the log.
"""
from __future__ import annotations

import logging
import queue
import threading

_log = logging.getLogger("dvielle")
_pending: queue.Queue[tuple[str, str, float]] = queue.Queue(maxsize=8)
_lock = threading.Lock()
_worker: threading.Thread | None = None


def _deliver(title: str, message: str, duration: float) -> None:
    from dvielle.gui.tray import notify_tray, _create_icon_image
    if notify_tray(title, message):
        return
    import pystray
    if not pystray.Icon.HAS_NOTIFICATION:
        raise RuntimeError("Notification backend unavailable")
    image = _create_icon_image()
    if image is None:
        raise RuntimeError("Notification icon unavailable")
    icon = pystray.Icon("dvielle-notification", image, "D'Vielle")

    def setup(ready_icon):
        try:
            ready_icon.visible = True
            ready_icon.notify(message[:255], title[:63])
            threading.Event().wait(duration)
        except Exception:
            _log.exception("Notification backend failed")
        finally:
            ready_icon.stop()

    try:
        icon.run(setup=setup)
    finally:
        icon.stop()


def _run() -> None:
    while True:
        title, message, duration = _pending.get()
        try:
            _deliver(title, message, duration)
        except Exception:
            _log.exception("Notification submission failed: %s: %s", title, message)
        finally:
            _pending.task_done()


def submit_notification(title: str, message: str, duration: int = 8) -> bool:
    """Return queue admission, not OS visibility. Never block the caller."""
    global _worker
    item = (str(title), str(message), max(1.0, min(30.0, float(duration))))
    with _lock:
        if _worker is None or not _worker.is_alive():
            _worker = threading.Thread(target=_run, name="dvielle-notifications", daemon=True)
            _worker.start()
        try:
            _pending.put_nowait(item)
            return True
        except queue.Full:
            _log.warning("Notification queue full: %s: %s", title, message)
            return False

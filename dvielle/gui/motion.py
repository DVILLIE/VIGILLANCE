"""Short interaction transitions. No simulated measurements or traffic."""
from __future__ import annotations

import sys
import time


def system_motion_allowed() -> bool:
    if sys.platform == "win32":
        try:
            import ctypes
            enabled = ctypes.c_int()
            if ctypes.windll.user32.SystemParametersInfoW(0x1042, 0, ctypes.byref(enabled), 0):
                return bool(enabled.value)
        except (AttributeError, OSError):
            pass
    return True


class Motion:
    """One bounded timer for finite transitions; hidden windows settle immediately."""

    def __init__(self, root, enabled: bool = True):
        self.root = root
        self.enabled = enabled
        self._items = {}
        self._job = None
        self._closed = False

    def tween(self, key, paint, duration: int = 180):
        self._items.pop(key, None)
        if not self.enabled or self._closed or not self.root.winfo_viewable():
            paint(1.0)
            return
        self._items[key] = (time.monotonic(), max(0.05, duration / 1000), paint)
        paint(0.0)
        if self._job is None:
            self._job = self.root.after(33, self._tick)

    def _tick(self):
        self._job = None
        if self._closed:
            return
        now = time.monotonic()
        visible = bool(self.root.winfo_viewable())
        for key, (started, duration, paint) in list(self._items.items()):
            progress = min(1.0, (now - started) / duration) if visible and self.enabled else 1.0
            try:
                paint(1 - (1 - progress) ** 3)
            except Exception:
                self._items.pop(key, None)  # destroyed or unmapped widget
                continue
            if progress >= 1:
                self._items.pop(key, None)
        if self._items:
            self._job = self.root.after(33, self._tick)

    def set_enabled(self, enabled: bool):
        self.enabled = bool(enabled)
        if not self.enabled:
            self._settle()

    def _settle(self):
        if self._job is not None:
            self.root.after_cancel(self._job)
            self._job = None
        items, self._items = self._items, {}
        for _, _, paint in items.values():
            try:
                paint(1.0)
            except Exception:
                pass

    def close(self):
        self._settle()
        self._closed = True


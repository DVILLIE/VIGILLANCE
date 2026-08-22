"""Notification policy — quiet in tray unless CRITICAL."""

from __future__ import annotations

_minimized_to_tray = False


def set_minimized_to_tray(value: bool) -> None:
    global _minimized_to_tray
    _minimized_to_tray = value


def is_minimized_to_tray() -> bool:
    return _minimized_to_tray


def should_popup(severity: str = "INFO") -> bool:
    """When minimized: only CRITICAL popups. When visible: no popups (feed only)."""
    if _minimized_to_tray:
        return severity.upper() == "CRITICAL"
    return False

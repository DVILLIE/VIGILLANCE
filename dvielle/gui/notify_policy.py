"""Notification policy — quiet in tray unless CRITICAL."""

from __future__ import annotations

_mode = "headless"


def set_notification_mode(mode: str) -> None:
    """Headless and tray owners deliver critical alerts; visible console uses its feed."""
    if mode not in {"headless", "visible", "tray"}:
        raise ValueError(f"Unknown notification mode: {mode}")
    global _mode
    _mode = mode


def set_minimized_to_tray(value: bool) -> None:
    set_notification_mode("tray" if value else "visible")


def is_minimized_to_tray() -> bool:
    return _mode == "tray"


def should_popup(severity: str = "INFO") -> bool:
    """When minimized: only CRITICAL popups. When visible: no popups (feed only)."""
    return _mode in {"headless", "tray"} and severity.upper() == "CRITICAL"

"""Shared utilities for DVielle Agent."""

from __future__ import annotations

import ipaddress
import logging
import os
import platform
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any, Iterable

import yaml

from dvielle import APP_NAME, DATA_DIR_NAME, WINDOWS_DATA_DIR, WINDOWS_INSTALL_DIR

IS_WINDOWS = platform.system() == "Windows"

PROJECT_ROOT = Path(__file__).resolve().parents[1]

def _default_data_dir() -> Path:
    if IS_WINDOWS:
        # Installed layout: C:\DVILLIE\data
        if Path(WINDOWS_DATA_DIR).exists() or Path(WINDOWS_INSTALL_DIR).exists():
            return Path(WINDOWS_DATA_DIR)
        base = Path(os.environ.get("PROGRAMDATA", "C:/ProgramData"))
        dvielle = base / DATA_DIR_NAME
        legacy = base / "FortoroAgent"
        if legacy.exists() and not dvielle.exists():
            return legacy
        return Path(WINDOWS_DATA_DIR)
    return PROJECT_ROOT / "data"

def _default_project_root() -> Path:
    if IS_WINDOWS and Path(WINDOWS_INSTALL_DIR).exists():
        return Path(WINDOWS_INSTALL_DIR)
    return PROJECT_ROOT

DEFAULT_DATA_DIR = _default_data_dir()
INSTALL_ROOT = _default_project_root()


def load_yaml(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    with path.open(encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def resolve_config_paths(data_dir: Path | None = None) -> tuple[Path, Path, Path]:
    base = data_dir or DEFAULT_DATA_DIR
    install_config = INSTALL_ROOT / "config" / "config.yaml"
    if install_config.exists():
        config_dir = INSTALL_ROOT / "config"
    elif (base / "config" / "config.yaml").exists():
        config_dir = base / "config"
    else:
        config_dir = PROJECT_ROOT / "config"
    return (
        config_dir / "config.yaml",
        config_dir / "whitelists.yaml",
        config_dir / "telemetry-domains.txt",
    )


def setup_logging(data_dir: Path, level: str = "INFO", max_mb: int = 10, backup_count: int = 3) -> logging.Logger:
    log_dir = data_dir / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    logger = logging.getLogger("dvielle")
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))
    logger.handlers.clear()

    fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")
    file_handler = RotatingFileHandler(
        log_dir / "agent.log",
        maxBytes=max_mb * 1024 * 1024,
        backupCount=backup_count,
        encoding="utf-8",
    )
    file_handler.setFormatter(fmt)
    logger.addHandler(file_handler)

    if not getattr(sys, "frozen", False):
        stream = logging.StreamHandler()
        stream.setFormatter(fmt)
        logger.addHandler(stream)

    return logger


def ip_in_whitelist(ip: str, whitelist: Iterable[str]) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for entry in whitelist:
        entry = entry.strip()
        if not entry:
            continue
        try:
            if "/" in entry:
                if addr in ipaddress.ip_network(entry, strict=False):
                    return True
            elif addr == ipaddress.ip_address(entry):
                return True
        except ValueError:
            continue
    return False


def set_process_priority(priority: str) -> None:
    if not IS_WINDOWS:
        return
    try:
        import psutil

        proc = psutil.Process()
        mapping = {
            "idle": psutil.IDLE_PRIORITY_CLASS,
            "below_normal": psutil.BELOW_NORMAL_PRIORITY_CLASS,
            "normal": psutil.NORMAL_PRIORITY_CLASS,
        }
        proc.nice(mapping.get(priority, psutil.BELOW_NORMAL_PRIORITY_CLASS))
    except Exception:
        pass


def show_toast(title: str, message: str, duration: int = 8) -> None:
    if not IS_WINDOWS:
        logging.getLogger("dvielle").info("TOAST [%s]: %s", title, message)
        return
    try:
        from win10toast import ToastNotifier

        ToastNotifier().show_toast(title, message, duration=duration, threaded=True)
    except Exception:
        logging.getLogger("dvielle").info("TOAST [%s]: %s", title, message)


def get_foreground_process() -> tuple[int | None, str | None]:
    """Return (pid, process_name) of the foreground window on Windows."""
    if not IS_WINDOWS:
        return None, None
    try:
        import ctypes
        from ctypes import wintypes

        user32 = ctypes.windll.user32  # type: ignore[attr-defined]
        hwnd = user32.GetForegroundWindow()
        if not hwnd:
            return None, None
        pid = wintypes.DWORD()
        user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
        if not pid.value:
            return None, None
        import psutil

        return pid.value, psutil.Process(pid.value).name()
    except Exception:
        return None, None

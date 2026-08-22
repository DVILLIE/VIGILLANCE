"""Shared utilities for Fortoro Agent."""

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

IS_WINDOWS = platform.system() == "Windows"

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DATA_DIR = (
    Path(os.environ.get("PROGRAMDATA", "C:/ProgramData")) / "FortoroAgent"
    if IS_WINDOWS
    else PROJECT_ROOT / "data"
)


def load_yaml(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    with path.open(encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def resolve_config_paths(data_dir: Path | None = None) -> tuple[Path, Path, Path]:
    base = data_dir or DEFAULT_DATA_DIR
    config_dir = base / "config" if (base / "config" / "config.yaml").exists() else PROJECT_ROOT / "config"
    return (
        config_dir / "config.yaml",
        config_dir / "whitelists.yaml",
        config_dir / "telemetry-domains.txt",
    )


def setup_logging(data_dir: Path, level: str = "INFO", max_mb: int = 10, backup_count: int = 3) -> logging.Logger:
    log_dir = data_dir / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    logger = logging.getLogger("fortoro")
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


def show_toast(title: str, message: str) -> None:
    if not IS_WINDOWS:
        return
    try:
        from win10toast import ToastNotifier

        ToastNotifier().show_toast(title, message, duration=8, threaded=True)
    except Exception:
        pass

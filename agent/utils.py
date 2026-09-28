"""Shared utilities for DVielle Agent."""

from __future__ import annotations

import ipaddress
import logging
import subprocess
import sys
import threading
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any, Iterable

import yaml

IS_WINDOWS = sys.platform == "win32"

# Identity is the tree that supplied this code, or the config directory the
# caller selected. C:\DVILLIE is only the installer default, never a silent fallback.
PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DATA_DIR = PROJECT_ROOT / "data"
INSTALL_ROOT = PROJECT_ROOT


def load_yaml(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    with path.open(encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def _is_inside(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except ValueError:
        return False


def resolve_config_paths(config_dir: Path | None = None) -> tuple[Path, Path, Path]:
    """Config files for one install. Never prefers another tree because it exists."""
    directory = Path(config_dir) if config_dir is not None else (PROJECT_ROOT / "config")
    return (
        directory / "config.yaml",
        directory / "whitelists.yaml",
        directory / "telemetry-domains.txt",
    )


def resolve_data_dir(config: dict[str, Any], install_root: Path) -> Path:
    """Data directory for the selected install root.

    An explicit ``agent.data_dir`` is used only when it stays inside that root.
    A path in another install is refused. Null means ``<install_root>/data``.
    """
    root = Path(install_root).resolve()
    agent_cfg = config.get("agent") if isinstance(config, dict) else None
    custom = agent_cfg.get("data_dir") if isinstance(agent_cfg, dict) else None
    if custom:
        candidate = Path(str(custom)).expanduser()
        if not candidate.is_absolute():
            candidate = root / candidate
        candidate = candidate.resolve()
        if not _is_inside(candidate, root):
            raise ValueError(
                f"data_dir {candidate} is outside the selected install root {root}"
            )
        return candidate
    return (root / "data").resolve()


def setup_logging(data_dir: Path, level: str = "INFO", max_mb: int = 10, backup_count: int = 3) -> logging.Logger:
    log_dir = data_dir / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    logger = logging.getLogger("dvielle")
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))
    for handler in list(logger.handlers):
        logger.removeHandler(handler)
        handler.close()

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


def show_toast(title: str, message: str, duration: int = 8, severity: str = "INFO") -> None:
    try:
        from dvielle.gui.notify_policy import should_popup
        if not should_popup(severity):
            logging.getLogger("dvielle").info("LOG [%s/%s]: %s", severity, title, message)
            return
    except ImportError:
        pass
    if not IS_WINDOWS:
        logging.getLogger("dvielle").info("TOAST [%s]: %s", title, message)
        return
    try:
        from win10toast import ToastNotifier

        ToastNotifier().show_toast(title, message, duration=duration, threaded=True)
    except Exception:
        logging.getLogger("dvielle").info("TOAST [%s]: %s", title, message)


def _tree_kill(proc: subprocess.Popen) -> None:
    """Kill proc AND its descendants (children first) so no grandchild keeps the
    stdout pipe open. Best-effort via psutil (already a dependency); falls back to
    killing the direct child. Bounded by a short wait.
    """
    try:
        import psutil

        try:
            parent = psutil.Process(proc.pid)
        except psutil.NoSuchProcess:
            return
        descendants = parent.children(recursive=True)
        for child in descendants:
            try:
                child.kill()
            except Exception:
                pass
        try:
            parent.kill()
        except Exception:
            pass
        psutil.wait_procs(descendants + [parent], timeout=2)
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass


def run_hardened(
    args: list[str],
    *,
    timeout: float,
    secondary: float = 3.0,
) -> tuple[str | None, bool]:
    """Run a console command with a HARD wall-time bound. Returns (stdout|None, timed_out).

    Fixes the Windows subprocess wedge (CPython #88693): ``subprocess.run`` kills
    the direct child on timeout then calls ``communicate()`` with NO timeout, which
    blocks forever if a descendant inherited the stdout pipe. Bounded ``communicate``
    alone is NOT enough — once the direct child exits, ``communicate``'s reader-thread
    join can ignore its own timeout, and an ORPHANED grandchild can't be reached by a
    psutil tree-walk from the dead parent. So the real work runs on a daemon worker
    thread and we hard-join with a ceiling WE control; if it's still stuck we abandon
    it (best-effort tree-kill) and return. Guarantee: returns within roughly
    ``timeout + secondary + 3s`` — never minutes.

    A stuck orphaned descendant leaks a daemon reader thread + fd until it exits — the
    documented trigger to upgrade this to a Windows Job Object (KILL_ON_JOB_CLOSE).
    stdin/stderr are DEVNULL (only stdout is piped) to shrink the inherited-handle surface.
    """
    result: dict[str, Any] = {}

    def _worker() -> None:
        creationflags = (
            subprocess.CREATE_NO_WINDOW if (IS_WINDOWS and hasattr(subprocess, "CREATE_NO_WINDOW")) else 0
        )
        try:
            proc = subprocess.Popen(
                args,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                creationflags=creationflags,
            )
        except (FileNotFoundError, OSError) as exc:
            result["spawn_failed"] = True
            logging.getLogger("dvielle").debug("run_hardened spawn failed for %s: %s", args[:1], exc)
            return
        result["proc"] = proc
        try:
            out, _ = proc.communicate(timeout=timeout)
            # Native exit status matters: partial output from a failed command
            # must not be interpreted as a successful Windows observation.
            result["out"], result["timed_out"] = out if proc.returncode == 0 else None, False
        except subprocess.TimeoutExpired:
            _tree_kill(proc)
            try:
                out, _ = proc.communicate(timeout=secondary)
                result["out"], result["timed_out"] = (out or None), True
            except subprocess.TimeoutExpired:
                # Descendant still holds the pipe. Do NOT close the pipe here — that
                # blocks on the reader thread's buffer lock until the descendant dies.
                # Leave it; the reader thread is a daemon that exits on its own.
                result["out"], result["timed_out"] = None, True

    worker = threading.Thread(target=_worker, name="dv-run-hardened", daemon=True)
    worker.start()
    worker.join(timeout + secondary + 3.0)  # hard ceiling WE own

    if worker.is_alive():
        proc = result.get("proc")
        if proc is not None:
            _tree_kill(proc)  # best-effort; an orphaned descendant may survive (daemon leak)
        logging.getLogger("dvielle").warning(
            "run_hardened hard-abandoned a wedged subprocess (descendant held the pipe): %s", args[:1]
        )
        return None, True
    if result.get("spawn_failed"):
        return None, False
    return result.get("out"), result.get("timed_out", False)


def run_powershell(script: str, *, timeout: float, secondary: float = 3.0) -> tuple[str | None, bool]:
    """run_hardened for a PowerShell -Command script. Returns (stdout|None, timed_out)."""
    return run_hardened(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
        timeout=timeout,
        secondary=secondary,
    )


def get_foreground_process() -> tuple[int | None, str | None]:
    """Return (pid, process_name) of the foreground window on Windows."""
    if not IS_WINDOWS:
        return None, None
    try:
        import ctypes
        from ctypes import wintypes

        user32 = ctypes.windll.user32  # type: ignore[attr-defined]
        user32.GetForegroundWindow.restype = wintypes.HWND
        user32.GetWindowThreadProcessId.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.DWORD)]
        user32.GetWindowThreadProcessId.restype = wintypes.DWORD
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

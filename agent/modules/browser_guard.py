"""Defensive browser / credential hygiene watch.

Detects suspicious programs that often steal passwords, inject ads, or mimic
browsers — especially while a real browser is open.

This module NEVER captures keystrokes, passwords, or clipboard contents.
It only inspects process names/paths and network peers (psutil).
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import Any

import psutil

from agent.store.db import AgentStore
from agent.utils import IS_WINDOWS

logger = logging.getLogger("dvielle.browser_guard")

BROWSER_EXES = {
    "chrome.exe",
    "msedge.exe",
    "firefox.exe",
    "brave.exe",
    "opera.exe",
    "vivaldi.exe",
    "chromium.exe",
    "iexplore.exe",
    "waterfox.exe",
}

# Legitimate install path fragments (lowercase)
BROWSER_PATH_HINTS = (
    r"\google\chrome\\",
    r"\microsoft\edge\\",
    r"\mozilla firefox\\",
    r"\bravesoftware\\",
    r"\opera\\",
    r"\vivaldi\\",
    r"\chromium\\",
    r"\internet explorer\\",
    r"\program files",
)

# Name / path heuristics for stealers, clippers, injectors, adware (defensive)
SUSPICIOUS_NAME_RE = re.compile(
    r"(key.?log|keylog|clipper|stealer|password.?steal|pwd.?steal|"
    r"credential.?dump|mimikatz|lazagne|browser.?steal|inject(or|ion)?|"
    r"adware|pup\.|spyware|trojan|backdoor|rat\.|miner|cryptojack)",
    re.I,
)

# Common ad / tracker hosts (substring) — non-browser talking to these while browsing is odd
AD_HOST_HINTS = (
    "doubleclick.net",
    "googlesyndication.com",
    "adservice.google",
    "adnxs.com",
    "adsafeprotected.com",
    "taboola.com",
    "outbrain.com",
    "criteo.com",
    "pubmatic.com",
    "openx.net",
    "rubiconproject.com",
)


@dataclass
class BrowserThreat:
    kind: str
    severity: str
    process_name: str
    pid: int | None
    message: str
    detail: str


def _exe_path(proc: psutil.Process) -> str:
    try:
        return (proc.exe() or "").lower()
    except (psutil.Error, OSError):
        return ""


def _is_legit_browser_path(path: str) -> bool:
    if not path:
        return False
    return any(h in path for h in BROWSER_PATH_HINTS)


def _browsers_running() -> list[tuple[int, str, str]]:
    found: list[tuple[int, str, str]] = []
    for proc in psutil.process_iter(["pid", "name"]):
        try:
            name = (proc.info.get("name") or "").lower()
            if name in BROWSER_EXES:
                path = _exe_path(proc)
                found.append((int(proc.info["pid"]), name, path))
        except (psutil.Error, OSError, TypeError, ValueError):
            continue
    return found


class BrowserGuard:
    """Watch for credential/ad-steal style programs while browsing."""

    def __init__(self, store: AgentStore, config: dict[str, Any]) -> None:
        self.store = store
        self.config = config
        bg = config.get("browser_guard", {})
        self.enabled = bg.get("enabled", True)
        self._seen: set[str] = set()

    def run(self) -> list[BrowserThreat]:
        if not self.enabled or not IS_WINDOWS:
            return []

        browsers = _browsers_running()
        browsing = bool(browsers)
        threats: list[BrowserThreat] = []

        # Fake browsers (name matches chrome/edge but lives in Temp / odd path)
        for pid, name, path in browsers:
            if path and not _is_legit_browser_path(path):
                if "\\temp\\" in path or "\\downloads\\" in path or path.endswith(name):
                    threats.append(
                        BrowserThreat(
                            kind="fake_browser",
                            severity="CRITICAL",
                            process_name=name,
                            pid=pid,
                            message=f"Suspicious browser lookalike: {name} (pid {pid})",
                            detail=f"Path not a normal install location: {path or 'unknown'}",
                        )
                    )

        # Process name heuristics (always; louder when browsing)
        for proc in psutil.process_iter(["pid", "name"]):
            try:
                name = proc.info.get("name") or ""
                pid = proc.info.get("pid")
                path = _exe_path(proc)
                blob = f"{name} {path}"
                if not SUSPICIOUS_NAME_RE.search(blob):
                    continue
                if name.lower() in BROWSER_EXES and _is_legit_browser_path(path):
                    continue
                sev = "CRITICAL" if browsing else "WARNING"
                threats.append(
                    BrowserThreat(
                        kind="suspicious_process",
                        severity=sev,
                        process_name=name,
                        pid=int(pid) if pid is not None else None,
                        message=f"Possible stealer/adware process: {name}",
                        detail=f"Matched defensive heuristic while browsing={browsing}. Path={path or 'n/a'}",
                    )
                )
            except (psutil.Error, OSError, TypeError, ValueError):
                continue

        # Non-browser processes talking to known ad networks while a browser is open
        # (optional — reverse DNS is slow; off by default)
        bg = self.config.get("browser_guard", {})
        if browsing and bg.get("check_ad_sidecars", False):
            threats.extend(self._ad_sidecar_connections())

        # Dedupe + log
        out: list[BrowserThreat] = []
        for t in threats:
            key = f"{t.kind}|{t.process_name}|{t.pid}|{t.message}"
            if key in self._seen:
                continue
            self._seen.add(key)
            out.append(t)
            self.store.log_event(
                "browser_guard",
                t.severity,
                t.message,
                {"kind": t.kind, "pid": t.pid, "detail": t.detail, "browsing": browsing},
            )
            logger.warning("%s — %s", t.message, t.detail)

        if browsing and not out:
            # Quiet heartbeat for Attacks window (INFO, once per run is fine via store)
            self.store.log_event(
                "browser_guard",
                "INFO",
                f"Browser watch OK — {len(browsers)} browser process(es); no stealer/adware heuristics hit",
                {"browsers": [b[1] for b in browsers[:8]]},
            )

        return out

    def _ad_sidecar_connections(self) -> list[BrowserThreat]:
        found: list[BrowserThreat] = []
        try:
            conns = psutil.net_connections(kind="inet")
        except (psutil.AccessDenied, PermissionError):
            return found

        for c in conns:
            if not c.raddr or c.status != "ESTABLISHED":
                continue
            try:
                if c.pid is None:
                    continue
                proc = psutil.Process(c.pid)
                name = (proc.name() or "").lower()
            except (psutil.Error, OSError):
                continue
            if name in BROWSER_EXES or name in ("svchost.exe", "system", "msedgewebview2.exe"):
                continue
            # Resolve is expensive; match IP host via reverse only for flagged — use port+name heuristic lightly
            # Check process cmdline for ad SDK? skip. Match remote via getnameinfo optional.
            remote = f"{c.raddr.ip}:{c.raddr.port}"
            host_hint = self._quick_host_hint(c.raddr.ip)
            if host_hint and any(a in host_hint for a in AD_HOST_HINTS):
                found.append(
                    BrowserThreat(
                        kind="ad_sidecar",
                        severity="WARNING",
                        process_name=name,
                        pid=c.pid,
                        message=f"Non-browser process contacting ad network: {name}",
                        detail=f"{remote} ~ {host_hint}",
                    )
                )
        return found

    @staticmethod
    def _quick_host_hint(ip: str) -> str | None:
        import socket

        try:
            socket.setdefaulttimeout(0.4)
            host, _, _ = socket.gethostbyaddr(ip)
            return host.lower()
        except OSError:
            return None

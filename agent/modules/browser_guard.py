"""Defensive browser / credential hygiene watch.

Detects suspicious programs that often steal passwords, inject ads, or mimic
browsers — especially while a real browser is open.

This module NEVER captures keystrokes, passwords, or clipboard contents.
It only inspects process names/paths and network peers (psutil).
"""

from __future__ import annotations

import logging
import ntpath
import re
from dataclasses import dataclass
from typing import Any

import psutil

from agent import net_resolve
from agent.net_identity import host_matches_any
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

# Canonical install-location patterns are observations, never executable trust.
_BROWSER_INSTALL = re.compile(
    r"^(?:[a-z]:\\program files(?: \(x86\))?\\|"
    r"[a-z]:\\users\\[^\\]+\\appdata\\local\\)"
    r"(?:google\\chrome\\application\\chrome\.exe|"
    r"microsoft\\edge\\application\\msedge\.exe|"
    r"mozilla firefox\\firefox\.exe|"
    r"bravesoftware\\brave-browser\\application\\brave\.exe|"
    r"(?:programs\\)?opera(?:\\[0-9.]+)?\\opera\.exe|"
    r"vivaldi\\application\\vivaldi\.exe|"
    r"chromium\\application\\chromium\.exe|"
    r"internet explorer\\iexplore\.exe|waterfox\\waterfox\.exe)$",
    re.I,
)

# Name / path heuristics for stealers, clippers, injectors, adware (defensive)
SUSPICIOUS_NAME_RE = re.compile(
    r"(key.?log|keylog|clipper|stealer|password.?steal|pwd.?steal|"
    r"credential.?dump|mimikatz|lazagne|browser.?steal|inject(or|ion)?|"
    r"adware|pup\.|spyware|trojan|backdoor|rat\.|miner|cryptojack)",
    re.I,
)

# Exact DNS-boundary hints; reverse DNS does not prove adware or peer identity.
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
    return bool(_BROWSER_INSTALL.fullmatch(ntpath.normcase(ntpath.normpath(path))))


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
        self.collection_error: str | None = None
        self.config = config
        bg = config.get("browser_guard", {})
        self.enabled = bg.get("enabled", True)
        self._seen: set[str] = set()

    def run(self) -> list[BrowserThreat]:
        if not self.enabled or not IS_WINDOWS:
            return []

        self.collection_error = None
        try:
            browsers = _browsers_running()
            processes = list(psutil.process_iter(["pid", "name"]))
        except (psutil.Error, OSError) as exc:
            self.collection_error = f"Process enumeration unavailable: {type(exc).__name__}"
            return []
        browsing = bool(browsers)
        threats: list[BrowserThreat] = []

        for pid, name, path in browsers:
            if not _is_legit_browser_path(path):
                normalized = ntpath.normcase(ntpath.normpath(path)) if path else ""
                transient = "\\temp\\" in normalized or "\\downloads\\" in normalized
                threats.append(
                    BrowserThreat(
                        kind="browser_location_review" if transient else "browser_location_unverified",
                        severity="WARNING" if transient else "INFO",
                        process_name=name, pid=pid,
                        message=f"Browser install location {'needs review' if transient else 'unverified'}: {name} (pid {pid})",
                        detail=f"Observed path: {path or 'unavailable'}. "
                        "Portable/custom installs are possible; location alone cannot identify a fake browser.",
                    )
                )

        # Process name heuristics (always; louder when browsing)
        for proc in processes:
            try:
                name = proc.info.get("name") or ""
                pid = proc.info.get("pid")
                path = _exe_path(proc)
                blob = f"{name} {path}"
                if not SUSPICIOUS_NAME_RE.search(blob):
                    continue
                if name.lower() in BROWSER_EXES and _is_legit_browser_path(path):
                    continue
                sev = "WARNING"
                threats.append(
                    BrowserThreat(
                        kind="suspicious_process",
                        severity=sev,
                        process_name=name,
                        pid=int(pid) if pid is not None else None,
                        message=f"Process name/path heuristic needs review: {name}",
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
            if len(self._seen) >= 2048:
                self._seen.clear()
            self._seen.add(key)
            out.append(t)
            self.store.log_event(
                "browser_guard",
                t.severity,
                t.message,
                {"kind": t.kind, "pid": t.pid, "detail": t.detail, "browsing": browsing},
            )
            logger.log(logging.WARNING if t.severity == "WARNING" else logging.INFO,
                       "%s — %s", t.message, t.detail)

        if browsing and not out:
            # Quiet heartbeat for Attacks window (INFO, once per run is fine via store)
            self.store.log_event(
                "browser_guard",
                "INFO",
                f"Browser observation: {len(browsers)} browser process(es); no new name/path heuristic observations",
                {"browsers": [b[1] for b in browsers[:8]]},
            )

        return out

    def _ad_sidecar_connections(self) -> list[BrowserThreat]:
        found: list[BrowserThreat] = []
        try:
            conns = psutil.net_connections(kind="inet")
        except (psutil.Error, OSError) as exc:
            self.collection_error = f"Browser sidecar collection unavailable: {type(exc).__name__}"
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
            if host_matches_any(host_hint, list(AD_HOST_HINTS)):
                found.append(
                    BrowserThreat(
                        kind="ad_sidecar",
                        severity="INFO",
                        process_name=name,
                        pid=c.pid,
                        message=f"Non-browser peer has ad-network PTR hint: {name}",
                        detail=f"{remote} ~ {host_hint}; unverified reverse-DNS hint, not proof of adware",
                    )
                )
        return found

    @staticmethod
    def _quick_host_hint(ip: str) -> str | None:
        return net_resolve.lookup(ip)

"""Read-only privacy policy observations; missing evidence stays unavailable."""

from __future__ import annotations

import ipaddress
import logging
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from agent.net_identity import normalize_hostname
from agent.store.db import AgentStore
from agent.utils import IS_WINDOWS

if IS_WINDOWS:
    import winreg
else:
    winreg = None  # type: ignore[assignment]

logger = logging.getLogger("dvielle.privacy")
SETTINGS_ENDPOINT = "settings-win.data.microsoft.com"


@dataclass
class PrivacyCheckResult:
    name: str
    expected: str
    actual: str
    passed: bool | None
    detail: str = "Registry policy observation; effective behavior and network traffic are not measured."


def _read_reg_dword(hive, path: str, name: str) -> int | None:
    if not IS_WINDOWS or winreg is None:
        return None
    try:
        with winreg.OpenKey(hive, path) as key:
            value, kind = winreg.QueryValueEx(key, name)
            return value if kind == winreg.REG_DWORD and type(value) is int else None
    except OSError:
        return None


def _windows_edition() -> str | None:
    if not IS_WINDOWS or winreg is None:
        return None
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion") as key:
            value, _ = winreg.QueryValueEx(key, "EditionID")
            return value if isinstance(value, str) and value else None
    except OSError:
        return None


def _diagnostic_floor(edition: str | None) -> int | None:
    """Supported policy minimum, not a claim about observed outbound traffic.

    Microsoft Learn: configure-windows-diagnostic-data-in-your-organization.
    ProfessionalEducation is a Professional SKU, not the Education SKU.
    """
    edition = (edition or "").lower()
    if edition.startswith(("enterprise", "education", "iotenterprise", "server")):
        return 0
    if edition.startswith(("core", "home", "professional")):
        return 1
    return None


def _privacy_checks() -> list[dict]:
    if not IS_WINDOWS or winreg is None:
        return []
    return [
        {"name": "AllowTelemetry", "hive": winreg.HKEY_LOCAL_MACHINE,
         "path": r"SOFTWARE\Policies\Microsoft\Windows\DataCollection",
         "value": "AllowTelemetry", "expected": 0},
        {"name": "AllowCortana", "hive": winreg.HKEY_LOCAL_MACHINE,
         "path": r"SOFTWARE\Policies\Microsoft\Windows\Windows Search",
         "value": "AllowCortana", "expected": 0},
        {"name": "DisableAdvertisingId", "hive": winreg.HKEY_CURRENT_USER,
         "path": r"SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo",
         "value": "Enabled", "expected": 0},
    ]


def _hosts_overrides(text: str) -> dict[str, set[str]]:
    """Parse active exact hosts-file aliases; comments/substrings are not entries."""
    entries: dict[str, set[str]] = {}
    for line in text.splitlines():
        parts = line.split("#", 1)[0].split()
        if len(parts) < 2:
            continue
        try:
            address = str(ipaddress.ip_address(parts[0]))
        except ValueError:
            continue
        for alias in parts[1:]:
            hostname = normalize_hostname(alias)
            if hostname:
                entries.setdefault(hostname, set()).add(address)
    return entries


class PrivacyGuard:
    """Observe registry policy and exact hosts overrides without changing either."""

    def __init__(self, store: AgentStore, config: dict[str, Any], telemetry_file: Path) -> None:
        self.store = store
        self.telemetry_file = telemetry_file
        self.collection_error: str | None = None
        self._last_results: dict[str, tuple[str, bool | None]] = {}

    def run(self) -> list[PrivacyCheckResult]:
        self.collection_error = None
        if not IS_WINDOWS or winreg is None:
            self.collection_error = "Windows privacy policy unavailable on this platform"
            return []
        results: list[PrivacyCheckResult] = []
        edition = _windows_edition()
        for check in _privacy_checks():
            value = _read_reg_dword(check["hive"], check["path"], check["value"])
            expected = check["expected"]
            result = PrivacyCheckResult(check["name"], str(expected),
                                        str(value) if value is not None else "not configured or unreadable",
                                        None if value is None else value == expected)
            if check["name"] == "AllowTelemetry":
                floor = _diagnostic_floor(edition)
                result.expected = f"supported policy minimum {floor}" if floor is not None else "edition unavailable"
                result.passed = (max(floor, value) == floor
                                 if floor is not None and value in (0, 1, 2, 3) else None)
                result.detail = (f"Edition: {edition or 'unavailable'}. "
                                 f"Supported diagnostic policy floor: {floor if floor is not None else 'unavailable'}. "
                                 "A configured 0 does not turn diagnostics off on Home/Pro. "
                                 "Registry policy does not prove effective enforcement or zero Microsoft traffic.")
            results.append(result)
        results.extend(self._check_hosts_entries())
        for result in results:
            self.store.log_privacy_check(result.name, result.expected, result.actual, result.passed)
            state = (result.actual, result.passed)
            if result.passed is not True and self._last_results.get(result.name) != state:
                severity = "WARNING" if result.passed is False else "INFO"
                self.store.log_event("privacy", severity,
                                     f"Privacy policy {'needs review' if result.passed is False else 'unavailable'}: "
                                     f"{result.name} = {result.actual}",
                                     {"expected": result.expected, "detail": result.detail})
            self._last_results[result.name] = state
        missing = [r.name for r in results if r.passed is None]
        if missing:
            self.collection_error = "Privacy observations incomplete: " + ", ".join(missing)
        return results

    def _check_hosts_entries(self) -> list[PrivacyCheckResult]:
        hosts_path = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32/drivers/etc/hosts"
        try:
            entries = _hosts_overrides(hosts_path.read_text(encoding="utf-8-sig"))
        except (OSError, UnicodeError):
            return [PrivacyCheckResult("DiagnosticSettingsEndpoint", "no hosts override",
                                       "hosts file unavailable", None,
                                       "Hosts-file evidence is unavailable; endpoint reachability is untested.")]
        overrides = entries.get(SETTINGS_ENDPOINT, set())
        return [PrivacyCheckResult("DiagnosticSettingsEndpoint", "no hosts override",
                                   ", ".join(sorted(overrides)) if overrides else "no hosts override observed",
                                   not overrides,
                                   "Microsoft requires this endpoint for diagnostics settings; it does not upload "
                                   "Windows diagnostic data. Hosts-file absence does not verify firewall/DNS reachability.")]

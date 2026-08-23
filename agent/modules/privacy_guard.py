"""Privacy guard — re-check hardening settings; does not re-apply unless configured."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from agent.store.db import AgentStore
from agent.utils import IS_WINDOWS

if IS_WINDOWS:
    import winreg
else:
    winreg = None  # type: ignore[assignment]

logger = logging.getLogger("dvielle.privacy")


@dataclass
class PrivacyCheckResult:
    name: str
    expected: str
    actual: str
    passed: bool


def _read_reg_dword(hive, path: str, name: str) -> int | None:
    if not IS_WINDOWS or winreg is None:
        return None
    try:
        with winreg.OpenKey(hive, path) as key:
            val, _ = winreg.QueryValueEx(key, name)
            return int(val)
    except OSError:
        return None


def _privacy_checks() -> list[dict]:
    if not IS_WINDOWS or winreg is None:
        return []
    return [
        {
            "name": "AllowTelemetry",
            "hive": winreg.HKEY_LOCAL_MACHINE,
            "path": r"SOFTWARE\Policies\Microsoft\Windows\DataCollection",
            "value": "AllowTelemetry",
            # Aspirational Security(0). Windows Home often floors at Required(1).
            # See docs/TELEMETRY_AND_HOME.md — do not promise zero Microsoft traffic.
            "expected": 0,
        },
        {
            "name": "AllowCortana",
            "hive": winreg.HKEY_LOCAL_MACHINE,
            "path": r"SOFTWARE\Policies\Microsoft\Windows\Windows Search",
            "value": "AllowCortana",
            "expected": 0,
        },
        {
            "name": "DisableAdvertisingId",
            "hive": winreg.HKEY_CURRENT_USER,
            "path": r"SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo",
            "value": "Enabled",
            "expected": 0,
        },
    ]


class PrivacyGuard:
    """Monitor-only re-check of key privacy registry values."""

    def __init__(self, store: AgentStore, config: dict[str, Any], telemetry_file: Path) -> None:
        self.store = store
        self.telemetry_file = telemetry_file

    def run(self) -> list[PrivacyCheckResult]:
        if not IS_WINDOWS:
            logger.debug("Privacy guard skipped (non-Windows)")
            return []

        results: list[PrivacyCheckResult] = []
        for check in _privacy_checks():
            actual_val = _read_reg_dword(check["hive"], check["path"], check["value"])
            expected = check["expected"]
            if actual_val is None:
                actual_str = "not set"
                passed = False
            else:
                actual_str = str(actual_val)
                passed = actual_val == expected

            result = PrivacyCheckResult(
                name=check["name"],
                expected=str(expected),
                actual=actual_str,
                passed=passed,
            )
            results.append(result)
            self.store.log_privacy_check(check["name"], str(expected), actual_str, passed)

            if not passed:
                self.store.log_event(
                    "privacy",
                    "WARNING",
                    f"Privacy setting drift: {check['name']} is {actual_str} (expected {expected})",
                    None,
                )
                logger.warning("Privacy drift: %s = %s (expected %s)", check["name"], actual_str, expected)

        self._check_hosts_entries()
        return results

    def _check_hosts_entries(self) -> None:
        if not self.telemetry_file.exists():
            return
        hosts_path = Path(r"C:\Windows\System32\drivers\etc\hosts")
        if not hosts_path.exists():
            return
        try:
            hosts_content = hosts_path.read_text(encoding="utf-8", errors="ignore").lower()
        except OSError:
            return

        domains = [
            line.strip()
            for line in self.telemetry_file.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.startswith("#")
        ]
        missing = [d for d in domains[:5] if d.lower() not in hosts_content]
        if missing and len(missing) == min(5, len(domains)):
            self.store.log_event(
                "privacy",
                "INFO",
                "Telemetry domains not blocked in hosts file (run harden-once.ps1 to apply)",
                {"sample_missing": missing[:3]},
            )

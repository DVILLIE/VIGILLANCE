"""Windows Defender and firewall status checks."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

from agent.store.db import AgentStore
from agent.utils import IS_WINDOWS, run_powershell

logger = logging.getLogger("dvielle.security")


@dataclass
class SecurityStatus:
    defender_enabled: bool | None
    realtime_protection: bool | None
    firewall_enabled: bool | None
    firewall_profiles: dict[str, bool]
    issues: list[str]


def _query_defender() -> tuple[bool | None, bool | None]:
    if not IS_WINDOWS:
        return None, None
    ps = """
$mp = Get-MpComputerStatus -ErrorAction SilentlyContinue
if ($mp) {
    Write-Output "AM:$($mp.AntivirusEnabled)"
    Write-Output "RT:$($mp.RealTimeProtectionEnabled)"
}
"""
    stdout, _ = run_powershell(ps, timeout=20)
    if stdout is None:
        return None, None
    am, rt = None, None
    for line in stdout.splitlines():
        if line.startswith("AM:"):
            am = line.split(":", 1)[1].strip().lower() == "true"
        elif line.startswith("RT:"):
            rt = line.split(":", 1)[1].strip().lower() == "true"
    return am, rt


def _query_firewall() -> tuple[bool | None, dict[str, bool]]:
    if not IS_WINDOWS:
        return None, {}
    ps = """
$profiles = Get-NetFirewallProfile -ErrorAction SilentlyContinue
foreach ($p in $profiles) {
    Write-Output "$($p.Name):$($p.Enabled)"
}
"""
    stdout, _ = run_powershell(ps, timeout=20)
    if stdout is None:
        return None, {}
    profiles: dict[str, bool] = {}
    for line in stdout.splitlines():
        if ":" in line:
            name, enabled = line.split(":", 1)
            profiles[name.strip()] = enabled.strip().lower() == "true"
    all_on = all(profiles.values()) if profiles else None
    return all_on, profiles


class SecurityMonitor:
    def __init__(self, store: AgentStore, config: dict[str, Any]) -> None:
        self.store = store

    def run(self) -> SecurityStatus:
        defender, realtime = _query_defender()
        firewall, profiles = _query_firewall()
        issues: list[str] = []

        if defender is False:
            issues.append("Windows Defender antivirus is disabled")
        if realtime is False:
            issues.append("Real-time protection is disabled")
        if firewall is False:
            issues.append("One or more firewall profiles are disabled")

        for issue in issues:
            self.store.log_event("security", "CRITICAL", issue, None)
            logger.critical(issue)

        return SecurityStatus(
            defender_enabled=defender,
            realtime_protection=realtime,
            firewall_enabled=firewall,
            firewall_profiles=profiles,
            issues=issues,
        )

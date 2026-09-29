"""Windows Defender and firewall status checks."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

from agent.capability import current_edition_matrix
from agent.edition_matrix import EditionMatrix
from agent.modules.defender_health import (
    MAPS_GUIDANCE,
    DefenderHealth,
    MapsCheck,
    combine_health,
    query_defender_health,
    query_maps,
)
from agent.modules.firewall_assist import query_firewall_assist
from agent.modules.prevention import build_promotion, load_recovery, query_prevention_posture
from agent.policy import ActionKind, Authorization, PolicyCortex
from agent.policy.levels import LEVEL_RECOMMEND
from agent.store.db import AgentStore
from agent.utils import IS_WINDOWS, run_powershell

logger = logging.getLogger("dvielle.security")

# Transition dedup: only issue a fresh recommendation when the posture CHANGES,
# not every pulse while Defender/firewall stays off.
_last_security_sig: str | None = None


@dataclass
class SecurityStatus:
    defender_enabled: bool | None
    realtime_protection: bool | None
    firewall_enabled: bool | None
    firewall_profiles: dict[str, bool]
    issues: list[str]
    defender_health: dict[str, Any] | None = None
    maps: dict[str, Any] | None = None
    edition_matrix: dict[str, Any] | None = None
    firewall_query_state: str = "UNKNOWN"
    prevention: dict[str, Any] | None = None
    recovery: dict[str, Any] | None = None
    promotion: dict[str, Any] | None = None
    firewall_assist: dict[str, Any] | None = None


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
    stdout, timed_out = run_powershell(ps, timeout=20)
    if stdout is None or timed_out:
        return None, None
    am, rt = None, None
    for line in stdout.splitlines():
        if line.startswith("AM:"):
            am = {"true": True, "false": False}.get(line.split(":", 1)[1].strip().lower())
        elif line.startswith("RT:"):
            rt = {"true": True, "false": False}.get(line.split(":", 1)[1].strip().lower())
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
    stdout, timed_out = run_powershell(ps, timeout=20)
    if stdout is None or timed_out:
        return None, {}
    profiles: dict[str, bool] = {}
    for line in stdout.splitlines():
        if ":" in line:
            name, enabled = line.split(":", 1)
            value = {"true": True, "false": False}.get(enabled.strip().lower())
            if value is not None and name.strip().lower() in {"domain", "private", "public"}:
                profiles[name.strip().lower()] = value
    # A known disabled profile is adverse evidence even when another is unreadable.
    all_on = False if False in profiles.values() else (True if len(profiles) == 3 else None)
    return all_on, profiles


def _query_defender_health() -> DefenderHealth:
    return query_defender_health()


def _query_maps() -> MapsCheck:
    return query_maps()


def _query_edition_matrix() -> EditionMatrix:
    return current_edition_matrix()


def _query_prevention():
    return query_prevention_posture()


def _query_firewall_assist():
    return query_firewall_assist()


def _firewall_query_state(profiles: dict[str, bool]) -> str:
    if not IS_WINDOWS:
        return "UNAVAILABLE"
    if len(profiles) == 3:
        return "AVAILABLE"
    if profiles:
        return "LIMITED"
    return "UNKNOWN"


class SecurityMonitor:
    def __init__(
        self,
        store: AgentStore,
        config: dict[str, Any],
        cortex: PolicyCortex | None = None,
    ) -> None:
        self.store = store
        self.cortex = cortex
        self.collection_error: str | None = None

    def run(self) -> SecurityStatus:
        global _last_security_sig
        defender, realtime = _query_defender()
        firewall, profiles = _query_firewall()
        maps = _query_maps()
        health = combine_health(_query_defender_health(), maps)
        matrix = _query_edition_matrix()
        posture = _query_prevention()
        firewall_assist = _query_firewall_assist()
        recovery = load_recovery(self.store.db_path.parent / "learn" / "recovery.txt")
        promotion = build_promotion(posture, health, maps, sku=matrix.sku)
        issues: list[str] = []

        if defender is False:
            issues.append("Windows Defender antivirus is disabled")
        if realtime is False:
            issues.append("Real-time protection is disabled")
        if firewall is False:
            issues.append("One or more firewall profiles are disabled")
        if health.coverage == "complete" and health.active_mode == "LIMITED":
            issues.append(
                "Defender AMRunningMode is not Normal. Active mode is a prerequisite for ASR and CFA. "
                "Passive or EDR Block Mode can be expected when another antivirus provides real-time protection."
            )
        if health.signatures_out_of_date is True:
            issues.append("Defender reports security intelligence out of date")
        if maps.result == "fail":
            issues.append(
                "Defender cloud connectivity check failed. " + MAPS_GUIDANCE
            )

        for issue in issues:
            self.store.log_event("security", "CRITICAL", issue, None)
            logger.critical(issue)

        # L2 recommendation on the normal path — a durable evidence-chain entry for
        # the WHY surface (recommend only; no automatic action). Issue on change.
        sig = ";".join(sorted(issues))
        if issues and self.cortex is not None and sig != _last_security_sig:
            self.cortex.issue(
                action=ActionKind.RECOMMEND,
                action_level=LEVEL_RECOMMEND,
                confidence=0.9,
                evidence_summary=issues + ["Level-2 recommendation — DVielle takes no automatic action"],
                authorization=Authorization.AUTOMATIC_POLICY,
                target="windows_security_posture",
                initiator="security",
                reversible=False,
                policy_ref="security_posture",
                details={"issues": issues, "defender": defender, "firewall": firewall},
            )
        _last_security_sig = sig if issues else None

        reasons: list[str] = []
        if health.coverage != "complete":
            reasons.append(health.coverage_detail)
        if posture.coverage != "complete":
            reasons.append(posture.coverage_detail)
        if firewall_assist.coverage != "complete":
            reasons.append(firewall_assist.coverage_detail)
        if defender is None or realtime is None or firewall is None:
            reasons.append("Windows security posture partially unavailable")
        # MAPS unavailable blocks all_clear on the health report. It does not
        # discard a completed Defender and firewall read.
        self.collection_error = "; ".join(reasons) if reasons else None

        return SecurityStatus(
            defender_enabled=defender,
            realtime_protection=realtime,
            firewall_enabled=firewall,
            firewall_profiles=profiles,
            issues=issues,
            defender_health=health.to_dict(),
            maps=maps.to_dict(),
            edition_matrix=matrix.to_dict(),
            firewall_query_state=_firewall_query_state(profiles),
            prevention=posture.to_dict(),
            recovery=recovery.to_dict(),
            promotion=promotion,
            firewall_assist=firewall_assist.to_dict(),
        )

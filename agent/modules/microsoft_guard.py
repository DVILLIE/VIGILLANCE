"""Microsoft / privacy observations — Privacy Control Plane provider adapter.

P0 invariant: this module OBSERVES and RECOMMENDS only.
It must not firewall, terminate, disable services, or mutate registry
without a Policy Cortex Decision ID + Action Executor.

Process list entries are candidates for purpose classification, not a kill list.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import psutil

from agent import net_resolve
from agent.net_identity import host_matches_any, host_matches_domain, normalize_hostname
from agent.policy import ActionKind, Authorization, PolicyCortex
from agent.policy.levels import LEVEL_RECOMMEND
from agent.store.db import AgentStore
from agent.utils import IS_WINDOWS

logger = logging.getLogger("dvielle.microsoft_guard")

TELEMETRY_PROCESSES = {
    "compattelrunner.exe",
    "devicecensus.exe",
    "diagnosticshub.standardcollector.service.exe",
    "wermgr.exe",
    "dmclient.exe",
    "gamebar.exe",
    "gamebarftserver.exe",
    "phoneexperiencehost.exe",
    "widgets.exe",
    "searchapp.exe",
}

UPDATE_SAFE_DOMAINS = (
    "windowsupdate.com",
    "update.microsoft.com",
    "download.microsoft.com",
    "ctldl.windowsupdate.com",
    "delivery.mp.microsoft.com",
    "mp.microsoft.com",
    "wns.windows.com",
    "login.live.com",
    "login.microsoftonline.com",
)


@dataclass
class TelemetryAlert:
    kind: str
    message: str
    detail: str
    blocked: bool = False
    recommended_action: str | None = None


def _load_domains(telemetry_file: Path) -> set[str]:
    if not telemetry_file.exists():
        return set()
    domains: set[str] = set()
    for line in telemetry_file.read_text(encoding="utf-8").splitlines():
        line = line.strip().lower()
        if line and not line.startswith("#"):
            domains.add(line)
    return domains


def _is_update_domain(host: str) -> bool:
    return any(host_matches_domain(host, d) for d in UPDATE_SAFE_DOMAINS)


def _resolve_ip_to_host(ip: str) -> str | None:
    # Non-blocking cached reverse-DNS — never stall the nerve loop (audit C3).
    host = net_resolve.lookup(ip)
    return normalize_hostname(host) if host else None


def _host_matches_telemetry(host: str, domains: set[str]) -> bool:
    if _is_update_domain(host):
        return False
    return host_matches_any(host, domains)


class MicrosoftGuard:
    """Privacy adapter: observe → recommend. No direct mutations (Level ≥3 requires Cortex+Executor)."""

    def __init__(
        self,
        store: AgentStore,
        config: dict[str, Any],
        telemetry_file: Path,
        scripts_dir: Path,
        never_block_domains: list[str],
        cortex: PolicyCortex | None = None,
    ) -> None:
        self.store = store
        self.telemetry_file = telemetry_file
        self.scripts_dir = scripts_dir
        self.domains = _load_domains(telemetry_file)
        self.never_block = {d.lower() for d in never_block_domains}
        self.cortex = cortex
        cfg = config.get("microsoft_guard", {})
        self.strict_mode = cfg.get("strict_mode", True)
        self._legacy_wants_act = any(
            [
                cfg.get("auto_remediate_registry", False),
                cfg.get("block_telemetry_firewall", False),
                cfg.get("block_telemetry_connections", False),
                cfg.get("disable_telemetry_services", False),
            ]
        )

    def run(self, monitor_only: bool = False) -> list[TelemetryAlert]:
        if not IS_WINDOWS:
            return []

        alerts: list[TelemetryAlert] = []
        if self._legacy_wants_act and not monitor_only:
            decision_id = None
            if self.cortex is not None:
                decision = self.cortex.issue(
                    action=ActionKind.RECOMMEND,
                    action_level=LEVEL_RECOMMEND,
                    confidence=0.55,
                    evidence_summary=[
                        "Config requested privacy remediation flags",
                        "P0.0: mutations require Level≥3 + Authorization + typed handler",
                    ],
                    authorization=Authorization.AUTOMATIC_POLICY,
                    policy_ref="microsoft_guard_legacy_flags",
                    target="privacy_remediation",
                    initiator="microsoft_guard",
                    reversible=False,
                    details={"suggested_next": "USER_APPROVED + typed action"},
                )
                if decision is not None:
                    decision_id = decision.decision_id
            alerts.append(
                TelemetryAlert(
                    kind="policy",
                    message=(
                        "RECOMMEND: privacy remediation requested in config but blocked by P0 — "
                        "requires Level≥3 Authorization + typed ActionExecutor"
                        + (f" (decision={decision_id})" if decision_id else "")
                    ),
                    detail="cortex_required",
                    blocked=False,
                    recommended_action="RECOMMEND",
                )
            )
            self.store.log_event(
                "microsoft_guard",
                "INFO",
                "Legacy mutate flags ignored — observe/recommend only (P0.0)",
                {"monitor_only": monitor_only, "decision_id": decision_id},
            )

        alerts.extend(self._scan_telemetry_connections())
        alerts.extend(self._scan_telemetry_processes())
        return alerts

    def _scan_telemetry_connections(self) -> list[TelemetryAlert]:
        alerts: list[TelemetryAlert] = []
        try:
            connections = psutil.net_connections(kind="inet")
        except (psutil.AccessDenied, PermissionError):
            return alerts

        for conn in connections:
            if conn.status != psutil.CONN_ESTABLISHED or not conn.raddr:
                continue
            remote_ip = conn.raddr.ip
            proc_name = None
            if conn.pid:
                try:
                    proc_name = psutil.Process(conn.pid).name()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass

            hostname = _resolve_ip_to_host(remote_ip)
            if not hostname:
                continue
            if host_matches_any(hostname, self.never_block):
                continue
            if not _host_matches_telemetry(hostname, self.domains):
                continue

            msg = f"Observed Microsoft-classified traffic: {proc_name or 'unknown'} -> {hostname}"
            alerts.append(
                TelemetryAlert(
                    kind="connection",
                    message=msg,
                    detail=hostname,
                    blocked=False,
                    recommended_action="AUDIT",
                )
            )
            self.store.log_event(
                "microsoft_guard",
                "WARNING",
                msg,
                {"pid": conn.pid, "process": proc_name, "host": hostname, "blocked": False},
            )
            logger.warning("%s", msg)

        return alerts

    def _scan_telemetry_processes(self) -> list[TelemetryAlert]:
        alerts: list[TelemetryAlert] = []
        for proc in psutil.process_iter(["pid", "name"]):
            try:
                name = (proc.info["name"] or "").lower()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
            if name not in TELEMETRY_PROCESSES:
                continue
            msg = f"Observed candidate process (purpose TBD): {proc.info['name']}"
            alerts.append(
                TelemetryAlert(
                    kind="process",
                    message=msg,
                    detail=name,
                    blocked=False,
                    recommended_action="CLASSIFY",
                )
            )
            self.store.log_event(
                "microsoft_guard",
                "INFO",
                msg,
                {"pid": proc.info["pid"], "blocked": False},
            )
        return alerts

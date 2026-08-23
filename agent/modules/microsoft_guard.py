"""Microsoft telemetry guard — block spying, data uploads, and background internet use."""

from __future__ import annotations

import logging
import socket
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import psutil

from agent.store.db import AgentStore
from agent.utils import IS_WINDOWS, show_toast

logger = logging.getLogger("dvielle.microsoft_guard")

# Processes commonly associated with telemetry / background Microsoft uploads
TELEMETRY_PROCESSES = {
    "compatTelRunner.exe",
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

# Services that upload telemetry — safe to disable in strict mode
TELEMETRY_SERVICES = {
    "DiagTrack",           # Connected User Experiences and Telemetry
    "dmwappushservice",    # WAP Push Message Routing
    "WerSvc",              # Windows Error Reporting (optional)
}

UPDATE_SAFE_SUBSTRINGS = (
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
    h = host.lower()
    return any(s in h for s in UPDATE_SAFE_SUBSTRINGS)


def _resolve_ip_to_host(ip: str) -> str | None:
    try:
        host, _, _ = socket.gethostbyaddr(ip)
        return host.lower()
    except (socket.herror, socket.gaierror, OSError):
        return None


def _host_matches_telemetry(host: str, domains: set[str]) -> bool:
    if _is_update_domain(host):
        return False
    h = host.lower()
    return any(h == d or h.endswith("." + d) for d in domains)


def _run_ps(script: str, timeout: int = 60) -> tuple[bool, str]:
    if not IS_WINDOWS:
        return False, "not Windows"
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script],
            capture_output=True,
            text=True,
            timeout=timeout,
            creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, "CREATE_NO_WINDOW") else 0,
        )
        return result.returncode == 0, result.stdout + result.stderr
    except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
        return False, str(exc)


class MicrosoftGuard:
    """
    Stops Microsoft telemetry uploads and re-enforces privacy settings.
    Internet stays available for user apps; telemetry domains are blocked.
    """

    def __init__(
        self,
        store: AgentStore,
        config: dict[str, Any],
        telemetry_file: Path,
        scripts_dir: Path,
        never_block_domains: list[str],
    ) -> None:
        self.store = store
        self.telemetry_file = telemetry_file
        self.scripts_dir = scripts_dir
        self.domains = _load_domains(telemetry_file)
        self.never_block = {d.lower() for d in never_block_domains}
        cfg = config.get("microsoft_guard", {})
        self.strict_mode = cfg.get("strict_mode", True)
        self.auto_remediate = cfg.get("auto_remediate_registry", True)
        self.block_firewall = cfg.get("block_telemetry_firewall", True)
        self.block_connections = cfg.get("block_telemetry_connections", True)
        self.disable_services = cfg.get("disable_telemetry_services", True)
        self._firewall_applied = False

    def run(self, monitor_only: bool = False) -> list[TelemetryAlert]:
        if not IS_WINDOWS:
            return []

        alerts: list[TelemetryAlert] = []

        if self.strict_mode and not monitor_only:
            if self.block_firewall and not self._firewall_applied:
                self._ensure_firewall_blocks()
            if self.disable_services:
                alerts.extend(self._disable_telemetry_services())
            if self.auto_remediate:
                alerts.extend(self._remediate_registry())

        alerts.extend(self._scan_telemetry_connections(monitor_only))
        alerts.extend(self._scan_telemetry_processes(monitor_only))
        return alerts

    def _ensure_firewall_blocks(self) -> None:
        script = self.scripts_dir / "block-telemetry-firewall.ps1"
        if not script.exists():
            return
        ok, out = _run_ps(
            f"& '{script}' -DomainsFile '{self.telemetry_file}'",
            timeout=120,
        )
        if ok:
            self._firewall_applied = True
            self.store.log_event("microsoft_guard", "INFO", "Telemetry firewall rules applied", None)
        else:
            logger.warning("Firewall block script failed: %s", out)

    def _disable_telemetry_services(self) -> list[TelemetryAlert]:
        alerts: list[TelemetryAlert] = []
        for svc in TELEMETRY_SERVICES:
            ps = f"""
$s = Get-Service -Name '{svc}' -ErrorAction SilentlyContinue
if ($s -and $s.Status -ne 'Stopped') {{
    Stop-Service -Name '{svc}' -Force -ErrorAction SilentlyContinue
    Set-Service -Name '{svc}' -StartupType Disabled -ErrorAction SilentlyContinue
    Write-Output 'stopped'
}}
"""
            ok, out = _run_ps(ps)
            if ok and "stopped" in out:
                msg = f"Stopped telemetry service: {svc}"
                alerts.append(TelemetryAlert("service", msg, svc, blocked=True))
                self.store.log_event("microsoft_guard", "INFO", msg, {"service": svc})
        return alerts

    def _remediate_registry(self) -> list[TelemetryAlert]:
        alerts: list[TelemetryAlert] = []
        fixes = [
            (r"HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection", "AllowTelemetry", 0),
            (r"HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search", "AllowCortana", 0),
            (r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo", "Enabled", 0),
            (r"HKLM\SOFTWARE\Policies\Microsoft\Windows\System", "PublishUserActivities", 0),
            (r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection", "AllowTelemetry", 0),
        ]
        for path, name, value in fixes:
            ps = f"""
if (-not (Test-Path '{path}')) {{ New-Item -Path '{path}' -Force | Out-Null }}
$cur = (Get-ItemProperty -Path '{path}' -Name '{name}' -ErrorAction SilentlyContinue).{name}
if ($cur -ne {value}) {{
    Set-ItemProperty -Path '{path}' -Name '{name}' -Value {value} -Type DWord -Force
    Write-Output 'fixed'
}}
"""
            ok, out = _run_ps(ps)
            if ok and "fixed" in out:
                msg = f"Re-applied privacy setting: {name}=0"
                alerts.append(TelemetryAlert("registry", msg, path, blocked=True))
                self.store.log_event("microsoft_guard", "INFO", msg, {"key": name})
        return alerts

    def _scan_telemetry_connections(self, monitor_only: bool) -> list[TelemetryAlert]:
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
            if any(nb in hostname for nb in self.never_block):
                continue
            if not _host_matches_telemetry(hostname, self.domains):
                continue

            msg = f"Microsoft telemetry upload: {proc_name or 'unknown'} -> {hostname}"
            blocked = False
            if self.block_connections and not monitor_only and conn.pid:
                try:
                    psutil.Process(conn.pid).terminate()
                    blocked = True
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass

            alerts.append(TelemetryAlert("connection", msg, hostname, blocked=blocked))
            self.store.log_event(
                "microsoft_guard",
                "WARNING" if not blocked else "INFO",
                msg,
                {"pid": conn.pid, "process": proc_name, "host": hostname, "blocked": blocked},
            )
            logger.warning(msg)

        return alerts

    def _scan_telemetry_processes(self, monitor_only: bool) -> list[TelemetryAlert]:
        alerts: list[TelemetryAlert] = []
        for proc in psutil.process_iter(["pid", "name"]):
            try:
                name = (proc.info["name"] or "").lower()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
            if name not in {p.lower() for p in TELEMETRY_PROCESSES}:
                continue
            msg = f"Telemetry process running: {proc.info['name']}"
            blocked = False
            if self.strict_mode and not monitor_only:
                try:
                    proc.terminate()
                    blocked = True
                    msg = f"Stopped telemetry process: {proc.info['name']}"
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
            alerts.append(TelemetryAlert("process", msg, name, blocked=blocked))
            self.store.log_event(
                "microsoft_guard",
                "INFO" if blocked else "WARNING",
                msg,
                {"pid": proc.info["pid"], "blocked": blocked},
            )
        return alerts

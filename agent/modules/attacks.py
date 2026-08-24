"""Attack detection via Windows Security event log (4625, 4776)."""

from __future__ import annotations

import logging
import subprocess
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from agent.store.db import AgentStore
from agent.utils import IS_WINDOWS

logger = logging.getLogger("dvielle.attacks")

# Track last processed record to avoid duplicates across polls
_last_check: datetime | None = None


@dataclass
class AttackAlert:
    source_ip: str
    username: str | None
    event_id: int
    attempt_count: int
    should_block: bool


def _query_security_events(since: datetime) -> list[dict[str, str | int | None]]:
    if not IS_WINDOWS:
        return []

    since_str = since.strftime("%Y-%m-%dT%H:%M:%S")
    ps_script = f"""
$events = Get-WinEvent -FilterHashtable @{{
    LogName = 'Security'
    Id = 4625, 4776
    StartTime = [datetime]'{since_str}'
}} -ErrorAction SilentlyContinue | Select-Object -First 50
foreach ($e in $events) {{
    $xml = [xml]$e.ToXml()
    $ip = ($xml.Event.EventData.Data | Where-Object {{ $_.Name -eq 'IpAddress' }}).'#text'
    if (-not $ip) {{ $ip = ($xml.Event.EventData.Data | Where-Object {{ $_.Name -eq 'Workstation' }}).'#text' }}
    $user = ($xml.Event.EventData.Data | Where-Object {{ $_.Name -eq 'TargetUserName' }}).'#text'
    $ws = ($xml.Event.EventData.Data | Where-Object {{ $_.Name -eq 'WorkstationName' }}).'#text'
    Write-Output "$($e.Id)|$ip|$user|$ws"
}}
"""
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_script],
            capture_output=True,
            text=True,
            timeout=30,
            creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, "CREATE_NO_WINDOW") else 0,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
        logger.warning("Event log query failed: %s", exc)
        return []

    events: list[dict[str, str | int | None]] = []
    for line in result.stdout.splitlines():
        line = line.strip()
        if not line or "|" not in line:
            continue
        parts = line.split("|", 3)
        if len(parts) < 2:
            continue
        try:
            event_id = int(parts[0])
        except ValueError:
            continue
        source_ip = parts[1] if parts[1] and parts[1] not in ("-", "") else None
        username = parts[2] if len(parts) > 2 else None
        workstation = parts[3] if len(parts) > 3 else None
        events.append(
            {
                "event_id": event_id,
                "source_ip": source_ip,
                "username": username,
                "workstation": workstation,
            }
        )
    return events


def _block_ip_powershell(ip: str, scripts_dir: Path) -> bool:
    script = scripts_dir / "block-ip.ps1"
    if not script.exists():
        logger.error("block-ip.ps1 not found at %s", script)
        return False
    try:
        subprocess.run(
            [
                "powershell",
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                str(script),
                "-IpAddress",
                ip,
                "-Reason",
                "DVielle brute-force auto-block",
            ],
            check=True,
            capture_output=True,
            text=True,
            timeout=30,
            creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, "CREATE_NO_WINDOW") else 0,
        )
        return True
    except subprocess.CalledProcessError as exc:
        logger.error("Failed to block IP %s: %s", ip, exc.stderr)
        return False


class AttackMonitor:
    def __init__(
        self,
        store: AgentStore,
        config: dict[str, Any],
        scripts_dir: Path,
    ) -> None:
        self.store = store
        self.config = config
        self.scripts_dir = scripts_dir
        self.block_after = int(config.get("thresholds", {}).get("failed_logon_block_after", 5))
        self.window_minutes = int(config.get("thresholds", {}).get("failed_logon_window_minutes", 15))

    def run(self, enable_auto_block: bool = False) -> list[AttackAlert]:
        global _last_check
        now = datetime.now(timezone.utc)
        since = _last_check or (now - timedelta(minutes=5))
        _last_check = now

        if not IS_WINDOWS:
            logger.debug("Attack monitor skipped (non-Windows)")
            return []

        alerts: list[AttackAlert] = []
        for event in _query_security_events(since):
            source_ip = event.get("source_ip")
            if not source_ip or source_ip in ("127.0.0.1", "::1", "-"):
                continue

            event_id = int(event["event_id"])  # type: ignore[arg-type]
            count = self.store.record_failed_logon(
                event_id=event_id,
                source_ip=str(source_ip),
                username=event.get("username"),  # type: ignore[arg-type]
                workstation=event.get("workstation"),  # type: ignore[arg-type]
                window_minutes=self.window_minutes,
            )

            should_block = count >= self.block_after and not self.store.is_ip_blocked(str(source_ip))
            alert = AttackAlert(
                source_ip=str(source_ip),
                username=event.get("username"),  # type: ignore[arg-type]
                event_id=event_id,
                attempt_count=count,
                should_block=should_block and enable_auto_block,
            )
            alerts.append(alert)

            severity = "CRITICAL" if should_block else "WARNING"
            self.store.log_event(
                "attacks",
                severity,
                f"Failed logon from {source_ip} (count={count}, event={event_id})",
                {"username": event.get("username"), "count": count},
            )
            logger.warning(
                "Failed logon: IP=%s user=%s count=%s event=%s",
                source_ip,
                event.get("username"),
                count,
                event_id,
            )

            if should_block and enable_auto_block:
                if _block_ip_powershell(str(source_ip), self.scripts_dir):
                    self.store.block_ip(str(source_ip), f"Brute force: {count} failed logons")
                    self.store.log_event(
                        "attacks",
                        "CRITICAL",
                        f"Blocked IP {source_ip} after {count} failed logons",
                        None,
                    )

        return alerts

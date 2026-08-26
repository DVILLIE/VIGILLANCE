"""Attack detection via Windows Security event log (4625, 4776) — P0.3 / P0.6.

Microsoft Learn Event 4776: Source Workstation is a *computer name*, not an IP.
Never feed 4776 workstation into block-ip.

Cursor: EventRecordID primary; advance only after successful process.
No silent truncation — report COLLECTION_DEGRADED.
"""

from __future__ import annotations

import logging
import subprocess
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from agent.net_identity import looks_like_ipv4_or_ipv6
from agent.policy import ActionKind, Authorization, PolicyCortex
from agent.policy.levels import LEVEL_RECOMMEND
from agent.store.db import AgentStore
from agent.utils import IS_WINDOWS

logger = logging.getLogger("dvielle.attacks")

CURSOR_KEY = "security_event_record_id"
QUERY_BATCH = 200


@dataclass
class AttackAlert:
    source_ip: str | None
    source_host: str | None
    username: str | None
    event_id: int
    attempt_count: int
    should_block: bool
    record_id: int | None = None
    collection_degraded: bool = False


def _query_security_events(
    *,
    after_record_id: int,
    since: datetime,
) -> tuple[list[dict[str, Any]], bool, str | None]:
    """Return (events, degraded, error).

    degraded=True if we hit the batch cap (possible truncation).
    On query failure: empty list + error string (caller must NOT advance cursor).
    """
    if not IS_WINDOWS:
        return [], False, None

    since_str = since.strftime("%Y-%m-%dT%H:%M:%S")
    # Emit: EventID|RecordID|IpAddress|TargetUserName|WorkstationName|Workstation(4776)
    ps_script = f"""
$ErrorActionPreference = 'Stop'
try {{
  $events = @(Get-WinEvent -FilterHashtable @{{
    LogName = 'Security'
    Id = 4625, 4776
    StartTime = [datetime]'{since_str}'
  }} -ErrorAction Stop | Sort-Object RecordId)
}} catch {{
  Write-Output 'QUERY_FAIL|'
  exit 0
}}
$n = 0
foreach ($e in $events) {{
  if ($e.RecordId -le {int(after_record_id)}) {{ continue }}
  $xml = [xml]$e.ToXml()
  $ip = ($xml.Event.EventData.Data | Where-Object {{ $_.Name -eq 'IpAddress' }}).'#text'
  $user = ($xml.Event.EventData.Data | Where-Object {{ $_.Name -eq 'TargetUserName' }}).'#text'
  if (-not $user) {{ $user = ($xml.Event.EventData.Data | Where-Object {{ $_.Name -eq 'TargetUserName' }}).'#text' }}
  $wsName = ($xml.Event.EventData.Data | Where-Object {{ $_.Name -eq 'WorkstationName' }}).'#text'
  $ws = ($xml.Event.EventData.Data | Where-Object {{ $_.Name -eq 'Workstation' }}).'#text'
  Write-Output "$($e.Id)|$($e.RecordId)|$ip|$user|$wsName|$ws"
  $n++
  if ($n -ge {QUERY_BATCH}) {{
    Write-Output 'TRUNCATED|'
    break
  }}
}}
"""
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_script],
            capture_output=True,
            text=True,
            timeout=45,
            creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, "CREATE_NO_WINDOW") else 0,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
        logger.warning("Event log query failed: %s", exc)
        return [], True, str(exc)

    events: list[dict[str, Any]] = []
    degraded = False
    for line in result.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        if line.startswith("QUERY_FAIL"):
            return [], True, "Get-WinEvent failed"
        if line.startswith("TRUNCATED"):
            degraded = True
            continue
        parts = line.split("|")
        if len(parts) < 3:
            continue
        try:
            event_id = int(parts[0])
            record_id = int(parts[1])
        except ValueError:
            continue
        ip_raw = parts[2] if len(parts) > 2 and parts[2] not in ("-", "") else None
        username = parts[3] if len(parts) > 3 and parts[3] not in ("-", "") else None
        ws_name = parts[4] if len(parts) > 4 and parts[4] not in ("-", "") else None
        ws_4776 = parts[5] if len(parts) > 5 and parts[5] not in ("-", "") else None

        source_ip: str | None = None
        source_host: str | None = None
        if event_id == 4625:
            if looks_like_ipv4_or_ipv6(ip_raw):
                source_ip = ip_raw
            source_host = ws_name
        elif event_id == 4776:
            # Microsoft: Workstation field is computer name — never treat as IP
            source_ip = None
            source_host = ws_4776 or ws_name
        else:
            continue

        events.append(
            {
                "event_id": event_id,
                "record_id": record_id,
                "source_ip": source_ip,
                "source_host": source_host,
                "username": username,
            }
        )
    return events, degraded, None


class AttackMonitor:
    def __init__(
        self,
        store: AgentStore,
        config: dict[str, Any],
        scripts_dir: Path,
        cortex: PolicyCortex | None = None,
    ) -> None:
        self.store = store
        self.config = config
        self.scripts_dir = scripts_dir
        self.cortex = cortex
        self.block_after = int(config.get("thresholds", {}).get("failed_logon_block_after", 5))
        self.window_minutes = int(config.get("thresholds", {}).get("failed_logon_window_minutes", 15))

    def run(self, enable_auto_block: bool = False) -> list[AttackAlert]:
        if not IS_WINDOWS:
            logger.debug("Attack monitor skipped (non-Windows)")
            return []

        last_rid = self.store.get_cursor(CURSOR_KEY, default=0)
        since = datetime.now(timezone.utc) - timedelta(hours=24)
        events, degraded, err = _query_security_events(after_record_id=last_rid, since=since)

        if err:
            self.store.log_event(
                "attacks",
                "WARNING",
                f"COLLECTION_DEGRADED: security log query failed — cursor not advanced ({err})",
                {"cursor": last_rid},
            )
            return [
                AttackAlert(
                    source_ip=None,
                    source_host=None,
                    username=None,
                    event_id=0,
                    attempt_count=0,
                    should_block=False,
                    collection_degraded=True,
                )
            ]

        if degraded:
            self.store.log_event(
                "attacks",
                "WARNING",
                f"COLLECTION_DEGRADED: processed batch capped at {QUERY_BATCH}; visibility incomplete",
                {"cursor": last_rid},
            )

        alerts: list[AttackAlert] = []
        max_rid = last_rid
        for event in events:
            rid = int(event["record_id"])
            max_rid = max(max_rid, rid)
            event_id = int(event["event_id"])
            source_ip = event.get("source_ip")
            source_host = event.get("source_host")
            username = event.get("username")

            # Rolling window key: prefer IP for 4625; host for 4776 (correlation only)
            key = source_ip or (f"host:{source_host}" if source_host else "unknown")
            count = self.store.record_failed_logon(
                event_id=event_id,
                source_ip=key if source_ip else f"host:{source_host or 'unknown'}",
                username=username,  # type: ignore[arg-type]
                workstation=source_host,  # type: ignore[arg-type]
                window_minutes=self.window_minutes,
            )

            # P0.3: never IP-block from 4776 or non-IP keys
            can_block = (
                event_id == 4625
                and looks_like_ipv4_or_ipv6(source_ip)
                and count >= self.block_after
                and not self.store.is_ip_blocked(str(source_ip))
            )
            # P0: modules do not mutate; Level-2 RECOMMEND only. BLOCK_IP needs L4+USER_APPROVED.
            should_block = False
            if can_block and enable_auto_block:
                decision_id = None
                if self.cortex is not None:
                    conf = min(0.50 + (count - self.block_after) * 0.05, 0.85)
                    decision = self.cortex.issue(
                        action=ActionKind.RECOMMEND,
                        action_level=LEVEL_RECOMMEND,
                        confidence=conf,
                        evidence_summary=[
                            f"Event 4625 failed logons count={count} from {source_ip}",
                            "Suggested future action: BLOCK_IP at Level 4 with USER_APPROVED",
                        ],
                        authorization=Authorization.AUTOMATIC_POLICY,
                        policy_ref="attacks_recommend_block",
                        target=str(source_ip),
                        initiator="attacks",
                        reversible=False,
                        details={
                            "event_id": event_id,
                            "count": count,
                            "record_id": rid,
                            "suggested_action": ActionKind.BLOCK_IP.value,
                        },
                    )
                    if decision is not None:
                        decision_id = decision.decision_id
                self.store.log_event(
                    "attacks",
                    "WARNING",
                    f"RECOMMEND block IP {source_ip} (count={count}) — L2 only; no mutation",
                    {
                        "event_id": event_id,
                        "count": count,
                        "record_id": rid,
                        "decision_id": decision_id,
                    },
                )

            alert = AttackAlert(
                source_ip=source_ip if isinstance(source_ip, str) else None,
                source_host=source_host if isinstance(source_host, str) else None,
                username=username if isinstance(username, str) else None,
                event_id=event_id,
                attempt_count=count,
                should_block=should_block,
                record_id=rid,
                collection_degraded=degraded,
            )
            alerts.append(alert)

            severity = "WARNING"
            self.store.log_event(
                "attacks",
                severity,
                f"Failed auth event={event_id} ip={source_ip} host={source_host} count={count}",
                {
                    "username": username,
                    "count": count,
                    "record_id": rid,
                    "source_ip": source_ip,
                    "source_host": source_host,
                },
            )
            logger.warning(
                "Failed auth: event=%s ip=%s host=%s user=%s count=%s rid=%s",
                event_id,
                source_ip,
                source_host,
                username,
                count,
                rid,
            )

        # Advance cursor only after successful process/persist
        if max_rid > last_rid:
            self.store.set_cursor(CURSOR_KEY, max_rid)

        return alerts

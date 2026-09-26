"""Attack detection via Windows Security event log (4625, 4776) — P0.3 / P0.6.

Microsoft Learn Event 4776: Source Workstation is a *computer name*, not an IP.
Never feed 4776 workstation into block-ip.

Cursor: EventRecordID primary; advance only after successful process.
No silent truncation — report COLLECTION_DEGRADED.
"""

from __future__ import annotations

import logging
import json
import ipaddress
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from agent.net_identity import looks_like_ipv4_or_ipv6
from agent.policy import ActionKind, Authorization, PolicyCortex
from agent.policy.levels import LEVEL_RECOMMEND
from agent.store.db import AgentStore
from agent.utils import IS_WINDOWS, run_powershell

logger = logging.getLogger("dvielle.attacks")

CURSOR_KEY = "security_event_record_id"
QUERY_BATCH = 200

# Per-source cooldown so a sustained brute-force issues one recommendation per
# window, not one per event/pulse (keeps the WHY ledger legible).
_recommended_at: dict[str, datetime] = {}
# ACCESS_DENIED is a capability gap, not a flaky query — report once per process.
_access_denied_reported: bool = False


def _recommend_cooldown_ok(ip: str, window_minutes: int) -> bool:
    now = datetime.now(timezone.utc)
    for key, when in list(_recommended_at.items()):
        if now - when >= timedelta(minutes=window_minutes):
            _recommended_at.pop(key, None)
    if len(_recommended_at) >= 1024 and ip not in _recommended_at:
        return False
    last = _recommended_at.get(ip)
    if last is not None and (now - last) < timedelta(minutes=window_minutes):
        return False
    _recommended_at[ip] = now
    return True


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


class SecurityEvents(list[dict[str, Any]]):
    """Event rows with a checkpoint describing the bounded source-log snapshot."""

    next_record_id: int | None = None
    next_timestamp: str | None = None
    reset: bool = False
    gap: bool = False


def _query_security_events(
    *, after_record_id: int, since: datetime, after_timestamp: str | None = None,
) -> tuple[list[dict[str, Any]], bool, str | None]:
    if not IS_WINDOWS:
        return [], False, None
    since_str = since.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000000Z")
    # Timestamp is parsed first, so persisted text cannot become PowerShell code.
    cursor_ts = (datetime.fromisoformat(after_timestamp.replace("Z", "+00:00"))
                 .astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
                 if after_timestamp else "")
    ps_script = f"""
$ErrorActionPreference = 'Stop'
try {{
  $latest = Get-WinEvent -LogName Security -MaxEvents 1 -ErrorAction Stop
  $oldest = Get-WinEvent -LogName Security -Oldest -MaxEvents 1 -ErrorAction Stop
}} catch {{
  $fq = [string]$_.FullyQualifiedErrorId
  if ($_.Exception -is [System.UnauthorizedAccessException] -or $fq -like '*UnauthorizedAccess*') {{
    Write-Output 'ACCESS_DENIED|'
  }} elseif ($fq -like 'NoMatchingEventsFound*') {{
    # A cleared, currently empty log has no usable checkpoint; retain old state
    # so the next nonempty snapshot can identify the reset.
    Write-Output 'NO_EVENTS|'
  }} else {{ Write-Output 'QUERY_FAIL|' }}
  exit 0
}}
$cursor = [long]{int(after_record_id)}
$reset = $cursor -gt $latest.RecordId
$gap = $cursor -gt 0 -and $oldest.RecordId -gt ($cursor + 1)
if (-not $reset -and $cursor -gt 0 -and '{cursor_ts}' -and $oldest.RecordId -le $cursor) {{
  try {{
    $prior = Get-WinEvent -LogName Security -FilterXPath "*[System[EventRecordID=$cursor]]" -MaxEvents 1 -ErrorAction Stop
    $reset = $prior.TimeCreated.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.ffffff') -ne ([datetime]::Parse('{cursor_ts}').ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.ffffff'))
  }} catch {{
    Write-Output 'QUERY_FAIL|'
    exit 0
  }}
}}
if ($reset) {{ $cursor = 0 }}
# Filter at the source, fetch OLDEST first, and read one extra row to detect backlog.
# Once a cursor exists, do not apply the startup time horizon: downtime must not
# silently discard retained events. Fix the upper bound to this source snapshot.
$timeFilter = if ($cursor -eq 0) {{ " and TimeCreated[@SystemTime >= '{since_str}']" }} else {{ '' }}
$xpath = "*[System[(EventID=4625 or EventID=4776) and EventRecordID > $cursor and EventRecordID <= $($latest.RecordId)$timeFilter]]"
try {{
  $events = @(Get-WinEvent -LogName Security -FilterXPath $xpath -Oldest -MaxEvents {QUERY_BATCH + 1} -ErrorAction Stop)
}} catch {{
  $fq = [string]$_.FullyQualifiedErrorId
  if ($fq -like 'NoMatchingEventsFound*') {{ $events = @() }} else {{
    Write-Output 'QUERY_FAIL|'
    exit 0
  }}
}}
$n = 0
$nextId = $latest.RecordId
$nextTime = $latest.TimeCreated.ToUniversalTime().ToString('o')
foreach ($e in ($events | Select-Object -First {QUERY_BATCH})) {{
  $xml = [xml]$e.ToXml()
  $data = @{{}}
  foreach ($d in $xml.Event.EventData.Data) {{ $data[[string]$d.Name] = [string]$d.'#text' }}
  @{{event_id=$e.Id; record_id=$e.RecordId; timestamp=$e.TimeCreated.ToUniversalTime().ToString('o');
    ip=$data['IpAddress']; username=$data['TargetUserName']; workstation_name=$data['WorkstationName'];
    workstation=$data['Workstation']; status=$data['Status']}} | ConvertTo-Json -Compress
  $n++
  if ($events.Count -gt {QUERY_BATCH}) {{ $nextId = $e.RecordId; $nextTime = $e.TimeCreated.ToUniversalTime().ToString('o') }}
}}
@{{checkpoint=$true; record_id=$nextId; timestamp=$nextTime; reset=[bool]$reset; gap=[bool]$gap}} | ConvertTo-Json -Compress
if ($events.Count -gt {QUERY_BATCH}) {{ Write-Output 'TRUNCATED|' }}
"""
    stdout, timed_out = run_powershell(ps_script, timeout=45)
    if stdout is None:
        return [], True, "query_failed_or_timeout"
    return _parse_security_query_stdout(stdout, timed_out=timed_out)


def _parse_security_query_stdout(
    stdout: str, *, timed_out: bool = False,
) -> tuple[list[dict[str, Any]], bool, str | None]:
    """Parse JSON lines without losing source event time or delimiter-bearing names."""
    events = SecurityEvents()
    if timed_out:
        return events, True, "query_failed_or_timeout"
    degraded = False
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        if line == "NO_EVENTS|":
            return events, False, None
        if line == "ACCESS_DENIED|":
            return SecurityEvents(), True, "access_denied"
        if line == "QUERY_FAIL|":
            return SecurityEvents(), True, "Get-WinEvent failed"
        if line == "TRUNCATED|":
            degraded = True
            continue
        try:
            row = json.loads(line)
            rid = int(row["record_id"])
            timestamp = str(row["timestamp"])
            stamp = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
            if stamp.tzinfo is None or rid < 1:
                raise ValueError("invalid event identity")
            if row.get("checkpoint"):
                events.next_record_id = rid
                events.next_timestamp = timestamp
                events.reset = bool(row.get("reset"))
                events.gap = bool(row.get("gap"))
                continue
            event_id = int(row["event_id"])
            if event_id not in (4625, 4776):
                raise ValueError("unexpected Security event")
            status = row.get("status") or None
            status_code = None
            if status is not None:
                try:
                    status_code = int(str(status), 16)
                except ValueError:
                    degraded = True
            if event_id == 4776 and status_code is None:
                degraded = True
            ip = row.get("ip")
            source_ip = None
            if event_id == 4625 and looks_like_ipv4_or_ipv6(ip):
                address = ipaddress.ip_address(ip.strip())
                # Windows may report the same IPv4 client as ::ffff:IPv4.
                # One client must not split its rolling count across equivalent forms.
                source_ip = str(address.ipv4_mapped or address) if isinstance(address, ipaddress.IPv6Address) else str(address)
            events.append({
                "event_id": event_id, "record_id": rid, "timestamp": timestamp,
                "status": status, "is_failure": event_id == 4625 or (status_code is not None and status_code != 0),
                "source_ip": source_ip,
                "source_host": ((row.get("workstation") or row.get("workstation_name"))
                                if event_id == 4776 else row.get("workstation_name")) or None,
                "username": row.get("username") or None,
            })
        except (ValueError, KeyError, TypeError):
            # Never acknowledge a malformed record and silently jump the cursor.
            return SecurityEvents(), True, "invalid_security_event_payload"
    if events.next_record_id is None:
        return SecurityEvents(), True, "missing_security_checkpoint"
    if any(e["record_id"] > events.next_record_id for e in events):
        return SecurityEvents(), True, "invalid_security_checkpoint"
    return events, degraded or events.gap or events.reset, None


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
        self.collection_error: str | None = None
        self.collection_degraded = False
        self.block_after = int(config.get("thresholds", {}).get("failed_logon_block_after", 5))
        self.window_minutes = int(config.get("thresholds", {}).get("failed_logon_window_minutes", 15))

    def run(self, enable_auto_block: bool = False) -> list[AttackAlert]:
        self.collection_error = None
        self.collection_degraded = False
        if not IS_WINDOWS:
            logger.debug("Attack monitor skipped (non-Windows)")
            return []

        last_rid = self.store.get_cursor(CURSOR_KEY, default=0)
        since = datetime.now(timezone.utc) - timedelta(hours=24)
        events, degraded, err = _query_security_events(
            after_record_id=last_rid, since=since,
            after_timestamp=self.store.get_cursor_timestamp(CURSOR_KEY),
        )

        if err:
            self.collection_error = err
            self.collection_degraded = True
            global _access_denied_reported
            if err == "access_denied":
                # Honest capability gap — do not cry "query failed" every pulse.
                if not _access_denied_reported:
                    _access_denied_reported = True
                    self.store.log_event(
                        "attacks",
                        "WARNING",
                        "COLLECTION_LIMITED: Security log unreadable without elevation "
                        "(Event Log Readers / admin) — brute-force detection unavailable",
                        {"cursor": last_rid, "error": err},
                    )
                else:
                    logger.debug("Security log still unreadable (access_denied); suppressed repeat")
            else:
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
            self.collection_degraded = True
            self.store.log_event(
                "attacks",
                "WARNING",
                "COLLECTION_DEGRADED: backlog, log reset/gap, or incomplete event fields; visibility incomplete",
                {"cursor": last_rid},
            )

        # The source cursor advances in the SAME transaction as durable evidence.
        # Recommendations are derived afterwards; a crash cannot double-count rows.
        next_id = getattr(events, "next_record_id", None)
        if next_id is not None:
            events = self.store.ingest_security_events(
                events, cursor_key=CURSOR_KEY, next_record_id=next_id,
                next_timestamp=getattr(events, "next_timestamp", None),
            )
        alerts: list[AttackAlert] = []
        if degraded and not events:
            alerts.append(AttackAlert(None, None, None, 0, 0, False, collection_degraded=True))
        counts: dict[str, int] = {}
        for event in events:
            rid = int(event["record_id"])
            event_id = int(event["event_id"])
            source_ip = event.get("source_ip")
            source_host = event.get("source_host")
            username = event.get("username")

            # Rolling window key: prefer IP for 4625; host for 4776 (correlation only)
            key = source_ip or f"host:{source_host or 'unknown'}"
            if key not in counts:
                counts[key] = self.store.get_failed_logon_count(key, self.window_minutes)
            count = counts[key]

            # P0.3: never IP-block from 4776 or non-IP keys
            can_block = (
                event_id == 4625
                and looks_like_ipv4_or_ipv6(source_ip)
                and count >= self.block_after
                and not self.store.is_ip_blocked(str(source_ip))
            )
            # P0: modules do not mutate; Level-2 RECOMMEND only. BLOCK_IP needs L4+USER_APPROVED.
            # Issue on the NORMAL path (independent of enable_auto_block) so the burst
            # leaves a durable WHY evidence entry; per-source cooldown prevents spam.
            should_block = False
            if can_block and self.cortex is not None and _recommend_cooldown_ok(
                str(source_ip), self.window_minutes
            ):
                conf = min(0.50 + (count - self.block_after) * 0.05, 0.85)
                decision = self.cortex.issue(
                    action=ActionKind.RECOMMEND,
                    action_level=LEVEL_RECOMMEND,
                    confidence=conf,
                    evidence_summary=[
                        f"Event 4625 failed logons count={count} from {source_ip} in {self.window_minutes}m window",
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
                        "event_timestamp": event["timestamp"],
                        "status": event.get("status"),
                        "suggested_action": ActionKind.BLOCK_IP.value,
                    },
                )
                decision_id = decision.decision_id if decision is not None else None
                self.store.log_event(
                    "attacks",
                    "WARNING",
                    f"RECOMMEND review IP {source_ip} (count={count}) — L2 only; no mutation",
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
                    "event_timestamp": event["timestamp"],
                    "status": event.get("status"),
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

        return alerts

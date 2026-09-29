"""Pure, testable presentation rules for shared observations and freshness."""
from __future__ import annotations

from datetime import datetime, timezone
import math
from typing import Any


def age_seconds(stamp: str | None, now: datetime | None = None) -> float | None:
    try:
        value = datetime.fromisoformat(stamp)
        if value.tzinfo is None:
            return None
        age = ((now or datetime.now(timezone.utc)) - value).total_seconds()
        return age if age >= 0 else None
    except (TypeError, ValueError):
        return None


def snapshot_fresh(data: dict | None, now: datetime | None = None) -> bool:
    runtime = (data or {}).get("runtime") or {}
    age = age_seconds(runtime.get("heartbeat_at"), now)
    interval = cadence_seconds(data, "heartbeat", 5)
    return runtime.get("state") == "running" and age is not None and interval is not None and age < max(30, interval * 3)


def cadence_seconds(data: dict | None, name: str, default: float = 60) -> float | None:
    try:
        value = float((((data or {}).get("collectors") or {}).get(name) or {}).get("interval_seconds", default))
        return value if math.isfinite(value) and value > 0 else None
    except (TypeError, ValueError):
        return None


def collector_state(data: dict | None, name: str, now: datetime | None = None) -> str:
    if not snapshot_fresh(data, now):
        return "unavailable" if not data else "stale"
    collector = (data.get("collectors") or {}).get(name) or {}
    status = collector.get("status", "pending")
    if status in {"error", "partial", "deferred", "pending", "disabled"}:
        return status
    age = age_seconds(collector.get("last_success_at"), now)
    if age is None:
        return "pending"
    interval = cadence_seconds(data, name)
    if interval is None:
        return "unknown"
    threshold = max(30, interval * 2)
    return "stale" if age > threshold else status


def section_current(data: dict | None, name: str, stamp: str | None = None) -> bool:
    if not snapshot_fresh(data):
        return False
    if name == "heartbeat":
        age = age_seconds(stamp)
        interval = cadence_seconds(data, "heartbeat", 5)
        return age is not None and interval is not None and age < max(30, interval * 3)
    return collector_state(data, name) in {"ok", "running"}


def failed_logon_copy(rows: list[dict[str, Any]] | None, coverage: str) -> str:
    """Empty or stale auth history must not claim that nobody is guessing passwords."""
    rows = list(rows or [])
    if coverage != "ok":
        header = (
            f"Failed-logon coverage is {coverage}. "
            "Password-guessing activity is not known from this view. "
            "An empty list is not evidence of safety."
        )
        if not rows:
            return header
        lines = [header, "", "Retained rows (not a current reading):"]
        lines.extend(_format_logon_rows(rows))
        return "\n".join(lines)
    if not rows:
        return (
            "No failed logons were stored in the covered window. "
            "This is only the events DVielle recorded."
        )
    return "\n".join(_format_logon_rows(rows))


def _format_logon_rows(rows: list[dict[str, Any]]) -> list[str]:
    lines = ["SOURCE IP           COUNT  USER                 EVENT  WHEN", "-" * 72]
    for row in rows:
        lines.append(
            f"{str(row.get('source_ip'))[:18]:18}  {int(row.get('count') or 0):5}  "
            f"{str(row.get('username') or '-'):20}  {row.get('event_id')}  {str(row.get('ts'))[:19]}"
        )
    return lines


def why_measurement_line(data: dict | None) -> str:
    """Label retained vitals with freshness. Never call a stopped snapshot current."""
    if not snapshot_fresh(data):
        if not data:
            return "Measurements unavailable. Nothing shown here is a current reading."
        return "Measurements stale. Retained numbers are not a current reading."
    mem = (data or {}).get("memory") or {}
    system = (data or {}).get("system") or {}
    return (
        "Latest heartbeat:  "
        f"commit {mem.get('commit_percent', '—')}%  ·  "
        f"{mem.get('avail_phys_mb', '—')} MB free  ·  "
        f"cpu {system.get('cpu_percent', '—')}%"
    )


_MATRIX_LABELS = (
    ("asr", "ASR"),
    ("cfa", "CFA"),
    ("firewall", "Firewall"),
    ("smart_app_control", "SAC"),
    ("windows_sandbox", "Sandbox"),
    ("app_control_authoring", "AppControl"),
)


def prevention_evidence_line(data: dict | None) -> str:
    """Compact prevention evidence for the console strip.

    A partial, stale, or failed check is labeled incomplete. The line does not
    say the machine is clear.
    """
    if not data:
        return "Prevention evidence unavailable."
    if not snapshot_fresh(data):
        return "Prevention evidence stale. Retained status is not a current reading."
    security = data.get("security") if isinstance(data.get("security"), dict) else {}
    capability = data.get("capability") if isinstance(data.get("capability"), dict) else {}
    matrix = security.get("edition_matrix") if isinstance(security.get("edition_matrix"), dict) else {}
    features = matrix.get("features") if isinstance(matrix.get("features"), dict) else capability.get("feature_matrix")
    if not isinstance(features, dict):
        features = {}
    health = security.get("defender_health") if isinstance(security.get("defender_health"), dict) else {}
    maps = security.get("maps") if isinstance(security.get("maps"), dict) else {}
    sku = matrix.get("sku") or capability.get("edition_sku") or "Unknown"
    state = collector_state(data, "security")
    age = health.get("signature_age_days")
    age_text = f"{age}d" if isinstance(age, int) and not isinstance(age, bool) else "UNKNOWN"
    parts = [
        f"SKU {sku}",
        f"Defender collection {state}",
        f"mode {health.get('am_running_mode') or 'UNKNOWN'}",
        f"realtime {health.get('realtime') or 'UNKNOWN'}",
        f"signature age {age_text}",
        f"signature {health.get('signature_freshness') or 'UNKNOWN'}",
        "engine freshness UNKNOWN",
        f"MAPS {maps.get('result') or 'unavailable'}",
    ]
    mode = matrix.get("smart_app_control_mode") or capability.get("smart_app_control_mode")
    for key, label in _MATRIX_LABELS:
        parts.append(f"{label} {features.get(key) or 'UNKNOWN'}")
    if mode:
        parts.append(f"SAC mode {mode}")
    prevention = security.get("prevention") if isinstance(security.get("prevention"), dict) else None
    recovery = security.get("recovery") if isinstance(security.get("recovery"), dict) else None
    if prevention:
        parts.append(f"ASR read {prevention.get('coverage') or 'unknown'}")
        parts.append(f"CFA {prevention.get('cfa_mode_name') or 'Unread'}")
        parts.append("CFA modification shield")
    if recovery:
        parts.append(f"BackupConfigured {recovery.get('backup_configured') or 'unknown'}")
        parts.append(f"BackupFresh {recovery.get('backup_fresh') or 'unknown'}")
        parts.append(f"RestoreVerified {recovery.get('restore_verified') or 'unknown'}")
    firewall_assist = security.get("firewall_assist") if isinstance(security.get("firewall_assist"), dict) else None
    if firewall_assist:
        parts.append(f"Firewall rules {firewall_assist.get('coverage') or 'unknown'}")
        parts.append("not leakproof")
    sandbox = security.get("sandbox") if isinstance(security.get("sandbox"), dict) else None
    if sandbox:
        parts.append(f"Sandbox offer {sandbox.get('offer') or 'UNKNOWN'}")
        if sandbox.get("running") is True:
            parts.append(f"Sandbox session {sandbox.get('isolation') or 'UNKNOWN'}")
        else:
            parts.append("no sandbox session")
    update = security.get("update") if isinstance(security.get("update"), dict) else None
    if update:
        parts.append(f"TUF {update.get('last_result') or 'UNKNOWN'}")
        version = update.get("installed_version") or "UNKNOWN"
        parts.append(f"package {version}")
        if update.get("privileged_auto_update") is False:
            parts.append("privileged auto-update off")
        else:
            parts.append("privileged auto-update not off")
        parts.append(f"live binary {update.get('live_binary_attestation') or 'UNCHECKED'}")
    privacy_clause = privacy_evidence_clause(data)
    if privacy_clause:
        parts.append(privacy_clause)
    line = " · ".join(str(part) for part in parts)
    healthy = (
        state == "ok"
        and health.get("all_clear") is True
        and maps.get("result") == "pass"
    )
    if not healthy:
        line += " · coverage incomplete"
    return line


def privacy_evidence_clause(data: dict | None) -> str:
    """Observed privacy settings versus unknown ones, plus intel availability.

    A missing feed is the exact label ``intel: unavailable``. An empty match
    list is not added unless a comparison actually ran.
    """
    privacy = (data or {}).get("privacy") if isinstance((data or {}).get("privacy"), dict) else {}
    parts: list[str] = []
    intel = privacy.get("intel") if isinstance(privacy.get("intel"), dict) else None
    if intel is not None:
        label = str(intel.get("intel") or "unavailable")
        if label == "unavailable":
            parts.append("intel: unavailable")
        else:
            kev_count = (intel.get("kev") or {}).get("count") if isinstance(intel.get("kev"), dict) else None
            osv_count = (intel.get("osv") or {}).get("count") if isinstance(intel.get("osv"), dict) else None
            kev_text = str(kev_count) if isinstance(kev_count, int) and not isinstance(kev_count, bool) else "unknown"
            osv_text = str(osv_count) if isinstance(osv_count, int) and not isinstance(osv_count, bool) else "unknown"
            matches = intel.get("matches") if isinstance(intel.get("matches"), dict) else {}
            parts.append(f"intel: {label} kev {kev_text} osv {osv_text}")
            parts.append(f"matches {matches.get('state') or 'unavailable'}")
    assistant = privacy.get("assistant") if isinstance(privacy.get("assistant"), dict) else None
    if assistant is not None:
        observed = assistant.get("observed") if isinstance(assistant.get("observed"), list) else []
        unknown = assistant.get("unknown") if isinstance(assistant.get("unknown"), list) else []
        if observed:
            bits = []
            for row in observed:
                if isinstance(row, dict):
                    bits.append(f"{row.get('name')} {row.get('meaning') or row.get('value')}")
            parts.append("observed " + ", ".join(bits))
        else:
            parts.append("observed none")
        parts.append("unknown " + (", ".join(str(item) for item in unknown) if unknown else "none"))
        if assistant.get("security_off"):
            parts.append(f"Security=Off {assistant.get('security_off')}")
    return " · ".join(parts)


def activity_summary(data: dict | None) -> str:
    if not snapshot_fresh(data):
        return "Monitoring observations unavailable or stale"
    counts: dict[str, int] = {}
    for name in (data.get("collectors") or {}):
        state = collector_state(data, name)
        counts[state] = counts.get(state, 0) + 1
    return "Collectors: " + (" · ".join(f"{count} {state}" for state, count in sorted(counts.items())) or "waiting")


def chat_stats(data: dict | None, running: bool, cycles: int) -> dict[str, Any]:
    data = data or {}
    mem, system, network = (data.get(k) or {} for k in ("memory", "system", "network"))
    ram_ok = section_current(data, "heartbeat", mem.get("sampled_at"))
    cpu_ok = section_current(data, "heartbeat", system.get("cpu_sampled_at"))
    disk_ok = section_current(data, "disk")
    net_ok = section_current(data, "network_info")
    return {
        "agent_started": running and snapshot_fresh(data), "agent_cycles": cycles,
        "observation_status": activity_summary(data),
        "cpu_percent": system.get("cpu_percent") if cpu_ok else None,
        "ram_percent": mem.get("memory_load_percent") if ram_ok else None,
        "ram_available_gb": mem.get("avail_phys_mb") / 1024 if ram_ok and mem.get("avail_phys_mb") is not None else None,
        "commit_percent": mem.get("commit_percent") if ram_ok else None,
        "disk_percent_used": system.get("disk_percent") if disk_ok else None,
        "disk_free_gb": system.get("disk_free_gb") if disk_ok else None,
        "hostname": network.get("hostname") if net_ok else None,
        "local_ips": network.get("local_ips", []) if net_ok else [],
        "public_ip": network.get("public_ip") if net_ok else None,
        "vpn_active": network.get("vpn_active") if net_ok else None,
        "vpn_name": network.get("vpn_adapter") if net_ok else None,
        "vpn_ip": network.get("vpn_ip") if net_ok else None,
        "dns_servers": network.get("dns_servers", []) if net_ok else [],
        "gateway": network.get("gateway") if net_ok else None,
    }

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

"""Build live screen stats context for chat."""

from __future__ import annotations

from typing import Any
import math


def gather_stats_context(agent_started: bool = False, cycle_count: int = 0) -> dict[str, Any]:
    """Without an owner-supplied snapshot, chat has no current observations.

    Opening chat must not create another network or security collector.
    """
    return {
        "agent_started": False,
        "agent_cycles": cycle_count,
        "observation_status": "Current shared observations were not supplied",
        "cpu_percent": None, "ram_percent": None, "ram_available_gb": None,
        "commit_percent": None, "disk_percent_used": None, "disk_free_gb": None,
        "hostname": None, "local_ips": [], "public_ip": None, "vpn_active": None,
        "vpn_name": None, "vpn_ip": None, "dns_servers": [], "gateway": None,
    }


def sensitive_values(stats: dict[str, Any]) -> list[str]:
    """Concrete network-identity strings to scrub before any off-box (cloud) send.

    These are the fields that fingerprint the machine/network — hostname, all
    local IPs, public IP, VPN adapter + tunnel IP, DNS servers, gateway. Returned
    longest-first so replacement never partially clobbers a shorter substring.
    """
    values: list[str] = []

    def _add(v: Any) -> None:
        if isinstance(v, str) and v.strip() and v.strip().lower() not in ("unknown", "none"):
            values.append(v.strip())

    _add(stats.get("hostname"))
    _add(stats.get("public_ip"))
    _add(stats.get("vpn_ip"))
    _add(stats.get("vpn_name"))
    _add(stats.get("gateway"))
    for ip in stats.get("local_ips") or []:
        _add(ip)
    for dns in stats.get("dns_servers") or []:
        _add(dns)
    return sorted(set(values), key=len, reverse=True)


def number(value: Any, digits: int = 0) -> str:
    return f"{value:.{digits}f}" if isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value) else "unavailable"


def vpn_observation(stats: dict[str, Any]) -> str:
    if stats.get("vpn_active") is True:
        return f"VPN-like adapter is up ({stats.get('vpn_name') or 'name unavailable'}), adapter IP {stats.get('vpn_ip') or 'unavailable'}. Traffic routing and encryption are unverified."
    if stats.get("vpn_active") is False:
        return "No VPN-like adapter detected. This does not establish whether traffic uses a VPN or a direct connection."
    return "VPN adapter observation is unavailable or stale. Traffic routing and encryption are unverified."


def format_stats_block(stats: dict[str, Any]) -> str:
    agent = "running with a current heartbeat" if stats.get("agent_started") else "not currently verified as running"
    return (
        "OBSERVED STATS (unavailable means unknown, never zero):\n"
        f"- Vigilance agent: {agent} ({stats.get('agent_cycles', 0)} cycles)\n"
        f"- Coverage: {stats.get('observation_status', 'Not supplied')}\n"
        f"- CPU percent: {number(stats.get('cpu_percent'))}\n"
        f"- RAM percent: {number(stats.get('ram_percent'))}; available GB: {number(stats.get('ram_available_gb'), 1)}; commit percent: {number(stats.get('commit_percent'))}\n"
        f"- Disk used percent: {number(stats.get('disk_percent_used'))}; free GB: {number(stats.get('disk_free_gb'), 1)}\n"
        f"- Host: {stats.get('hostname') or 'unavailable'}\n"
        f"- Local IP(s): {', '.join(stats.get('local_ips') or ['unknown'])}\n"
        f"- Public IP: {stats.get('public_ip') or 'unknown'}\n"
        f"- {vpn_observation(stats)}\n"
        f"- DNS: {', '.join(stats.get('dns_servers') or ['unknown'])}\n"
        f"- Gateway: {stats.get('gateway') or 'unknown'}"
    )

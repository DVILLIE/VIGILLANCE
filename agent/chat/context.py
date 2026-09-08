"""Build live screen stats context for chat."""

from __future__ import annotations

import sys
from typing import Any

import psutil

from agent.modules.network_info import collect_network_snapshot


def gather_stats_context(agent_started: bool = False, cycle_count: int = 0) -> dict[str, Any]:
    mem = psutil.virtual_memory()
    try:
        disk = psutil.disk_usage("C:\\" if sys.platform == "win32" else "/")
    except Exception:
        disk = psutil.disk_usage("/")

    net = collect_network_snapshot()
    cpu = psutil.cpu_percent(interval=0.1)

    return {
        "agent_started": agent_started,
        "agent_cycles": cycle_count,
        "cpu_percent": round(cpu, 1),
        "ram_percent": round(mem.percent, 1),
        "ram_available_gb": round(mem.available / (1024**3), 2),
        "disk_percent_used": round(disk.percent, 1),
        "disk_free_gb": round(disk.free / (1024**3), 2),
        "hostname": net.hostname,
        "local_ips": net.local_ips,
        "public_ip": net.public_ip,
        "vpn_active": net.vpn_active,
        "vpn_name": net.vpn_adapter,
        "vpn_ip": net.vpn_ip,
        "dns_servers": net.dns_servers,
        "gateway": net.gateway,
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


def format_stats_block(stats: dict[str, Any]) -> str:
    vpn_line = (
        f"VPN ON ({stats.get('vpn_name')}) tunnel IP {stats.get('vpn_ip')}"
        if stats.get("vpn_active")
        else "VPN OFF — direct internet connection"
    )
    agent = "running" if stats.get("agent_started") else "standby (stats only)"
    return (
        "LIVE STATS:\n"
        f"- Vigilance agent: {agent} ({stats.get('agent_cycles', 0)} cycles)\n"
        f"- CPU: {stats.get('cpu_percent')}%\n"
        f"- RAM: {stats.get('ram_percent')}% ({stats.get('ram_available_gb')} GB free)\n"
        f"- Disk: {stats.get('disk_percent_used')}% used ({stats.get('disk_free_gb')} GB free)\n"
        f"- Host: {stats.get('hostname')}\n"
        f"- Local IP(s): {', '.join(stats.get('local_ips') or ['unknown'])}\n"
        f"- Public IP: {stats.get('public_ip') or 'unknown'}\n"
        f"- {vpn_line}\n"
        f"- DNS: {', '.join(stats.get('dns_servers') or ['unknown'])}\n"
        f"- Gateway: {stats.get('gateway') or 'unknown'}"
    )

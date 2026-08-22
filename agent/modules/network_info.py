"""Real-time network, VPN, and DNS detection."""

from __future__ import annotations

import logging
import re
import socket
import subprocess
import urllib.request
from dataclasses import dataclass, field

import psutil

from agent.store.db import AgentStore
from agent.utils import IS_WINDOWS

logger = logging.getLogger("dvielle.network")

VPN_KEYWORDS = (
    "vpn", "wireguard", "wg", "tun", "tap", "nordlynx", "openvpn", "proton",
    "mullvad", "zerotier", "tailscale", "cisco", "anyconnect", "pangp",
    "fortinet", "softether", "ras", "nordvpn", "expressvpn", "surfshark",
    "windscribe", "hotspot", "tunnel", "ppp",
)


@dataclass
class NetworkSnapshot:
    hostname: str
    local_ips: list[str] = field(default_factory=list)
    public_ip: str | None = None
    vpn_active: bool = False
    vpn_adapter: str | None = None
    vpn_ip: str | None = None
    dns_servers: list[str] = field(default_factory=list)
    gateway: str | None = None

    def to_dict(self) -> dict:
        return {
            "hostname": self.hostname,
            "local_ips": self.local_ips,
            "public_ip": self.public_ip,
            "vpn_active": self.vpn_active,
            "vpn_adapter": self.vpn_adapter,
            "vpn_ip": self.vpn_ip,
            "dns_servers": self.dns_servers,
            "gateway": self.gateway,
        }


def _is_vpn_interface(name: str) -> bool:
    lower = name.lower()
    return any(k in lower for k in VPN_KEYWORDS)


def _collect_local_ips() -> tuple[list[str], str | None, str | None, str | None]:
    """Return local_ips, vpn_adapter, vpn_ip, gateway."""
    local_ips: list[str] = []
    vpn_adapter = None
    vpn_ip = None

    for iface, addrs in psutil.net_if_addrs().items():
        if iface.lower().startswith("loopback") or iface == "lo":
            continue
        for addr in addrs:
            if addr.family != socket.AF_INET:
                continue
            ip = addr.address
            if ip.startswith("127."):
                continue
            local_ips.append(ip)
            if _is_vpn_interface(iface):
                vpn_adapter = iface
                vpn_ip = ip

    gateway = None
    try:
        gws = psutil.net_if_stats()
        # default route via net_connections not ideal; parse route on Windows
        if IS_WINDOWS:
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command",
                 "(Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Sort-Object RouteMetric | Select-Object -First 1).NextHop"],
                capture_output=True, text=True, timeout=10,
                creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, "CREATE_NO_WINDOW") else 0,
            )
            gw = result.stdout.strip()
            if gw and re.match(r"[\d.]+", gw):
                gateway = gw
    except Exception:
        pass

    return list(dict.fromkeys(local_ips)), vpn_adapter, vpn_ip, gateway


def _fetch_public_ip(timeout: float = 5.0) -> str | None:
    urls = [
        "https://api.ipify.org",
        "https://ifconfig.me/ip",
        "https://icanhazip.com",
    ]
    for url in urls:
        try:
            with urllib.request.urlopen(url, timeout=timeout) as resp:
                ip = resp.read().decode().strip()
                if re.match(r"^[\d.a-fA-F:]+$", ip):
                    return ip
        except Exception:
            continue
    return None


def _fetch_dns_servers() -> list[str]:
    if not IS_WINDOWS:
        try:
            with open("/etc/resolv.conf") as f:
                return [line.split()[1] for line in f if line.startswith("nameserver")]
        except OSError:
            return []

    ps = """
Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
  Where-Object { $_.ServerAddresses } |
  ForEach-Object { $_.ServerAddresses } |
  Select-Object -Unique
"""
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-Command", ps],
            capture_output=True, text=True, timeout=15,
            creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, "CREATE_NO_WINDOW") else 0,
        )
        servers = [s.strip() for s in result.stdout.splitlines() if s.strip()]
        return list(dict.fromkeys(servers))
    except Exception:
        return []


def collect_network_snapshot() -> NetworkSnapshot:
    hostname = socket.gethostname()
    local_ips, vpn_adapter, vpn_ip, gateway = _collect_local_ips()
    dns_servers = _fetch_dns_servers()
    public_ip = _fetch_public_ip()

    vpn_active = vpn_adapter is not None and vpn_ip is not None

    # Heuristic: if VPN adapter exists but no vpn_ip yet, still flag active
    if not vpn_active:
        for iface in psutil.net_if_addrs():
            if _is_vpn_interface(iface):
                stats = psutil.net_if_stats().get(iface)
                if stats and stats.isup:
                    vpn_active = True
                    vpn_adapter = vpn_adapter or iface
                    break

    return NetworkSnapshot(
        hostname=hostname,
        local_ips=local_ips,
        public_ip=public_ip,
        vpn_active=vpn_active,
        vpn_adapter=vpn_adapter,
        vpn_ip=vpn_ip,
        dns_servers=dns_servers,
        gateway=gateway,
    )


class NetworkMonitor:
    def __init__(self, store: AgentStore) -> None:
        self.store = store
        self._last: NetworkSnapshot | None = None

    def run(self) -> NetworkSnapshot:
        snap = collect_network_snapshot()
        self._last = snap

        self.store.log_event(
            "network",
            "INFO",
            f"Network scan: public={snap.public_ip} vpn={snap.vpn_active} dns={len(snap.dns_servers)}",
            snap.to_dict(),
        )

        if snap.vpn_active:
            logger.info(
                "VPN detected: adapter=%s ip=%s public=%s dns=%s",
                snap.vpn_adapter, snap.vpn_ip, snap.public_ip, snap.dns_servers,
            )
        return snap

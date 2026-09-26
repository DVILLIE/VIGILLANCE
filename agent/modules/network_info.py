"""Real-time network, VPN, and DNS detection."""

from __future__ import annotations

import logging
import socket
import urllib.request
import ipaddress
from dataclasses import dataclass, field

import psutil

from agent.store.db import AgentStore
from agent.utils import IS_WINDOWS, run_powershell

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
    vpn_route_verified: bool | None = None
    public_ip_lookup_enabled: bool = False

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
            "vpn_route_verified": self.vpn_route_verified,
            "public_ip_lookup_enabled": self.public_ip_lookup_enabled,
        }


def _is_vpn_interface(name: str) -> bool:
    lower = name.lower()
    return any(k in lower for k in VPN_KEYWORDS)


def _collect_local_ips() -> tuple[list[str], str | None, str | None, str | None]:
    """Return local_ips, vpn_adapter, vpn_ip, gateway."""
    local_ips: list[str] = []
    vpn_adapter = None
    vpn_ip = None

    stats = psutil.net_if_stats()
    for iface, addrs in psutil.net_if_addrs().items():
        if iface.lower().startswith("loopback") or iface == "lo":
            continue
        if iface not in stats or not stats[iface].isup:
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
        # default route via net_connections not ideal; parse route on Windows
        if IS_WINDOWS:
            stdout, _ = run_powershell(
                "(Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Sort-Object RouteMetric | Select-Object -First 1).NextHop",
                timeout=10,
            )
            gw = (stdout or "").strip()
            if gw:
                gateway = str(ipaddress.ip_address(gw))
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
                ip = resp.read(128).decode().strip()
                return str(ipaddress.ip_address(ip))
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
        stdout, _ = run_powershell(ps, timeout=15)
        servers = [s.strip() for s in (stdout or "").splitlines() if s.strip()]
        return list(dict.fromkeys(servers))
    except Exception:
        return []


def collect_network_snapshot(*, allow_public_ip: bool = False) -> NetworkSnapshot:
    hostname = socket.gethostname()
    local_ips, vpn_adapter, vpn_ip, gateway = _collect_local_ips()
    dns_servers = _fetch_dns_servers()
    public_ip = _fetch_public_ip() if allow_public_ip else None

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
        public_ip_lookup_enabled=allow_public_ip,
    )


class NetworkMonitor:
    def __init__(self, store: AgentStore, config: dict | None = None) -> None:
        self.store = store
        self._last: NetworkSnapshot | None = None
        self.allow_public_ip = (config or {}).get("network", {}).get("allow_public_ip_lookup", False) is True

    def run(self) -> NetworkSnapshot:
        snap = collect_network_snapshot(allow_public_ip=self.allow_public_ip)
        self._last = snap

        self.store.log_event(
            "network",
            "INFO",
            f"Network observation: public={snap.public_ip} VPN-like adapter={snap.vpn_active} dns={len(snap.dns_servers)}",
            snap.to_dict(),
        )

        if snap.vpn_active:
            logger.info(
                "VPN detected: adapter=%s ip=%s public=%s dns=%s",
                snap.vpn_adapter, snap.vpn_ip, snap.public_ip, snap.dns_servers,
            )
        return snap

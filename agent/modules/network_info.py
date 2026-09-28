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
    # ok | unavailable | timeout | error | disabled. Empty lists are not success.
    dns_observation: str = "unavailable"
    gateway_observation: str = "unavailable"
    public_ip_observation: str = "disabled"

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
            "dns_observation": self.dns_observation,
            "gateway_observation": self.gateway_observation,
            "public_ip_observation": self.public_ip_observation,
        }


def coverage_error(snap: NetworkSnapshot) -> str | None:
    """None only when required probes completed. Timeout and access failure stay visible."""
    gaps: list[str] = []
    if snap.dns_observation != "ok":
        gaps.append(f"dns {snap.dns_observation}")
    if snap.gateway_observation != "ok":
        gaps.append(f"gateway {snap.gateway_observation}")
    if snap.public_ip_lookup_enabled and snap.public_ip_observation != "ok":
        gaps.append(f"public_ip {snap.public_ip_observation}")
    if not gaps:
        return None
    return "Network observation incomplete: " + ", ".join(gaps)


def _is_vpn_interface(name: str) -> bool:
    lower = name.lower()
    return any(k in lower for k in VPN_KEYWORDS)


def _probe_powershell(script: str, timeout: float) -> tuple[str | None, str]:
    """Return (stdout, observation). stdout is None unless the command finished ok."""
    try:
        stdout, timed_out = run_powershell(script, timeout=timeout)
    except Exception:
        logger.warning("Network probe failed", exc_info=True)
        return None, "error"
    if timed_out:
        return None, "timeout"
    if stdout is None:
        return None, "error"
    return stdout, "ok"


def _collect_local_ips() -> tuple[list[str], str | None, str | None, str | None, str]:
    """Return local_ips, vpn_adapter, vpn_ip, gateway, gateway_observation."""
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
    gateway_observation = "unavailable"
    if IS_WINDOWS:
        stdout, gateway_observation = _probe_powershell(
            "(Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Sort-Object RouteMetric | Select-Object -First 1).NextHop",
            10,
        )
        if gateway_observation == "ok":
            gw = (stdout or "").strip()
            if not gw:
                gateway_observation = "unavailable"
            else:
                try:
                    gateway = str(ipaddress.ip_address(gw))
                except ValueError:
                    gateway = None
                    gateway_observation = "error"

    return list(dict.fromkeys(local_ips)), vpn_adapter, vpn_ip, gateway, gateway_observation


def _fetch_public_ip(timeout: float = 5.0) -> tuple[str | None, str]:
    urls = [
        "https://api.ipify.org",
        "https://ifconfig.me/ip",
        "https://icanhazip.com",
    ]
    saw_timeout = False
    for url in urls:
        try:
            with urllib.request.urlopen(url, timeout=timeout) as resp:
                ip = resp.read(128).decode().strip()
                return str(ipaddress.ip_address(ip)), "ok"
        except TimeoutError:
            saw_timeout = True
            continue
        except Exception as exc:
            if isinstance(exc, (TimeoutError, socket.timeout)):
                saw_timeout = True
            continue
    return None, "timeout" if saw_timeout else "error"


def _fetch_dns_servers() -> tuple[list[str], str]:
    if not IS_WINDOWS:
        try:
            with open("/etc/resolv.conf") as f:
                servers = [line.split()[1] for line in f if line.startswith("nameserver")]
            return servers, "ok"
        except OSError:
            return [], "unavailable"

    ps = """
Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction Stop |
  Where-Object { $_.ServerAddresses } |
  ForEach-Object { $_.ServerAddresses } |
  Select-Object -Unique
"""
    stdout, observation = _probe_powershell(ps, 15)
    if observation != "ok":
        return [], observation
    servers = [s.strip() for s in (stdout or "").splitlines() if s.strip()]
    return list(dict.fromkeys(servers)), "ok"


def collect_network_snapshot(*, allow_public_ip: bool = False) -> NetworkSnapshot:
    hostname = socket.gethostname()
    local_ips, vpn_adapter, vpn_ip, gateway, gateway_observation = _collect_local_ips()
    dns_servers, dns_observation = _fetch_dns_servers()
    if allow_public_ip:
        public_ip, public_ip_observation = _fetch_public_ip()
    else:
        public_ip, public_ip_observation = None, "disabled"

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
        dns_observation=dns_observation,
        gateway_observation=gateway_observation,
        public_ip_observation=public_ip_observation,
    )


class NetworkMonitor:
    def __init__(self, store: AgentStore, config: dict | None = None) -> None:
        self.store = store
        self._last: NetworkSnapshot | None = None
        self.collection_error: str | None = None
        self.allow_public_ip = (config or {}).get("network", {}).get("allow_public_ip_lookup", False) is True

    def run(self) -> NetworkSnapshot:
        snap = collect_network_snapshot(allow_public_ip=self.allow_public_ip)
        self._last = snap
        self.collection_error = coverage_error(snap)

        self.store.log_event(
            "network",
            "WARNING" if self.collection_error else "INFO",
            self.collection_error
            or f"Network observation: public={snap.public_ip} VPN-like adapter={snap.vpn_active} dns={len(snap.dns_servers)}",
            snap.to_dict(),
        )

        if snap.vpn_active:
            logger.info(
                "VPN detected: adapter=%s ip=%s public=%s dns=%s",
                snap.vpn_adapter, snap.vpn_ip, snap.public_ip, snap.dns_servers,
            )
        return snap

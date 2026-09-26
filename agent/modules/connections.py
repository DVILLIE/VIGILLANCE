"""Connection monitor — classify remotes (LAN / CDN / unknown), identify process."""

from __future__ import annotations

import ipaddress
import logging
import socket
from dataclasses import dataclass
from typing import Any

import psutil

from agent.store.db import AgentStore
from agent.utils import IS_WINDOWS, ip_in_whitelist

logger = logging.getLogger("dvielle.connections")

# Well-known public cloud / CDN ranges (not your router or phone)
_CLOUD_CIDRS: list[tuple[str, str]] = [
    ("104.16.0.0/13", "Cloudflare CDN"),
    ("104.24.0.0/14", "Cloudflare CDN"),
    ("172.64.0.0/13", "Cloudflare CDN"),
    ("13.32.0.0/15", "Amazon CloudFront/AWS"),
    ("52.84.0.0/15", "Amazon CloudFront/AWS"),
    ("142.250.0.0/15", "Google"),
    ("142.251.0.0/16", "Google"),
    ("216.58.192.0/19", "Google"),
    ("20.0.0.0/8", "Microsoft Azure"),
    ("40.64.0.0/10", "Microsoft Azure"),
    ("13.64.0.0/11", "Microsoft Azure"),
    ("1.1.1.0/24", "Cloudflare DNS"),
    ("8.8.8.0/24", "Google DNS"),
    ("8.8.4.0/24", "Google DNS"),
    ("9.9.9.0/24", "Quad9 DNS"),
]


@dataclass
class ConnectionAlert:
    pid: int | None
    process_name: str | None
    local_addr: str
    remote_addr: str
    remote_ip: str
    remote_port: int | None
    reason: str
    kind: str = "unknown"
    explanation: str = ""


def _process_info(pid: int | None) -> tuple[str, str | None, str | None]:
    """Return (display_name, exe_path, note)."""
    if pid is None:
        return "System / driver (no PID)", None, "Windows did not expose a process id"
    try:
        proc = psutil.Process(pid)
        name = proc.name() or f"pid-{pid}"
        try:
            exe = proc.exe()
        except (psutil.AccessDenied, psutil.Error):
            exe = None
        try:
            user = proc.username()
        except (psutil.AccessDenied, psutil.Error):
            user = None
        note = f"user={user}" if user else None
        return name, exe, note
    except psutil.NoSuchProcess:
        return f"Ended process (was PID {pid})", None, "Process exited before lookup"
    except psutil.AccessDenied:
        return f"Protected process (PID {pid})", None, "Need Administrator for full name"


def _reverse_dns(ip: str, timeout: float = 0.8) -> str | None:
    old = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(timeout)
        host, _, _ = socket.gethostbyaddr(ip)
        return host
    except OSError:
        return None
    finally:
        socket.setdefaulttimeout(old)


def _default_gateway() -> str | None:
    if not IS_WINDOWS:
        return None
    try:
        import subprocess

        result = subprocess.run(
            [
                "powershell",
                "-NoProfile",
                "-Command",
                "(Get-NetRoute -DestinationPrefix '0.0.0.0/0' | "
                "Sort-Object RouteMetric | Select-Object -First 1).NextHop",
            ],
            capture_output=True,
            text=True,
            timeout=8,
            creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, "CREATE_NO_WINDOW") else 0,
        )
        gw = result.stdout.strip()
        if gw and all(c.isdigit() or c == "." for c in gw):
            return gw
    except Exception:
        return None
    return None


def _local_ipv4s() -> list[str]:
    ips: list[str] = []
    for _, addrs in psutil.net_if_addrs().items():
        for addr in addrs:
            if addr.family == socket.AF_INET and not addr.address.startswith("127."):
                ips.append(addr.address)
    return ips


def _cloud_label(ip: str) -> str | None:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    for cidr, label in _CLOUD_CIDRS:
        try:
            if addr in ipaddress.ip_network(cidr, strict=False):
                return label
        except ValueError:
            continue
    return None


def classify_remote(
    remote_ip: str,
    hostname: str | None,
    gateway: str | None,
    local_ips: list[str],
) -> tuple[str, str, bool]:
    """Return (kind, plain_english, treat_as_threat).

    kind examples: router, lan_device, phone_or_hotspot, vpn_peer,
    cdn_cloud, dns, unknown_internet
    """
    try:
        addr = ipaddress.ip_address(remote_ip)
    except ValueError:
        return "invalid", f"Invalid remote address {remote_ip}", True

    if addr.is_loopback:
        return "loopback", "Local loopback (this PC talking to itself)", False

    # Router / default gateway
    if gateway and remote_ip == gateway:
        return (
            "router",
            f"Your network gateway/router ({remote_ip}). Normal — not an internet attacker.",
            False,
        )

    # Private LAN — phone, extender, printer, NAS, etc.
    if addr.is_private:
        same_subnet = False
        for lip in local_ips:
            try:
                # Rough /24 neighbourhood for home Wi‑Fi
                if ".".join(lip.split(".")[:3]) == ".".join(remote_ip.split(".")[:3]):
                    same_subnet = True
                    break
            except Exception:
                pass
        host_bit = ""
        if hostname:
            host_bit = f" Hostname: {hostname}."
        if same_subnet:
            return (
                "lan_device",
                f"Device on your home/office network ({remote_ip}). "
                f"Could be a phone, Wi‑Fi extender, smart TV, printer, or another PC.{host_bit}",
                False,
            )
        return (
            "lan_private",
            f"Private network address ({remote_ip}) — usually router/LAN gear, not the public internet.{host_bit}",
            False,
        )

    # CGNAT / Tailscale / carrier grade (100.64/10)
    if addr in ipaddress.ip_network("100.64.0.0/10"):
        return (
            "vpn_or_cgnat",
            f"CGNAT / mesh VPN style address ({remote_ip}) — often Tailscale, phone hotspot, or ISP share.",
            False,
        )

    # Link-local
    if addr.is_link_local:
        return "link_local", f"Link-local address ({remote_ip}) — local link only.", False

    cloud = _cloud_label(remote_ip)
    host_l = (hostname or "").lower()
    if cloud or any(
        x in host_l
        for x in (
            "cloudflare",
            "akamai",
            "cloudfront",
            "amazonaws",
            "azure",
            "googleusercontent",
            "1e100.net",
            "fastly",
        )
    ):
        label = cloud or "major CDN/cloud"
        return (
            "cdn_cloud",
            f"{label} endpoint ({remote_ip}"
            + (f" / {hostname}" if hostname else "")
            + "). Usually a website, app update, or API — not your router or phone.",
            False,
        )

    if remote_ip in ("1.1.1.1", "8.8.8.8", "8.8.4.4", "9.9.9.9") or "dns" in host_l:
        return "dns", f"Public DNS service ({remote_ip}). Normal for name lookups.", False

    if hostname:
        return (
            "named_internet",
            f"Internet host {hostname} ({remote_ip}). Not a home router/phone — review which app opened it.",
            True,
        )

    return (
        "unknown_internet",
        f"Public internet IP {remote_ip} with no hostname. "
        f"Not a typical home router/phone/extender — worth a closer look.",
        True,
    )


def _domain_whitelisted(hostname: str | None, domains: list[str]) -> bool:
    if not hostname:
        return False
    host = hostname.lower()
    return any(d.lower() in host for d in domains)


def _process_whitelisted(name: str | None, processes: list[str]) -> bool:
    if not name:
        return False
    lower = name.lower()
    # Strip notes like "Protected process..."
    base = lower.split("(")[0].strip()
    return any(p.lower() == lower or p.lower() == base for p in processes)


class ConnectionMonitor:
    def __init__(self, store: AgentStore, config: dict[str, Any], whitelists: dict[str, Any]) -> None:
        self.store = store
        self.config = config
        self.whitelists = whitelists
        self._seen_remote: set[str] = set()
        self._gateway = _default_gateway()
        self._local_ips = _local_ipv4s()

    def run(self, monitor_only: bool = True) -> list[ConnectionAlert]:
        alerts: list[ConnectionAlert] = []
        ip_wl = self.whitelists.get("ips", [])
        proc_wl = self.whitelists.get("processes", [])
        domain_wl = list(self.whitelists.get("domains", []))
        # CDN hosts are not "attacks"
        domain_wl.extend(
            ["cloudflare.com", "cloudflare.net", "akamai", "cloudfront.net", "fastly.net"]
        )

        # Refresh local topology each cycle (cheap)
        self._gateway = _default_gateway() or self._gateway
        self._local_ips = _local_ipv4s() or self._local_ips

        try:
            connections = psutil.net_connections(kind="inet")
        except (psutil.AccessDenied, PermissionError) as exc:
            logger.warning("Cannot read connections (run as admin for full visibility): %s", exc)
            return alerts

        for conn in connections:
            if conn.status != psutil.CONN_ESTABLISHED or not conn.raddr:
                continue

            remote_ip = conn.raddr.ip
            remote_port = conn.raddr.port
            pid = conn.pid
            proc_name, exe_path, proc_note = _process_info(pid)
            local = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else ""
            remote = f"{remote_ip}:{remote_port}"

            if proc_name and not proc_name.lower().startswith(("system", "protected", "ended")):
                self.store.update_baseline_process(proc_name)

            hostname = _reverse_dns(remote_ip)
            kind, explanation, could_be_threat = classify_remote(
                remote_ip, hostname, self._gateway, self._local_ips
            )

            # Trust rules
            trusted = False
            if ip_in_whitelist(remote_ip, ip_wl):
                trusted = True
                if kind.startswith("lan") or kind == "router":
                    explanation = explanation  # keep LAN story
                else:
                    explanation = f"Trusted network range. {explanation}"
            elif _process_whitelisted(proc_name, proc_wl):
                trusted = True
                explanation = f"Trusted app ({proc_name}). {explanation}"
            # Name-only baseline is observational history — NOT a trust grant
            # (Architecture P0: publisher+signature+path+hash identity required).
            elif _domain_whitelisted(hostname, domain_wl):
                trusted = True
                explanation = f"Trusted domain ({hostname}). {explanation}"
            elif kind in ("router", "lan_device", "lan_private", "vpn_or_cgnat", "cdn_cloud", "dns", "loopback", "link_local"):
                trusted = True

            # Only flag when we truly don't know the internet peer OR process is opaque + public IP
            suspicious = False
            if not trusted and could_be_threat:
                suspicious = True
            elif not trusted and kind == "named_internet" and "Protected process" in proc_name:
                suspicious = True
                explanation += " Process name hidden — run DVielle as Admin for the real app."

            reason = f"[{kind}] {explanation}"
            if proc_note:
                reason += f" ({proc_note})"
            if exe_path:
                reason += f" exe={exe_path}"

            self.store.log_connection(
                pid=pid,
                process_name=proc_name,
                local_addr=local,
                remote_addr=remote,
                remote_ip=remote_ip,
                remote_port=remote_port,
                status="ESTABLISHED",
                suspicious=suspicious,
                reason=reason,
            )

            # Also log informational LAN/CDN for Attacks Console "what is this?" — only once
            intel_key = f"{kind}|{remote_ip}|{proc_name}"
            if kind in ("router", "lan_device", "lan_private", "cdn_cloud") and intel_key not in self._seen_remote:
                self._seen_remote.add(intel_key)
                self.store.log_event(
                    "connections",
                    "INFO",
                    f"{proc_name} → {remote}: {explanation}",
                    {
                        "kind": kind,
                        "pid": pid,
                        "hostname": hostname,
                        "exe": exe_path,
                        "gateway": self._gateway,
                    },
                )

            if suspicious and remote not in self._seen_remote:
                self._seen_remote.add(remote)
                alert = ConnectionAlert(
                    pid=pid,
                    process_name=proc_name,
                    local_addr=local,
                    remote_addr=remote,
                    remote_ip=remote_ip,
                    remote_port=remote_port,
                    reason=reason,
                    kind=kind,
                    explanation=explanation,
                )
                alerts.append(alert)
                self.store.log_event(
                    "connections",
                    "WARNING",
                    f"Review connection: {proc_name} → {remote} — {explanation}",
                    {
                        "pid": pid,
                        "kind": kind,
                        "hostname": hostname,
                        "exe": exe_path,
                        "reason": reason,
                    },
                )
                logger.warning("Review: %s PID=%s → %s (%s)", proc_name, pid, remote, kind)

        return alerts

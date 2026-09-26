"""Connection monitor — classify remotes (LAN / CDN / unknown), identify process."""

from __future__ import annotations

import ipaddress
import logging
import os
import socket
import time
from dataclasses import dataclass
from typing import Any

import psutil

from agent import net_resolve
from agent.net_identity import host_matches_any
from agent.store.db import AgentStore
from agent.utils import IS_WINDOWS, ip_in_whitelist, run_powershell

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
        return "Unknown process (no PID)", None, "Windows did not expose a process id"
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
        return f"Protected process (PID {pid})", None, "Elevation may improve visibility; full name unavailable"


def _reverse_dns(ip: str) -> str | None:
    # Non-blocking: never stall the nerve loop on gethostbyaddr (audit C3).
    return net_resolve.lookup(ip)


# Gateway rarely changes; the PowerShell probe is expensive, so cache it (TTL)
# instead of spawning a process on every pulse.
_GW_TTL = 300.0
_gw_cache: dict[str, Any] = {"value": None, "expiry": 0.0}


def _default_gateway() -> str | None:
    if not IS_WINDOWS:
        return None
    now = time.monotonic()
    if _gw_cache["expiry"] > now:
        return _gw_cache["value"]
    gw: str | None = None
    stdout, _ = run_powershell(
        "(Get-NetRoute -DestinationPrefix '0.0.0.0/0' | "
        "Sort-Object RouteMetric | Select-Object -First 1).NextHop",
        timeout=8,
    )
    candidate = (stdout or "").strip()
    try:
        gw = str(ipaddress.IPv4Address(candidate))
    except ValueError:
        pass
    _gw_cache["value"] = gw
    _gw_cache["expiry"] = now + _GW_TTL
    return gw


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
        return "invalid", f"Invalid remote address {remote_ip}; identity unavailable", False

    if addr.is_loopback:
        return "loopback", "Local loopback (this PC talking to itself)", False

    # Router / default gateway
    if gateway and remote_ip == gateway:
        return (
            "router",
            f"Configured network gateway/router ({remote_ip}); location does not establish trust.",
            False,
        )

    if addr.is_link_local:
        return "link_local", f"Link-local address ({remote_ip}) — local link only.", False

    # Only RFC1918/ULA ranges imply private addressing; is_private also includes
    # reserved and documentation space on supported Python versions.
    if any(addr in ipaddress.ip_network(cidr) for cidr in
           ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7")):
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
                f"Private address ({remote_ip}) shares a prefix with a local address; subnet mask unverified. "
                f"Device type is unknown (could include a phone, Wi‑Fi extender, printer, or PC).{host_bit}",
                False,
            )
        return (
            "lan_private",
            f"Private network address ({remote_ip}); device identity and route are unverified.{host_bit}",
            False,
        )

    # CGNAT / Tailscale / carrier grade (100.64/10)
    if addr in ipaddress.ip_network("100.64.0.0/10"):
        return (
            "vpn_or_cgnat",
            f"CGNAT / mesh VPN style address ({remote_ip}) — often Tailscale, phone hotspot, or ISP share.",
            False,
        )

    if remote_ip in ("1.1.1.1", "8.8.8.8", "8.8.4.4", "9.9.9.9"):
        return "dns", f"Known public DNS address ({remote_ip}); use is not proof of safety.", False

    cloud = _cloud_label(remote_ip)
    if cloud:
        return (
            "cdn_cloud",
            f"Static address-range hint: {cloud} ({remote_ip}). "
            "Ownership and tenant identity are unverified; cloud hosting does not establish trust.",
            False,
        )
    if hostname:
        return (
            "named_internet",
            f"Internet IP {remote_ip}; reverse-DNS name {hostname} is an unverified naming hint. "
            "No threat determination from the name alone.",
            False,
        )
    return (
        "unknown_internet",
        f"Public internet IP {remote_ip}; reverse DNS unavailable. "
        "An unknown peer is an observation, not evidence of malicious activity.",
        False,
    )


def _domain_whitelisted(hostname: str | None, domains: list[str]) -> bool:
    return host_matches_any(hostname, domains)


def _process_whitelisted(name: str | None, processes: list[str]) -> bool:
    if not name:
        return False
    lower = name.lower()
    # Strip notes like "Protected process..."
    base = lower.split("(")[0].strip()
    return any(p.lower() == lower or p.lower() == base for p in processes)


# ── Network honesty (audit #2): pending-DNS grace, signed-app downgrade, cross-pulse dedup ──
GRACE_SECONDS = 120.0  # ~2 pulses — give async reverse-DNS time before flagging "no PTR"
_ALERT_TTL = 600.0     # re-log a given (kind, ip, proc) at most this often across pulses
_first_unresolved_at: dict[str, float] = {}   # remote_ip -> monotonic first-seen-unresolved
_alerted_at: dict[str, float] = {}            # dedup key -> monotonic last log
_sig_cache: dict[tuple[str, int, int], bool] = {}  # (exe_path, size, mtime) -> validly signed


def _within_resolve_grace(remote_ip: str, *, resolved: bool) -> bool:
    """True while a still-unresolved IP is inside the grace window (treat as pending,
    not suspicious). Time-based so it's immune to per-connection vs per-pulse counting.

    Call only for would-be-flagged connections (bounds the dict), and prune entries
    past the grace window — after GRACE_SECONDS the answer is always False anyway.
    """
    now = time.monotonic()
    if len(_first_unresolved_at) > 128:
        for ip, first in list(_first_unresolved_at.items()):
            if now - first >= GRACE_SECONDS:
                _first_unresolved_at.pop(ip, None)
    if resolved:
        _first_unresolved_at.pop(remote_ip, None)
        return False
    first = _first_unresolved_at.get(remote_ip)
    if first is None:
        _first_unresolved_at[remote_ip] = now
        return True
    return (now - first) < GRACE_SECONDS


def _refine_suspicion(
    *, base_suspicious: bool, hostname: str | None, within_grace: bool, is_signed: bool
) -> tuple[bool, str]:
    """Preserve explicit adverse evidence regardless of PTR or signature metadata.

    Unknown identity is never the base trigger. A signature proves neither the
    destination's identity nor the safety of the process's current behavior.
    """
    return (True, "review") if base_suspicious else (False, "")


def _alert_cooldown_ok(key: str) -> bool:
    """Cross-pulse dedup: True at most once per _ALERT_TTL for the same key.
    Prunes expired keys so the dict can't grow unbounded over a long-running agent.
    """
    now = time.monotonic()
    if len(_alerted_at) > 512:
        for k, when in list(_alerted_at.items()):
            if now - when >= _ALERT_TTL:
                _alerted_at.pop(k, None)
    last = _alerted_at.get(key)
    if last is not None and (now - last) < _ALERT_TTL:
        return False
    if len(_alerted_at) >= 1024 and key not in _alerted_at:
        _alerted_at.pop(min(_alerted_at, key=_alerted_at.get))
    _alerted_at[key] = now
    return True


def _is_signed_valid(exe_path: str | None) -> bool:
    """Whether exe is validly Authenticode-signed (Status == Valid), cached by
    (path, size, mtime) so a replaced binary re-checks. Signature validity is
    metadata only; it does not establish destination trust or process safety.
    """
    if not exe_path or not IS_WINDOWS:
        return False
    try:
        st = os.stat(exe_path)
        key = (exe_path, int(st.st_size), int(st.st_mtime))
    except OSError:
        return False
    cached = _sig_cache.get(key)
    if cached is not None:
        return cached
    safe = exe_path.replace("'", "''")
    stdout, timed_out = run_powershell(f"(Get-AuthenticodeSignature -LiteralPath '{safe}').Status", timeout=8)
    valid = not timed_out and stdout is not None and stdout.strip() == "Valid"
    if len(_sig_cache) >= 512:
        _sig_cache.pop(next(iter(_sig_cache)))
    _sig_cache[key] = valid
    return valid


class ConnectionMonitor:
    def __init__(self, store: AgentStore, config: dict[str, Any], whitelists: dict[str, Any]) -> None:
        self.store = store
        self.collection_error: str | None = None
        self.config = config
        self.whitelists = whitelists
        self._gateway = _default_gateway()
        self._local_ips = _local_ipv4s()

    def run(self, monitor_only: bool = True) -> list[ConnectionAlert]:
        alerts: list[ConnectionAlert] = []
        ip_wl = self.whitelists.get("ips", [])
        proc_wl = self.whitelists.get("processes", [])
        domain_wl = list(self.whitelists.get("domains", []))
        self.collection_error = None
        review_ips = self.config.get("network", {}).get("review_ips", [])

        # Refresh local topology each cycle (cheap)
        self._gateway = _default_gateway()
        self._local_ips = _local_ipv4s()

        try:
            connections = psutil.net_connections(kind="inet")
        except (psutil.AccessDenied, OSError) as exc:
            self.collection_error = f"Connection collection unavailable: {type(exc).__name__}"
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

            # These fields are context only. Neither an executable name nor a
            # PTR name, signature, or shared cloud range identifies a safe peer.
            if ip_in_whitelist(remote_ip, ip_wl):
                explanation += " Matches an explicitly configured IP allowlist."
            if _process_whitelisted(proc_name, proc_wl):
                explanation += f" Recognized process name ({proc_name}); executable identity unverified."
            if _domain_whitelisted(hostname, domain_wl):
                explanation += " PTR matches a configured domain; peer identity unverified."

            suspicious = ip_in_whitelist(remote_ip, review_ips)
            if suspicious:
                explanation += " Matches an explicitly configured network.review_ips rule; review requested."

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

            # Informational LAN/CDN intel — cross-pulse dedup so it isn't re-logged every pulse.
            intel_key = f"intel|{kind}|{remote_ip}|{proc_name}"
            if kind in ("router", "lan_device", "lan_private", "cdn_cloud") and _alert_cooldown_ok(intel_key):
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

            if suspicious and _alert_cooldown_ok(f"review|{remote_ip}|{proc_name}"):
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

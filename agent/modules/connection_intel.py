"""Enrich suspicious connections with process, DNS, and plain-English intel."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

import psutil

from agent import net_resolve
from agent.net_identity import host_matches_domain

logger = logging.getLogger("dvielle.connection_intel")

# Exact DNS boundaries provide naming hints only, never destination trust.
ORG_HINTS: tuple[tuple[str, str], ...] = (
    ("cloudflare.com", "Cloudflare naming domain"),
    ("akamai.net", "Akamai naming domain"),
    ("fastly.net", "Fastly naming domain"),
    ("amazonaws.com", "Amazon AWS naming domain"),
    ("cloudfront.net", "Amazon CloudFront naming domain"),
    ("google.com", "Google naming domain"),
    ("1e100.net", "Google infrastructure"),
    ("microsoft.com", "Microsoft naming domain"),
    ("msft.net", "Microsoft network"),
    ("azure.com", "Microsoft Azure naming domain"),
    ("office.com", "Microsoft Office naming domain"),
    ("facebook.com", "Meta naming domain"),
    ("fbcdn.net", "Facebook CDN naming domain"),
    ("twitter.com", "X naming domain"),
    ("github.com", "GitHub naming domain"),
    ("openai.com", "OpenAI naming domain"),
    ("cursor.com", "Cursor naming domain"),
    ("tailscale.com", "Tailscale naming domain"),
)

# Well-known public CDN / cloud prefixes (coarse — for plain English only)
IP_ORG_PREFIXES: tuple[tuple[str, str], ...] = (
    ("104.16.", "Likely Cloudflare anycast CDN"),
    ("104.17.", "Likely Cloudflare anycast CDN"),
    ("104.18.", "Likely Cloudflare anycast CDN"),
    ("104.19.", "Likely Cloudflare anycast CDN"),
    ("104.20.", "Likely Cloudflare anycast CDN"),
    ("104.21.", "Likely Cloudflare anycast CDN"),
    ("104.22.", "Likely Cloudflare anycast CDN"),
    ("104.24.", "Likely Cloudflare anycast CDN"),
    ("104.25.", "Likely Cloudflare anycast CDN"),
    ("104.26.", "Likely Cloudflare anycast CDN"),
    ("172.64.", "Likely Cloudflare"),
    ("172.65.", "Likely Cloudflare"),
    ("172.66.", "Likely Cloudflare"),
    ("172.67.", "Likely Cloudflare"),
    ("13.", "Often Amazon / AWS public range"),
    ("52.", "Often Amazon / AWS public range"),
    ("54.", "Often Amazon / AWS public range"),
    ("35.", "Often Google Cloud"),
    ("34.", "Often Google Cloud"),
    ("20.", "Often Microsoft Azure"),
    ("40.", "Often Microsoft Azure"),
    ("51.", "Often Microsoft"),
)

PORT_MEANING = {
    80: "HTTP (web)",
    443: "HTTPS convention (protocol/encryption unverified)",
    8080: "HTTP alternate",
    8443: "HTTPS alternate",
    22: "SSH",
    21: "FTP",
    25: "SMTP (email)",
    53: "DNS",
    3389: "RDP (remote desktop)",
    993: "IMAPS (email)",
    995: "POP3S (email)",
    587: "SMTP submission",
}


@dataclass
class ConnectionIntel:
    pid: int | None
    process_name: str | None
    exe_path: str | None
    remote_ip: str
    remote_port: int | None
    hostname: str | None
    org_hint: str | None
    port_meaning: str | None
    verdict: str  # observed | identity_unavailable
    summary: str
    detail_lines: list[str]


def reverse_dns(ip: str, timeout: float = 0.8) -> str | None:
    return net_resolve.resolve_blocking(ip, timeout=timeout)


def _org_from_host(hostname: str | None) -> str | None:
    if not hostname:
        return None
    for needle, label in ORG_HINTS:
        if host_matches_domain(hostname, needle):
            return f"Unverified PTR naming hint: {label}"
    return None


def _org_from_ip(ip: str) -> str | None:
    for prefix, label in IP_ORG_PREFIXES:
        if ip.startswith(prefix):
            return f"Unverified coarse IP-prefix hint: {label}"
    return None


def map_connections_to_processes() -> dict[tuple[str, int, str, int], tuple[int, str, str | None]]:
    """Map (remote_ip, remote_port, local_ip, local_port) -> (pid, name, exe).

    Per-process scan finds owners even when global net_connections() returns pid=None.
    """
    out: dict[tuple[str, int, str, int], tuple[int, str, str | None]] = {}
    for proc in psutil.process_iter(["pid", "name"]):
        try:
            pid = int(proc.info["pid"])
            name = proc.info.get("name") or f"pid-{pid}"
            try:
                exe = proc.exe()
            except (psutil.Error, OSError):
                exe = None
            for c in proc.net_connections(kind="inet"):
                if c.status != psutil.CONN_ESTABLISHED or not c.raddr or not c.laddr:
                    continue
                key = (c.raddr.ip, int(c.raddr.port), c.laddr.ip, int(c.laddr.port))
                out[key] = (pid, name, exe)
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
        except Exception:
            continue
    return out


def process_info(pid: int | None) -> tuple[str | None, str | None]:
    if pid is None:
        return None, None
    try:
        p = psutil.Process(pid)
        name = p.name()
        try:
            exe = p.exe()
        except (psutil.Error, OSError):
            exe = None
        return name, exe
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return None, None


def investigate(
    remote_ip: str,
    remote_port: int | None = None,
    pid: int | None = None,
    process_name: str | None = None,
    exe_path: str | None = None,
) -> ConnectionIntel:
    """Build a smart plain-English report for one remote peer."""
    hostname = reverse_dns(remote_ip)
    org = _org_from_host(hostname) or _org_from_ip(remote_ip)
    port_meaning = PORT_MEANING.get(int(remote_port), None) if remote_port else None

    name = process_name
    exe = exe_path
    if pid and (not name or not exe):
        n2, e2 = process_info(pid)
        name = name or n2
        exe = exe or e2

    if not name and pid is None:
        verdict = "elevated_unknown"
        who = "Unknown process (owner was not available in this observation; elevation may improve visibility)"
    elif not name:
        verdict = "review"
        who = f"PID {pid} (name unavailable)"
    else:
        who = name
        verdict = "review"

    # Names and shared-hosting hints do not determine trust or maliciousness.
    verdict = "identity_unavailable" if not name else "observed"

    lines = [
        f"Process: {who}" + (f"  PID {pid}" if pid else ""),
        f"Program path: {exe or 'unknown'}",
        f"Remote: {remote_ip}" + (f":{remote_port}" if remote_port else ""),
        f"Reverse-DNS hint (unverified): {hostname or 'unavailable'}",
        f"Organization hint: {org or 'unavailable'}",
        f"Port: {remote_port} ({port_meaning or 'uncommon / app-specific'})",
    ]

    summary = (
        f"{who} opened {port_meaning or 'a connection'} to {hostname or remote_ip}"
        + (f" ({org})" if org else "")
        + ". Connection observed; these metadata do not establish safety or maliciousness."
    )

    lines.append(f"Verdict: {verdict.replace('_', ' ')}")
    lines.append(f"Plain English: {summary}")

    return ConnectionIntel(
        pid=pid,
        process_name=name,
        exe_path=exe,
        remote_ip=remote_ip,
        remote_port=remote_port,
        hostname=hostname,
        org_hint=org,
        port_meaning=port_meaning,
        verdict=verdict,
        summary=summary,
        detail_lines=lines,
    )


def format_intel_block(intel: ConnectionIntel, ts: str | None = None) -> str:
    head = f"[{ts}] " if ts else ""
    body = "\n".join(f"    {line}" for line in intel.detail_lines)
    return f"{head}{intel.summary}\n{body}\n"

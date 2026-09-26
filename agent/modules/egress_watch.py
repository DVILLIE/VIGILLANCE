"""Public egress facts for the options engine. Does not block or kill."""

from __future__ import annotations

import ipaddress
import logging

import psutil

from agent.engine.watch import AI_PROCESS_NAMES, is_ai_host
from agent.modules.browser_guard import BROWSER_EXES
from agent.modules.connections import classify_remote
from agent.modules.microsoft_guard import _is_update_domain
from agent.modules.resource_advisor import SYSTEM_PROTECTED

logger = logging.getLogger("dvielle.egress")

_SKIP_KINDS = {
    "router",
    "lan_device",
    "lan_private",
    "vpn_or_cgnat",
    "dns",
    "loopback",
    "link_local",
    "invalid",
}
_MAX_FACTS = 40


def _public(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_multicast or addr.is_unspecified)


def facts_from_connections(rows: list[dict]) -> list[dict]:
    """Group measured connections. One fact per app. Does not invent hostnames."""
    grouped: dict[tuple[str, str], dict] = {}
    for row in rows:
        name = str(row.get("app_name") or "").strip()
        if not name or "|" in name or "\n" in name:
            continue
        if name.lower() in SYSTEM_PROTECTED:
            continue
        remote_ip = str(row.get("remote_ip") or "")
        host = str(row.get("host") or "")
        if host and _is_update_domain(host):
            continue
        ai = is_ai_host(host) or (name.lower() in AI_PROCESS_NAMES and _public(remote_ip))
        if not ai:
            if name.lower() in BROWSER_EXES:
                continue
            if not _public(remote_ip):
                continue
            kind, _text, _threat = classify_remote(remote_ip, host or None, None, [])
            if kind in _SKIP_KINDS or kind == "cdn_cloud":
                continue
        pillar = "ai_data" if ai else "privacy"
        key = (pillar, name.lower())
        app_open = bool(row.get("app_open", True))
        fact = grouped.get(key)
        if fact is None:
            grouped[key] = {
                "pillar": pillar,
                "app_name": name,
                "pid": int(row.get("pid") or 0),
                "path": str(row.get("path") or ""),
                "remote": remote_ip,
                "host": host,
                "app_open": app_open,
                "suspicious_mismatch": not app_open,
            }
            continue
        if not app_open:
            fact["app_open"] = False
            fact["suspicious_mismatch"] = True
        if host and not fact.get("host"):
            fact["host"] = host
    facts = list(grouped.values())
    return facts[:_MAX_FACTS]


def collect_egress_facts() -> list[dict] | None:
    """Live connections. None means the list could not be read. Empty means none qualified."""
    try:
        connections = psutil.net_connections(kind="inet")
    except (psutil.AccessDenied, PermissionError, OSError) as exc:
        logger.info("Egress list was not readable (%s). No privacy finding was invented.", exc)
        return None
    running: set[str] = set()
    try:
        for proc in psutil.process_iter(["name"]):
            proc_name = (proc.info or {}).get("name")
            if proc_name:
                running.add(str(proc_name).lower())
    except (psutil.Error, OSError) as exc:
        logger.info("Process list was not readable (%s). No privacy finding was invented.", exc)
        return None
    rows: list[dict] = []
    for conn in connections:
        if conn.status != psutil.CONN_ESTABLISHED or not conn.raddr or not conn.pid:
            continue
        remote_ip = conn.raddr.ip
        if not _public(remote_ip):
            continue
        try:
            proc = psutil.Process(conn.pid)
            name = proc.name() or ""
            path = ""
            try:
                path = proc.exe() or ""
            except (psutil.Error, OSError):
                path = ""
        except (psutil.Error, OSError):
            continue
        if not name:
            continue
        rows.append(
            {
                "app_name": name,
                "pid": int(conn.pid),
                "path": path,
                "remote_ip": remote_ip,
                "host": "",
                "app_open": name.lower() in running,
            }
        )
    _attach_hosts(rows)
    return facts_from_connections(rows)


def _attach_hosts(rows: list[dict], limit: int = 8) -> None:
    """Best-effort names for a few public addresses. Failure leaves the host blank."""
    from agent.modules.connections import _reverse_dns

    seen = 0
    cache: dict[str, str] = {}
    for row in rows:
        ip = str(row.get("remote_ip") or "")
        if not ip or row.get("host"):
            continue
        if ip not in cache:
            if seen >= limit:
                continue
            seen += 1
            try:
                cache[ip] = _reverse_dns(ip, timeout=0.3) or ""
            except OSError:
                cache[ip] = ""
        row["host"] = cache[ip]

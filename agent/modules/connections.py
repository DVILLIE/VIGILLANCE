"""Connection monitor — psutil-based, no packet sniffing."""

from __future__ import annotations

import logging
import socket
from dataclasses import dataclass
from typing import Any

import psutil

from agent.store.db import AgentStore
from agent.utils import ip_in_whitelist, show_toast

logger = logging.getLogger("fortoro.connections")


@dataclass
class ConnectionAlert:
    pid: int | None
    process_name: str | None
    local_addr: str
    remote_addr: str
    remote_ip: str
    remote_port: int | None
    reason: str


def _process_name(pid: int | None) -> str | None:
    if pid is None:
        return None
    try:
        return psutil.Process(pid).name()
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return None


def _reverse_dns(ip: str, timeout: float = 1.0) -> str | None:
    old_timeout = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(timeout)
        host, _, _ = socket.gethostbyaddr(ip)
        return host
    except (socket.herror, socket.gaierror, OSError):
        return None
    finally:
        socket.setdefaulttimeout(old_timeout)


def _domain_whitelisted(hostname: str | None, domains: list[str]) -> bool:
    if not hostname:
        return False
    host = hostname.lower()
    return any(d.lower() in host for d in domains)


def _process_whitelisted(name: str | None, processes: list[str]) -> bool:
    if not name:
        return False
    lower = name.lower()
    return any(p.lower() == lower for p in processes)


class ConnectionMonitor:
    def __init__(self, store: AgentStore, config: dict[str, Any], whitelists: dict[str, Any]) -> None:
        self.store = store
        self.config = config
        self.whitelists = whitelists
        self._seen_remote: set[str] = set()

    def run(self, monitor_only: bool = True) -> list[ConnectionAlert]:
        alerts: list[ConnectionAlert] = []
        ip_wl = self.whitelists.get("ips", [])
        proc_wl = self.whitelists.get("processes", [])
        domain_wl = self.whitelists.get("domains", [])

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
            proc_name = _process_name(pid)
            local = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else ""
            remote = f"{remote_ip}:{remote_port}"

            if proc_name:
                self.store.update_baseline_process(proc_name)

            suspicious = False
            reason = None

            if ip_in_whitelist(remote_ip, ip_wl):
                pass
            elif _process_whitelisted(proc_name, proc_wl):
                pass
            elif self.store.is_baseline_process(proc_name or ""):
                pass
            else:
                hostname = _reverse_dns(remote_ip)
                if _domain_whitelisted(hostname, domain_wl):
                    pass
                else:
                    suspicious = True
                    reason = f"unknown outbound to {remote}"
                    if hostname:
                        reason += f" ({hostname})"

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

            if suspicious and remote not in self._seen_remote:
                self._seen_remote.add(remote)
                alert = ConnectionAlert(
                    pid=pid,
                    process_name=proc_name,
                    local_addr=local,
                    remote_addr=remote,
                    remote_ip=remote_ip,
                    remote_port=remote_port,
                    reason=reason or "suspicious",
                )
                alerts.append(alert)
                self.store.log_event(
                    "connections",
                    "WARNING",
                    f"Suspicious connection: {proc_name} -> {remote}",
                    {"pid": pid, "reason": reason},
                )
                logger.warning("Suspicious: %s PID=%s %s -> %s", proc_name, pid, local, remote)

        return alerts

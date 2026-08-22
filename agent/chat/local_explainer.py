"""Offline plain-English answers from on-screen stats (no LLM required)."""

from __future__ import annotations

import re
from typing import Any

from agent.chat.personas import Persona


def _plain_ram(stats: dict[str, Any], persona: Persona) -> str:
    pct = stats.get("ram_percent", 0)
    free = stats.get("ram_available_gb", 0)
    if persona.id == "kt":
        if pct >= 90:
            return (
                f"Your memory is quite full — about {pct:.0f}% in use. "
                f"Only {free:.1f} gigabytes are free, so the PC may feel sluggish. "
                "Try closing a few apps you aren't using."
            )
        if pct >= 75:
            return (
                f"Memory is moderately busy at {pct:.0f}% — you've got {free:.1f} GB free. "
                "Nothing urgent, but don't open too many heavy programmes at once."
            )
        return (
            f"Memory looks healthy — {pct:.0f}% used with {free:.1f} GB still free. "
            "Your PC has breathing room."
        )
    if pct >= 90:
        return (
            f"RAM is critical at {pct:.0f}% — only {free:.1f} GB free. "
            "Close background apps or the system may slow down."
        )
    if pct >= 75:
        return (
            f"RAM is elevated at {pct:.0f}% with {free:.1f} GB free. "
            "You're fine for now, but avoid opening more heavy apps."
        )
    return f"RAM is healthy at {pct:.0f}% — {free:.1f} GB available."


def _plain_cpu(stats: dict[str, Any], persona: Persona) -> str:
    pct = stats.get("cpu_percent", 0)
    if persona.id == "kt":
        if pct >= 85:
            return f"The processor is working hard — {pct:.0f}% busy. Something may be running in the background."
        return f"Processor load is {pct:.0f}%. That's {'normal' if pct < 70 else 'a bit high'} for everyday use."
    if pct >= 85:
        return f"CPU is hot at {pct:.0f}%. Check Task Manager for what's eating cycles."
    return f"CPU at {pct:.0f}% — within normal range."


def _plain_disk(stats: dict[str, Any], persona: Persona) -> str:
    used = stats.get("disk_percent_used", 0)
    free = stats.get("disk_free_gb", 0)
    if persona.id == "kt":
        if used >= 90:
            return f"Your drive is nearly full — {used:.0f}% used, only {free:.1f} GB left. Time to clear some files."
        return f"Disk is {used:.0f}% full with {free:.1f} GB free — {'all right' if used < 80 else 'getting tight'}."
    if used >= 90:
        return f"Disk critical: {used:.0f}% used, {free:.1f} GB free. Free space soon."
    return f"Disk {used:.0f}% used, {free:.1f} GB free."


def _plain_vpn(stats: dict[str, Any], persona: Persona) -> str:
    if stats.get("vpn_active"):
        name = stats.get("vpn_name") or "VPN"
        ip = stats.get("vpn_ip") or "unknown"
        if persona.id == "kt":
            return f"Yes — your VPN is on ({name}). Your tunnel address is {ip}, so more of your traffic is private."
        return f"VPN active: {name}, tunnel IP {ip}. Traffic is routed through the VPN."
    if persona.id == "kt":
        return (
            f"No VPN detected. Your public IP is {stats.get('public_ip') or 'unknown'} — "
            "you're on a direct connection."
        )
    return f"No VPN detected. Public IP: {stats.get('public_ip') or 'unknown'}."


def _plain_summary(stats: dict[str, Any], persona: Persona) -> str:
    agent = "vigilance agent is running" if stats.get("agent_started") else "stats are live but agent is on standby"
    if persona.id == "kt":
        return (
            f"Right then — here's your machine at a glance. The {agent}. "
            f"CPU {stats.get('cpu_percent')}%, memory {stats.get('ram_percent')}%, "
            f"disk {stats.get('disk_percent_used')}% full. "
            f"{'VPN is on' if stats.get('vpn_active') else 'No VPN'}. "
            "Ask me about any of those if you'd like more detail."
        )
    return (
        f"Quick status: {agent}. "
        f"CPU {stats.get('cpu_percent')}%, RAM {stats.get('ram_percent')}%, "
        f"disk {stats.get('disk_percent_used')}% used. "
        f"{'VPN on' if stats.get('vpn_active') else 'VPN off'}. "
        "Ask about any metric for a plain-English breakdown."
    )


def local_answer(question: str, stats: dict[str, Any], persona: Persona) -> str | None:
    q = question.lower().strip()
    if not q:
        return None

    if re.search(r"\b(hello|hi|hey|good morning|good evening)\b", q):
        if persona.id == "kt":
            return "Hello there. I'm KT — ask me about your screen stats or say something aloud if you need a web lookup."
        return "Hello. Jarvis online — ask about your stats or use voice for web questions."

    if re.search(r"\b(ram|memory)\b", q):
        return _plain_ram(stats, persona)
    if re.search(r"\b(cpu|processor)\b", q):
        return _plain_cpu(stats, persona)
    if re.search(r"\b(disk|storage|drive|space)\b", q):
        return _plain_disk(stats, persona)
    if re.search(r"\b(vpn|tunnel)\b", q):
        return _plain_vpn(stats, persona)
    if re.search(r"\b(ip|public ip|local ip)\b", q):
        loc = ", ".join(stats.get("local_ips") or ["unknown"])
        pub = stats.get("public_ip") or "unknown"
        if persona.id == "kt":
            return f"Local address(es): {loc}. Public address: {pub}."
        return f"Local IP(s): {loc}. Public IP: {pub}."
    if re.search(r"\b(dns)\b", q):
        dns = ", ".join(stats.get("dns_servers") or ["unknown"])
        return f"DNS servers: {dns}."
    if re.search(r"\b(agent|vigilance|dvielle|status|stats|summary|screen|everything)\b", q):
        return _plain_summary(stats, persona)

    return None

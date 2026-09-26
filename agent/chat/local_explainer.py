"""Offline explanations constrained to available observations."""
from __future__ import annotations

import math
import re
from typing import Any

from agent.chat.context import format_stats_block, number, vpn_observation
from agent.chat.personas import Persona


def _value(stats: dict, key: str) -> float | None:
    value = stats.get(key)
    return float(value) if isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value) else None


def _plain_ram(stats: dict[str, Any]) -> str:
    pct, free, commit = (_value(stats, key) for key in ("ram_percent", "ram_available_gb", "commit_percent"))
    if pct is None and free is None and commit is None:
        return "Memory observations are unavailable or stale. I cannot assess current memory pressure."
    parts = []
    if pct is not None:
        parts.append(f"RAM is {pct:.0f}% in use")
    if free is not None:
        parts.append(f"{free:.1f} GB is available")
    if commit is not None:
        parts.append(f"commit usage is {commit:.0f}% of its limit")
    return "; ".join(parts) + ". Used RAM alone does not establish memory pressure; available memory and commit headroom matter."


def _plain_cpu(stats: dict[str, Any]) -> str:
    pct = _value(stats, "cpu_percent")
    if pct is None:
        return "CPU utilization is unavailable or stale. Wait for a current monitoring sample."
    return f"The latest CPU sample is {pct:.0f}% utilization. A single sample does not identify the cause, sustained contention, or processor temperature."


def _plain_disk(stats: dict[str, Any]) -> str:
    used, free = (_value(stats, key) for key in ("disk_percent_used", "disk_free_gb"))
    if used is None and free is None:
        return "Disk observations are unavailable or stale. I cannot assess current free space."
    result = f"Disk used percent: {number(used)}; free space in GB: {number(free, 1)}."
    if used is not None and used >= 90:
        result += " Space is limited. Review files before deleting anything."
    return result


def local_answer(question: str, stats: dict[str, Any], persona: Persona) -> str | None:
    q = question.lower().strip()
    if not q:
        return None
    if re.search(r"\b(hello|hi|hey|good morning|good evening)\b", q):
        return f"Hello. I'm {persona.name}. Ask me about the monitoring observations available to this console."
    if re.search(r"\b(ram|memory)\b", q):
        return _plain_ram(stats)
    if re.search(r"\b(cpu|processor)\b", q):
        return _plain_cpu(stats)
    if re.search(r"\b(disk|storage|drive|space)\b", q):
        return _plain_disk(stats)
    if re.search(r"\b(vpn|tunnel)\b", q):
        return vpn_observation(stats)
    if re.search(r"\b(ip|public ip|local ip)\b", q):
        return f"Local IP(s): {', '.join(stats.get('local_ips') or ['unavailable'])}. Public IP: {stats.get('public_ip') or 'unavailable or lookup disabled'}."
    if re.search(r"\b(dns)\b", q):
        return f"DNS servers: {', '.join(stats.get('dns_servers') or ['unavailable'])}."
    if re.search(r"\b(agent|vigilance|dvielle|status|stats|summary|screen|everything)\b", q):
        return format_stats_block(stats)
    return None

"""CapabilityReport — detect what this Windows (or host) can actually see.

Tiers (Future Architecture):
  T0 Standard user — limited visibility, explain gaps
  T1 Elevated — admin rights
  T2 Pro/Enterprise extras when present (not required)
  T3 Low-end / constrained (≤8 GB RAM or similar) — thinner Nerve

Primary sources:
- Win32_OperatingSystem (BuildNumber, Caption) — Microsoft Learn CIM
- IsInRole(Administrator) — .NET / Win32 elevation check pattern
- psutil for RAM / CPU when WMI unavailable
"""

from __future__ import annotations

import platform
import subprocess
from dataclasses import asdict, dataclass, field
from typing import Any

import psutil

from agent.utils import IS_WINDOWS


@dataclass
class CapabilityReport:
    tier: str  # T0 | T1 | T2 | T3 (T3 may combine with T0/T1)
    windows: bool
    os_caption: str | None
    os_build: str | None
    edition_hint: str | None  # Home / Pro / unknown
    is_admin: bool
    ram_total_gb: float
    cpu_count: int
    wmi_available: bool
    event_log_security_readable: bool | None  # None = not probed deeply
    defender_queryable: bool | None
    firewall_queryable: bool | None
    gpu_counters: bool | None
    battery_present: bool | None
    process_visibility: str  # full | partial | unknown
    network_visibility: str
    gaps: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _is_admin() -> bool:
    if not IS_WINDOWS:
        return False
    try:
        import ctypes

        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _os_info() -> tuple[str | None, str | None, str | None, bool]:
    """Return caption, build, edition_hint, wmi_ok."""
    if not IS_WINDOWS:
        return platform.platform(), None, None, False
    try:
        ps = (
            "Get-CimInstance Win32_OperatingSystem | "
            "Select-Object -ExpandProperty Caption; "
            "Get-CimInstance Win32_OperatingSystem | "
            "Select-Object -ExpandProperty BuildNumber"
        )
        result = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps],
            capture_output=True,
            text=True,
            timeout=15,
            creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, "CREATE_NO_WINDOW") else 0,
        )
        lines = [ln.strip() for ln in result.stdout.splitlines() if ln.strip()]
        if len(lines) >= 2:
            caption, build = lines[0], lines[1]
            low = caption.lower()
            if "home" in low:
                edition = "Home"
            elif "pro" in low or "enterprise" in low or "education" in low:
                edition = "ProOrHigher"
            else:
                edition = "Unknown"
            return caption, build, edition, True
    except Exception:
        pass
    return platform.platform(), None, None, False


def _battery_present() -> bool | None:
    try:
        bat = psutil.sensors_battery()
        if bat is None:
            return False
        return True
    except Exception:
        return None


def probe_capabilities(*, deep: bool = False) -> CapabilityReport:
    """Build CapabilityReport. ``deep`` reserved for Event Log / Defender probes (pulse)."""
    gaps: list[str] = []
    notes: list[str] = []
    caption, build, edition, wmi_ok = _os_info()
    if not wmi_ok and IS_WINDOWS:
        gaps.append("wmi_cim_unavailable")
    admin = _is_admin()
    if IS_WINDOWS and not admin:
        gaps.append("not_elevated_partial_process_and_event_visibility")
        notes.append("Partial vision: protected processes and Security log may be incomplete without Admin.")

    ram_gb = round(psutil.virtual_memory().total / (1024**3), 2)
    cpu_n = psutil.cpu_count(logical=True) or 1

    tiers = ["T0"]
    if admin:
        tiers = ["T1"]
    if edition == "ProOrHigher":
        # Capability present; features still degrade if APIs missing
        if "T1" in tiers or admin:
            tiers.append("T2")
        else:
            notes.append("Pro/Enterprise edition detected but running as standard user (T0+T2_sku).")
            tiers.append("T2_sku")
    if ram_gb <= 8.0:
        tiers.append("T3")
        notes.append("Low-end RAM tier: prefer thinner Nerve (event + heartbeat; defer idle-deep).")

    primary = "T1" if admin else "T0"
    if "T3" in tiers:
        primary = f"{primary}+T3"

    event_log: bool | None = None
    defender: bool | None = None
    firewall: bool | None = None
    if deep and IS_WINDOWS:
        # Lightweight existence checks only — not full collection
        try:
            r = subprocess.run(
                [
                    "powershell",
                    "-NoProfile",
                    "-NonInteractive",
                    "-Command",
                    "try { Get-WinEvent -LogName Security -MaxEvents 1 -ErrorAction Stop | Out-Null; 'ok' } catch { 'no' }",
                ],
                capture_output=True,
                text=True,
                timeout=20,
                creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, "CREATE_NO_WINDOW") else 0,
            )
            event_log = "ok" in (r.stdout or "")
            if not event_log:
                gaps.append("security_event_log_unreadable")
        except Exception:
            event_log = False
            gaps.append("security_event_log_probe_failed")

    return CapabilityReport(
        tier=primary,
        windows=IS_WINDOWS,
        os_caption=caption,
        os_build=build,
        edition_hint=edition,
        is_admin=admin,
        ram_total_gb=ram_gb,
        cpu_count=int(cpu_n),
        wmi_available=wmi_ok,
        event_log_security_readable=event_log,
        defender_queryable=defender,
        firewall_queryable=firewall,
        gpu_counters=None,
        battery_present=_battery_present(),
        process_visibility="full" if admin else ("partial" if IS_WINDOWS else "unknown"),
        network_visibility="user" if IS_WINDOWS else "unknown",
        gaps=gaps,
        notes=notes,
    )

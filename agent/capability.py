"""CapabilityReport — honest visibility states (P0.5).

States: AVAILABLE | LIMITED | UNKNOWN | UNAVAILABLE
Never claim full vision when probes are None/unrun.
"""

from __future__ import annotations

import platform
import subprocess
from dataclasses import asdict, dataclass, field
from typing import Any, Literal

import psutil

from agent.utils import IS_WINDOWS

CapState = Literal["AVAILABLE", "LIMITED", "UNKNOWN", "UNAVAILABLE"]


@dataclass
class CapabilityReport:
    tier: str
    windows: bool
    os_caption: str | None
    os_build: str | None
    edition_hint: str | None
    is_admin: bool
    ram_total_gb: float
    cpu_count: int
    wmi: CapState
    event_log_security: CapState
    defender: CapState
    firewall: CapState
    gpu_counters: CapState
    battery: CapState
    process_visibility: CapState
    network_visibility: CapState
    overall_vision: CapState
    gaps: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    # Back-compat aliases used by older Twin code
    @property
    def wmi_available(self) -> bool:
        return self.wmi == "AVAILABLE"

    @property
    def event_log_security_readable(self) -> bool | None:
        if self.event_log_security == "UNKNOWN":
            return None
        return self.event_log_security == "AVAILABLE"

    @property
    def defender_queryable(self) -> bool | None:
        if self.defender == "UNKNOWN":
            return None
        return self.defender == "AVAILABLE"

    @property
    def firewall_queryable(self) -> bool | None:
        if self.firewall == "UNKNOWN":
            return None
        return self.firewall == "AVAILABLE"

    @property
    def battery_present(self) -> bool | None:
        if self.battery == "UNKNOWN":
            return None
        return self.battery == "AVAILABLE"

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


def _os_info() -> tuple[str | None, str | None, str | None, CapState]:
    if not IS_WINDOWS:
        return platform.platform(), None, None, "UNAVAILABLE"
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
            return caption, build, edition, "AVAILABLE"
    except Exception:
        pass
    return platform.platform(), None, None, "UNAVAILABLE"


def _battery_state() -> CapState:
    try:
        bat = psutil.sensors_battery()
        if bat is None:
            return "UNAVAILABLE"
        return "AVAILABLE"
    except Exception:
        return "UNKNOWN"


def _worst(*states: CapState) -> CapState:
    order = {"AVAILABLE": 0, "LIMITED": 1, "UNKNOWN": 2, "UNAVAILABLE": 3}
    return max(states, key=lambda s: order[s])


def probe_capabilities(*, deep: bool = False) -> CapabilityReport:
    gaps: list[str] = []
    notes: list[str] = []
    caption, build, edition, wmi = _os_info()
    if wmi != "AVAILABLE" and IS_WINDOWS:
        gaps.append("wmi_cim_unavailable")
    admin = _is_admin()

    process_vis: CapState = "AVAILABLE" if admin else ("LIMITED" if IS_WINDOWS else "UNKNOWN")
    network_vis: CapState = "LIMITED" if IS_WINDOWS else "UNKNOWN"
    if IS_WINDOWS and not admin:
        gaps.append("not_elevated_partial_process_and_event_visibility")
        notes.append("LIMITED vision: protected processes / Security log may be incomplete without Admin.")

    ram_gb = round(psutil.virtual_memory().total / (1024**3), 2)
    cpu_n = psutil.cpu_count(logical=True) or 1

    primary = "T1" if admin else "T0"
    if edition == "ProOrHigher" and not admin:
        notes.append("Pro/Enterprise SKU detected but running as standard user.")
    if ram_gb <= 8.0:
        primary = f"{primary}+T3"
        notes.append("Low-end RAM tier: prefer thinner Nerve.")

    event_log: CapState = "UNKNOWN"
    defender: CapState = "UNKNOWN"
    firewall: CapState = "UNKNOWN"
    if deep and IS_WINDOWS:
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
            event_log = "AVAILABLE" if "ok" in (r.stdout or "") else "UNAVAILABLE"
            if event_log != "AVAILABLE":
                gaps.append("security_event_log_unreadable")
        except Exception:
            event_log = "UNKNOWN"
            gaps.append("security_event_log_probe_failed")
    elif not IS_WINDOWS:
        event_log = defender = firewall = "UNAVAILABLE"

    overall = _worst(process_vis, network_vis, wmi, event_log if deep else "UNKNOWN")
    if gaps and overall == "AVAILABLE":
        overall = "LIMITED"

    return CapabilityReport(
        tier=primary,
        windows=IS_WINDOWS,
        os_caption=caption,
        os_build=build,
        edition_hint=edition,
        is_admin=admin,
        ram_total_gb=ram_gb,
        cpu_count=int(cpu_n),
        wmi=wmi,
        event_log_security=event_log,
        defender=defender,
        firewall=firewall,
        gpu_counters="UNKNOWN",
        battery=_battery_state(),
        process_visibility=process_vis,
        network_visibility=network_vis,
        overall_vision=overall,
        gaps=gaps,
        notes=notes,
    )

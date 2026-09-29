"""CapabilityReport — honest visibility states (P0.5).

States: AVAILABLE | LIMITED | UNKNOWN | UNAVAILABLE
Never claim full vision when probes are None/unrun.
"""

from __future__ import annotations

import platform
import sys
from dataclasses import asdict, dataclass, field
from typing import Any, Literal

import psutil

from agent.edition_matrix import EditionMatrix, build_edition_matrix, classify_sku, interpret_sac
from agent.utils import IS_WINDOWS, run_powershell

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
    edition_sku: str = "Unknown"
    edition_id: str | None = None
    feature_matrix: dict[str, str] = field(default_factory=dict)
    matrix_notes: list[str] = field(default_factory=list)
    smart_app_control_mode: str | None = None

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
        stdout, _ = run_powershell(ps, timeout=15)
        lines = [ln.strip() for ln in (stdout or "").splitlines() if ln.strip()]
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
    return _basic_os()[0], None, None, "UNAVAILABLE"


def _basic_os() -> tuple[str, str]:
    """Shallow boot must not call platform.uname()/platform()/version().

    On Windows those can pull native WMI. On other systems sys.platform is enough;
    a deeper caption waits for the idle probe.
    """
    if sys.platform == "win32":
        version = sys.getwindowsversion()
        return f"Windows NT {version.major}.{version.minor} (build {version.build})", str(version.build)
    return sys.platform, ""


def _read_edition_id() -> str | None:
    if not IS_WINDOWS:
        return None
    try:
        import winreg

        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
        ) as key:
            value, _kind = winreg.QueryValueEx(key, "EditionID")
            return value if isinstance(value, str) and value else None
    except OSError:
        return None


def _read_sac() -> tuple[str | None, CapState]:
    """Probe Smart App Control. Learn documents the DWORD; a miss stays UNKNOWN."""
    if not IS_WINDOWS:
        return None, "UNAVAILABLE"
    try:
        import winreg

        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Control\CI\Policy",
        ) as key:
            value, kind = winreg.QueryValueEx(key, "VerifiedAndReputablePolicyState")
            readable = kind == winreg.REG_DWORD
            return interpret_sac(value if readable else None, readable=readable, windows=True)
    except OSError:
        return None, "UNKNOWN"


def current_edition_matrix(caption: str | None = None) -> EditionMatrix:
    """SKU matrix from the registry and an optional CIM caption. No Defender mutation."""
    if not IS_WINDOWS:
        return build_edition_matrix("NonWindows")
    edition_id = _read_edition_id()
    mode, state = _read_sac()
    sku = classify_sku(edition_id, caption, windows=True)
    return build_edition_matrix(
        sku,
        edition_id=edition_id,
        smart_app_control=state,
        smart_app_control_mode=mode,
    )


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
    if deep:
        caption, build, _caption_edition, wmi = _os_info()
    else:
        # Boot never launches WMI/PowerShell. Deep capability probing is deferred.
        caption, build = _basic_os()
        wmi = "UNKNOWN"
    matrix = current_edition_matrix(caption if deep else None)
    edition = matrix.sku
    if wmi == "UNAVAILABLE" and IS_WINDOWS:
        gaps.append("wmi_cim_unavailable")
    elif wmi == "UNKNOWN":
        notes.append("Deep WMI and event-log probes have not run; capability is unverified.")
    admin = _is_admin()

    # Elevation alone does not prove visibility into every protected process.
    process_vis: CapState = "LIMITED" if IS_WINDOWS else "UNKNOWN"
    network_vis: CapState = "LIMITED" if IS_WINDOWS else "UNKNOWN"
    if IS_WINDOWS and not admin:
        gaps.append("not_elevated_partial_process_and_event_visibility")
        notes.append("LIMITED vision: protected processes / Security log may be incomplete without Admin.")

    ram_gb = round(psutil.virtual_memory().total / (1024**3), 2)
    cpu_n = psutil.cpu_count(logical=True) or 1

    primary = "T1" if admin else "T0"
    if edition == "ProOrHigher" and not admin:
        notes.append("Pro/Enterprise SKU detected but running as standard user.")
    if edition == "Home":
        notes.append("Windows Sandbox and App Control authoring are unavailable on this Home SKU.")
    if ram_gb <= 8.0:
        primary = f"{primary}+T3"
        notes.append("Low-end RAM tier: prefer thinner Nerve.")

    event_log: CapState = "UNKNOWN"
    defender: CapState = "UNKNOWN"
    firewall: CapState = "UNKNOWN"
    if deep and IS_WINDOWS:
        try:
            stdout, _ = run_powershell(
                "try { Get-WinEvent -LogName Security -MaxEvents 1 -ErrorAction Stop | Out-Null; 'ok' } catch { 'no' }",
                timeout=20,
            )
            event_log = "AVAILABLE" if "ok" in (stdout or "") else "UNAVAILABLE"
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
        edition_sku=matrix.sku,
        edition_id=matrix.edition_id,
        feature_matrix=dict(matrix.features),
        matrix_notes=list(matrix.notes),
        smart_app_control_mode=matrix.smart_app_control_mode,
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

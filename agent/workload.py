"""Conservative workload hypothesis from cheap measured signals, not intent claims.

No process enumeration on heartbeat. Busy work gets thinner observation; unknown
input state cannot qualify the PC for idle-deep analysis.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
import math

from agent.utils import IS_WINDOWS, get_foreground_process


def idle_seconds() -> float | None:
    if not IS_WINDOWS:
        return None
    try:
        import ctypes
        from ctypes import wintypes
        class LASTINPUTINFO(ctypes.Structure):
            _fields_ = [("cbSize", wintypes.UINT), ("dwTime", wintypes.DWORD)]
        info = LASTINPUTINFO()
        info.cbSize = ctypes.sizeof(info)
        user32, kernel32 = ctypes.windll.user32, ctypes.windll.kernel32
        user32.GetLastInputInfo.argtypes = [ctypes.POINTER(LASTINPUTINFO)]
        user32.GetLastInputInfo.restype = wintypes.BOOL
        kernel32.GetTickCount.restype = wintypes.DWORD
        if not user32.GetLastInputInfo(ctypes.byref(info)):
            return None
        return ((kernel32.GetTickCount() - info.dwTime) & 0xffffffff) / 1000.0
    except (AttributeError, OSError):
        return None


@dataclass
class WorkloadState:
    profile: str
    maximum: bool
    idle: bool
    reason: str
    foreground_pid: int | None
    foreground_name: str | None
    idle_seconds: float | None

    def to_dict(self) -> dict:
        return asdict(self)


class WorkloadTracker:
    def __init__(self, config: dict):
        cfg = config.get("workload", {})
        names = cfg.get("protected_foreground_processes", [])
        if not isinstance(names, list) or any(not isinstance(x, str) for x in names):
            raise ValueError("workload.protected_foreground_processes must be a list of names")
        self.protected = {x.lower() for x in names}
        self.high_cpu = float(cfg.get("busy_cpu_percent", 80))
        self.idle_after = float(cfg.get("idle_after_seconds", 120))
        if not math.isfinite(self.high_cpu) or not 10 < self.high_cpu <= 100:
            raise ValueError("workload.busy_cpu_percent must be greater than 10 and at most 100")
        if not math.isfinite(self.idle_after) or self.idle_after <= 0:
            raise ValueError("workload.idle_after_seconds must be finite and positive")
        self.idle_after = max(30.0, self.idle_after)
        self.busy_streak = 0
        self.recovery_streak = 0
        self.busy = False

    def update(self, cpu: float | None, pressure: bool, *, foreground: tuple,
               inactive: float | None) -> WorkloadState:
        pid, name = foreground
        high = cpu is not None and cpu >= self.high_cpu
        self.busy_streak = self.busy_streak + 1 if high else 0
        self.recovery_streak = self.recovery_streak + 1 if cpu is not None and cpu < self.high_cpu - 10 else 0
        if self.busy_streak >= 3:
            self.busy = True
        elif self.recovery_streak >= 3:
            self.busy = False
        protected = bool(name and name.lower() in self.protected)
        maximum = self.busy or pressure or protected
        idle = bool(not maximum and inactive is not None and inactive >= self.idle_after
                    and cpu is not None and cpu < 20)
        if pressure:
            profile, reason = "PRESSURE", "Measured memory pressure; optional collection deferred"
        elif protected:
            profile, reason = "PROTECTED", f"Configured foreground workload: {name}; optional collection deferred"
        elif self.busy:
            profile, reason = "BUSY", "Sustained measured CPU demand; optional collection deferred"
        elif idle:
            profile, reason = "IDLE", "Low CPU and no recent session input"
        elif cpu is None or inactive is None:
            profile, reason = "UNKNOWN", "Workload signals incomplete; idle-deep is withheld"
        else:
            profile, reason = "INTERACTIVE", "Session input detected; intent and application purpose remain unverified"
        return WorkloadState(profile, maximum, idle, reason, pid, name, inactive)

    def sample(self, cpu: float | None, pressure: bool) -> WorkloadState:
        return self.update(cpu, pressure, foreground=get_foreground_process(), inactive=idle_seconds())

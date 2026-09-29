"""Published CPU contracts for the resident agent and the analysis helper.

Idle observation uses measured scheduling: the existing self-budget defers
optional nerve collectors after a sustained overrun. That is not an OS hard cap.

The analysis helper may place its own process in a Windows Job Object with
CPU rate control. Microsoft documents ``CpuRate`` as percentage times 100
(20% is 2000). Rate 0 is invalid. The hard cap is interval-based. It cannot
be used under Remote Desktop Services when Dynamic Fair Share Scheduling is
in effect.

https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-jobobject_cpu_rate_control_information
fetched 2026-09-29.

This module never terminates another process. A failed assignment stays on
measured scheduling and says so.
"""

from __future__ import annotations

import math
from typing import Any

from agent.utils import IS_WINDOWS

# DVielle's published helper cap, not a figure copied from another product.
PUBLISHED_ANALYSIS_CPU_PERCENT = 20
PUBLISHED_ANALYSIS_CPU_RATE = PUBLISHED_ANALYSIS_CPU_PERCENT * 100
_JOB_CPU_RATE_CONTROL = 15
_ENABLE = 0x1
_HARD_CAP = 0x4

_JOB_HANDLE: list[int] = []

DFSS_NOTE = (
    "CPU rate control cannot be used by a job under Remote Desktop Services "
    "when Dynamic Fair Share Scheduling is in effect."
)
MEASURED_NOTE = (
    "The resident task uses measured scheduling. Optional collectors defer after "
    "three heartbeats over the configured CPU or memory budget. User applications are not terminated."
)


def _positive(raw: object, default: float) -> float:
    try:
        value = float(raw)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return default
    if not math.isfinite(value) or value <= 0:
        return default
    return value


def _analysis_percent(raw: object) -> int:
    try:
        value = int(raw)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return PUBLISHED_ANALYSIS_CPU_PERCENT
    if isinstance(raw, bool) or value < 1 or value > PUBLISHED_ANALYSIS_CPU_PERCENT:
        return PUBLISHED_ANALYSIS_CPU_PERCENT
    return value


def published_contract(config: dict[str, Any] | None = None, *, job: dict[str, Any] | None = None) -> dict[str, Any]:
    """Limits that belong in the twin. ``job`` is the helper assignment result, if any."""
    budget = {}
    if isinstance(config, dict) and isinstance(config.get("budget"), dict):
        budget = config["budget"]
    percent = _analysis_percent(budget.get("analysis_cpu_percent", PUBLISHED_ANALYSIS_CPU_PERCENT))
    applied = bool(job and job.get("applied"))
    reason = str((job or {}).get("reason") or MEASURED_NOTE)
    return {
        "scheduling_mode": "job_hard_cap" if applied else "measured",
        "measured_cpu_percent": _positive(budget.get("max_cpu_percent"), 1.0),
        "measured_rss_mb": _positive(budget.get("max_rss_mb"), 150.0),
        "analysis_cpu_percent": percent,
        "analysis_cpu_rate": percent * 100,
        "cpu_rate_unit": "percentage times 100",
        "job_cap_applied": applied,
        "job_cap_reason": reason,
        "terminates_other_processes": False,
        "assumptions": [
            "CpuRate is percentage times 100. CpuRate 0 is invalid and is not sent.",
            "A hard cap stops the job's threads until the next scheduling interval. It is not zero cost.",
            DFSS_NOTE,
            "Nested jobs take a portion of the parent rate. Minimum rates across jobs cannot sum above 100%.",
            MEASURED_NOTE,
            "20% (CpuRate 2000) is DVielle's published analysis-helper cap. It is not a Microsoft-mandated agent budget.",
        ],
    }


def try_assign_current_process(cpu_percent: int = PUBLISHED_ANALYSIS_CPU_PERCENT) -> dict[str, Any]:
    """Assign this process to a hard-capped job. Linux and any API failure stay measured."""
    percent = _analysis_percent(cpu_percent)
    rate = percent * 100
    if rate <= 0:
        return {"applied": False, "reason": "CpuRate must not be 0. " + MEASURED_NOTE}
    if not IS_WINDOWS:
        return {
            "applied": False,
            "reason": "Job Objects are a Windows API. This process uses measured scheduling. " + DFSS_NOTE,
        }
    try:
        import ctypes
        from ctypes import wintypes
    except ImportError:
        return {"applied": False, "reason": "The Windows ctypes bridge is unavailable. " + MEASURED_NOTE}

    class _CpuRate(ctypes.Structure):
        _fields_ = [("ControlFlags", wintypes.DWORD), ("CpuRate", wintypes.DWORD)]

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
    kernel32.CreateJobObjectW.restype = ctypes.c_void_p
    kernel32.SetInformationJobObject.argtypes = [
        ctypes.c_void_p,
        ctypes.c_int,
        ctypes.c_void_p,
        wintypes.DWORD,
    ]
    kernel32.SetInformationJobObject.restype = wintypes.BOOL
    kernel32.AssignProcessToJobObject.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
    kernel32.AssignProcessToJobObject.restype = wintypes.BOOL
    kernel32.GetCurrentProcess.restype = ctypes.c_void_p
    kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
    kernel32.CloseHandle.restype = wintypes.BOOL

    handle = kernel32.CreateJobObjectW(None, None)
    if not handle:
        err = ctypes.get_last_error()
        return {
            "applied": False,
            "reason": f"CreateJobObject failed ({err}). {MEASURED_NOTE} {DFSS_NOTE}",
        }
    info = _CpuRate(_ENABLE | _HARD_CAP, rate)
    if not kernel32.SetInformationJobObject(handle, _JOB_CPU_RATE_CONTROL, ctypes.byref(info), ctypes.sizeof(info)):
        err = ctypes.get_last_error()
        kernel32.CloseHandle(handle)
        return {
            "applied": False,
            "reason": f"SetInformationJobObject failed ({err}). {MEASURED_NOTE} {DFSS_NOTE}",
        }
    if not kernel32.AssignProcessToJobObject(handle, kernel32.GetCurrentProcess()):
        err = ctypes.get_last_error()
        kernel32.CloseHandle(handle)
        return {
            "applied": False,
            "reason": f"AssignProcessToJobObject failed ({err}). {MEASURED_NOTE} {DFSS_NOTE}",
        }
    _JOB_HANDLE.append(int(handle))
    return {
        "applied": True,
        "reason": (
            f"Analysis helper hard cap is {percent}% (CpuRate {rate}). "
            "The cap applies to this helper process only. " + DFSS_NOTE
        ),
    }

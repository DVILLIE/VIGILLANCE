"""Cheap Windows memory / commit counters for Adaptive Nerve FAST HEARTBEAT.

Verified primary sources (CURRENT research):
- MEMORYSTATUSEX / GlobalMemoryStatusEx — Microsoft Learn sysinfoapi
  https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/ns-sysinfoapi-memorystatusex
  ullAvailPhys = standby + free + zero (immediately reusable physical RAM).
  For *system-wide* commit, Learn directs to GetPerformanceInfo.
- PERFORMANCE_INFORMATION / GetPerformanceInfo — Microsoft Learn psapi
  https://learn.microsoft.com/en-us/windows/win32/api/psapi/ns-psapi-performance_information
  CommitTotal / CommitLimit are page counts; multiply by PageSize for bytes.
- AskPerf / PerfGuide: Available MBytes + % Committed Bytes In Use as primary
  physical vs commit pressure indicators (not “RAM % used alone”).

Non-Windows: psutil best-effort fallback; commit fields may be None.
"""

from __future__ import annotations

import platform
from dataclasses import dataclass
from typing import Any

import psutil

IS_WINDOWS = platform.system() == "Windows"


@dataclass(frozen=True)
class MemorySnapshot:
    """Pressure-oriented vector (v0). Scores come later in Policy Cortex."""

    total_phys_bytes: int
    avail_phys_bytes: int
    memory_load_percent: float
    commit_total_bytes: int | None
    commit_limit_bytes: int | None
    commit_percent: float | None
    process_count: int | None
    thread_count: int | None
    source: str  # "GetPerformanceInfo+MEMORYSTATUSEX" | "psutil" | "partial"

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_phys_bytes": self.total_phys_bytes,
            "avail_phys_bytes": self.avail_phys_bytes,
            "avail_phys_mb": round(self.avail_phys_bytes / (1024 * 1024), 1),
            "memory_load_percent": round(self.memory_load_percent, 2),
            "commit_total_bytes": self.commit_total_bytes,
            "commit_limit_bytes": self.commit_limit_bytes,
            "commit_percent": None if self.commit_percent is None else round(self.commit_percent, 2),
            "process_count": self.process_count,
            "thread_count": self.thread_count,
            "source": self.source,
        }


def _snapshot_windows() -> MemorySnapshot:
    import ctypes
    from ctypes import wintypes

    class MEMORYSTATUSEX(ctypes.Structure):
        _fields_ = [
            ("dwLength", wintypes.DWORD),
            ("dwMemoryLoad", wintypes.DWORD),
            ("ullTotalPhys", ctypes.c_uint64),
            ("ullAvailPhys", ctypes.c_uint64),
            ("ullTotalPageFile", ctypes.c_uint64),
            ("ullAvailPageFile", ctypes.c_uint64),
            ("ullTotalVirtual", ctypes.c_uint64),
            ("ullAvailVirtual", ctypes.c_uint64),
            ("ullAvailExtendedVirtual", ctypes.c_uint64),
        ]

    class PERFORMANCE_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("cb", wintypes.DWORD),
            ("CommitTotal", ctypes.c_size_t),
            ("CommitLimit", ctypes.c_size_t),
            ("CommitPeak", ctypes.c_size_t),
            ("PhysicalTotal", ctypes.c_size_t),
            ("PhysicalAvailable", ctypes.c_size_t),
            ("SystemCache", ctypes.c_size_t),
            ("KernelTotal", ctypes.c_size_t),
            ("KernelPaged", ctypes.c_size_t),
            ("KernelNonpaged", ctypes.c_size_t),
            ("PageSize", ctypes.c_size_t),
            ("HandleCount", wintypes.DWORD),
            ("ProcessCount", wintypes.DWORD),
            ("ThreadCount", wintypes.DWORD),
        ]

    mem = MEMORYSTATUSEX()
    mem.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
    if not ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(mem)):
        raise OSError("GlobalMemoryStatusEx failed")

    commit_total: int | None = None
    commit_limit: int | None = None
    commit_pct: float | None = None
    proc_count: int | None = None
    thread_count: int | None = None
    source = "MEMORYSTATUSEX"

    perf = PERFORMANCE_INFORMATION()
    perf.cb = ctypes.sizeof(PERFORMANCE_INFORMATION)
    # Prefer Kernel32 K32GetPerformanceInfo (Win7+); fall back to Psapi.dll
    ok = False
    for dll_name, fn_name in (("kernel32", "K32GetPerformanceInfo"), ("psapi", "GetPerformanceInfo")):
        try:
            dll = getattr(ctypes.windll, dll_name)
            fn = getattr(dll, fn_name)
            fn.argtypes = [ctypes.POINTER(PERFORMANCE_INFORMATION), wintypes.DWORD]
            fn.restype = wintypes.BOOL
            ok = bool(fn(ctypes.byref(perf), perf.cb))
            if ok:
                source = "GetPerformanceInfo+MEMORYSTATUSEX"
                break
        except (AttributeError, OSError):
            continue

    if ok and perf.PageSize:
        commit_total = int(perf.CommitTotal * perf.PageSize)
        commit_limit = int(perf.CommitLimit * perf.PageSize)
        if commit_limit > 0:
            commit_pct = 100.0 * commit_total / commit_limit
        proc_count = int(perf.ProcessCount)
        thread_count = int(perf.ThreadCount)

    return MemorySnapshot(
        total_phys_bytes=int(mem.ullTotalPhys),
        avail_phys_bytes=int(mem.ullAvailPhys),
        memory_load_percent=float(mem.dwMemoryLoad),
        commit_total_bytes=commit_total,
        commit_limit_bytes=commit_limit,
        commit_percent=commit_pct,
        process_count=proc_count,
        thread_count=thread_count,
        source=source,
    )


def _snapshot_psutil() -> MemorySnapshot:
    vm = psutil.virtual_memory()
    return MemorySnapshot(
        total_phys_bytes=int(vm.total),
        avail_phys_bytes=int(vm.available),
        memory_load_percent=float(vm.percent),
        commit_total_bytes=None,
        commit_limit_bytes=None,
        commit_percent=None,
        process_count=None,
        thread_count=None,
        source="psutil",
    )


def sample_memory() -> MemorySnapshot:
    """FAST HEARTBEAT-safe: no process enumeration, no DNS, no SQLite."""
    if IS_WINDOWS:
        try:
            return _snapshot_windows()
        except Exception:
            return _snapshot_psutil()
    return _snapshot_psutil()


AVAIL_FLOOR_MB = 256.0
AVAIL_FLOOR_FRACTION = 0.05  # Microsoft: Available MBytes < 5% of RAM = insufficient
COMMIT_PRESSURE_PERCENT = 85.0  # % Committed Bytes In Use (Committed / Commit Limit)


def memory_under_pressure(snap: MemorySnapshot) -> bool:
    """The single memory-pressure predicate, shared by RamMonitor and ResourceAdvisor.

    Microsoft-endorsed signals ONLY (never raw used% / memory_load): physical
    availability and commit ratio.
      - Available < max(256 MB, 5% of RAM)  — Available MBytes < 5% = insufficient RAM.
      - % Committed Bytes In Use >= 85       — commit approaching the commit limit.
    ullAvailPhys already includes the (reclaimable) standby list, so a machine whose
    "used %" is high purely from cache is NOT flagged. When commit_percent is
    unavailable (psutil-only fallback), use availability alone — never invent commit.
    """
    total_mb = snap.total_phys_bytes / (1024 * 1024)
    avail_mb = snap.avail_phys_bytes / (1024 * 1024)
    if avail_mb < max(AVAIL_FLOOR_MB, total_mb * AVAIL_FLOOR_FRACTION):
        return True
    if snap.commit_percent is not None and snap.commit_percent >= COMMIT_PRESSURE_PERCENT:
        return True
    return False

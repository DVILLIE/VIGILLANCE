"""Glue between monitors, the desktop close dialog, and the shared engine."""

from __future__ import annotations

import ctypes
import os

from agent.engine.handlers import HandlerContext, default_close, default_lookup
from agent.engine.loop import ResolutionEngine
from agent.engine.models import Observation
from agent.engine.observations import (
    from_advice_offenders,
    from_disk_status,
    from_security,
    from_speed_sample,
    startup_observations,
)
from agent.engine.footprint import FootprintProgress, collect_footprint_facts, observation_from_footprint
from agent.engine.watch import observation_from_camera, observation_from_egress
from agent.learn.memory import SafetyBaseline
from agent.modules.resource_advisor import SYSTEM_PROTECTED
from agent.store.db import AgentStore, utc_now


def engine_for(store: AgentStore, **kwargs) -> ResolutionEngine:
    return ResolutionEngine(store, **kwargs)


def ingest_monitors(
    store: AgentStore,
    *,
    security=None,
    advice=None,
    disks=None,
    startup_items=None,
    egress_facts=None,
    camera_facts=None,
    footprint_facts=None,
    collect_live: bool = False,
    experience=None,
    sample_times: dict[str, str] | None = None,
) -> list[dict]:
    """Ingest independent sources; eligible actions still pass the engine's DualGate."""
    engine = engine_for(store, experience=experience)
    results: list[dict] = []
    sample_times = dict(sample_times or {})

    def attempt(source, callback, *, collecting=False):
        try:
            value = callback()
            if collecting and value is not None:
                sample_times[source] = utc_now()
            if collecting and value is None:
                results.append({"disposition": "unavailable", "source": source,
                                "finding": None, "mutated": False})
            elif collecting and getattr(value, 'coverage_complete', True) is False:
                results.append({'disposition': 'unavailable', 'source': source,
                                'error': value.coverage_detail, 'finding': None, 'mutated': False})
            return value
        except Exception as exc:
            results.append({"disposition": "error", "source": source,
                            "error": f"{type(exc).__name__}: {exc}"[:500],
                            "finding": None, "mutated": False if collecting else None})
            return None

    def evaluate(source, convert):
        observations = attempt(source, convert)
        for obs in observations or []:
            if obs is not None:
                if source in sample_times:
                    stamp = sample_times[source]
                    obs.signals['sample_received_at'] = stamp
                    obs.evidence_refs.append(f'Sample received: {stamp}')
                result = attempt(source, lambda obs=obs: engine.evaluate(obs))
                if result is not None:
                    results.append(result)

    if collect_live:
        if egress_facts is None:
            from agent.modules.egress_watch import collect_egress_facts

            egress_facts = attempt("egress", collect_egress_facts, collecting=True)
        if camera_facts is None:
            from agent.modules.camera_guard import collect_camera_holders

            camera_facts = attempt("camera", collect_camera_holders, collecting=True)
        if footprint_facts is None:
            footprint_facts = attempt("footprint", collect_footprint_facts, collecting=True)
        if startup_items is None:
            startup_items = attempt("startup", collect_startup_items, collecting=True)
    if security is not None:
        evaluate("security", lambda: from_security(security))
    for advice_item in advice or []:
        evaluate("advice", lambda item=advice_item: from_advice_offenders([item]))
    for status in disks or []:
        evaluate("disk", lambda status=status: [from_disk_status(status)])
    if startup_items is not None:
        baseline = attempt("startup", lambda: SafetyBaseline(engine.memory.learn_dir / "baseline_safety.txt"))
        if baseline is not None:
            evaluate("startup", lambda: startup_observations(startup_items, baseline, engine.memory, engine.now()))
    for fact in egress_facts or []:
        evaluate("egress", lambda fact=fact: [observation_from_egress(fact)])
    for fact in camera_facts or []:
        evaluate("camera", lambda fact=fact: [observation_from_camera(fact)])
    progress = attempt("footprint", lambda: FootprintProgress(engine.memory.learn_dir / "baseline_footprint.txt"))
    for fact in footprint_facts or []:
        obs = attempt("footprint", lambda fact=fact: observation_from_footprint(fact))
        if obs is None:
            continue
        if progress is None:
            continue
        status = attempt("footprint", lambda: progress.get(obs.subject_identity))
        if not fact.get("fresh") and status in ("in_progress", "resolved", "monitoring"):
            continue
        evaluate("footprint", lambda obs=obs: [obs])
    return results


def observation_from_group(group) -> Observation:
    name = group.primary_name
    protected = name.lower() in SYSTEM_PROTECTED
    obs = from_speed_sample(
        name=name,
        pid=int(group.primary_pid or 0),
        path="",
        cpu_percent=float(group.cpu_percent or 0),
        memory_mb=float(group.memory_mb or 0),
        identity_ok=not protected and bool(group.primary_pid),
        suspicious_mismatch=protected,
        measured=True,
    )
    assert obs is not None
    obs.title_simple = f"{group.display_name} is open"
    obs.why_it_matters = group.close_advice
    obs.evidence_refs = [group.close_advice, "Processes: " + ", ".join(group.process_names[:8])]
    return obs


def choose_for_app_group(store: AgentStore, group, option_id: str, **engine_kwargs) -> dict:
    """The desktop dialog calls this. Close runs only for the close option."""
    engine = engine_for(store, **engine_kwargs)
    obs = observation_from_group(group)
    result = engine.evaluate(obs, force_surface=True)
    finding = result["finding"]
    if finding is None:
        raise RuntimeError("the options card could not be opened")
    return engine.select(finding["id"], option_id)


def startup_executable(command: str) -> str:
    """Parse argv[0] using the Windows parser, without executing the command."""
    command = command.strip()
    if not command:
        return ""
    if os.name == "nt":
        shell = ctypes.WinDLL("shell32", use_last_error=True)
        shell.CommandLineToArgvW.argtypes = [ctypes.c_wchar_p, ctypes.POINTER(ctypes.c_int)]
        shell.CommandLineToArgvW.restype = ctypes.POINTER(ctypes.c_wchar_p)
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.LocalFree.argtypes = [ctypes.c_void_p]
        kernel.LocalFree.restype = ctypes.c_void_p
        count = ctypes.c_int()
        argv = shell.CommandLineToArgvW(command, ctypes.byref(count))
        if not argv:
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            return argv[0] if count.value else ""
        finally:
            kernel.LocalFree(ctypes.cast(argv, ctypes.c_void_p))
    if command.startswith('"'):
        end = command.find('"', 1)
        return command[1:end] if end >= 0 else ""
    return command.split()[0]


def collect_startup_items():
    """Windows Run-key names and command paths. Other systems return None (not an empty threat list)."""
    from agent.utils import IS_WINDOWS

    if not IS_WINDOWS:
        return None
    try:
        import winreg
    except ImportError:
        return None
    items = []
    key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path) as key:
            index = 0
            while True:
                try:
                    name, value, value_type = winreg.EnumValue(key, index)
                except OSError as exc:
                    if getattr(exc, "winerror", None) == 259:  # ERROR_NO_MORE_ITEMS
                        break
                    raise
                index += 1
                if value_type not in (winreg.REG_SZ, winreg.REG_EXPAND_SZ):
                    continue
                text = str(value or "").strip()
                if value_type == winreg.REG_EXPAND_SZ:
                    text = winreg.ExpandEnvironmentStrings(text)
                exe = startup_executable(text)
                items.append(
                    {
                        "subject": f"startup:{name}",
                        "display_name": name,
                        "path": exe,
                        "source": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\" + name,
                    }
                )
    except FileNotFoundError:
        return []  # No Run key is an observed empty source.
    except OSError:
        return None
    return items


def default_handler_context(**overrides) -> HandlerContext:
    ctx = HandlerContext(lookup=default_lookup, close=default_close)
    for key, value in overrides.items():
        setattr(ctx, key, value)
    return ctx

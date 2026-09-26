"""Glue between monitors, the desktop close dialog, and the shared engine."""

from __future__ import annotations

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
from agent.engine.watch import observation_from_camera, observation_from_egress
from agent.learn.memory import SafetyBaseline
from agent.modules.resource_advisor import SYSTEM_PROTECTED
from agent.store.db import AgentStore


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
    collect_live: bool = False,
) -> list[dict]:
    """Feed one cycle into the engine. Does not close apps, block networks, or delete files by itself."""
    engine = engine_for(store)
    results: list[dict] = []
    if collect_live:
        if egress_facts is None:
            from agent.modules.egress_watch import collect_egress_facts

            egress_facts = collect_egress_facts()
        if camera_facts is None:
            from agent.modules.camera_guard import collect_camera_holders

            camera_facts = collect_camera_holders()
    if security is not None:
        for obs in from_security(security):
            results.append(engine.evaluate(obs))
    for obs in from_advice_offenders(advice or []):
        results.append(engine.evaluate(obs))
    for status in disks or []:
        obs = from_disk_status(status)
        if obs is not None:
            results.append(engine.evaluate(obs))
    if startup_items is not None:
        baseline = SafetyBaseline(engine.memory.learn_dir / "baseline_safety.txt")
        for obs in startup_observations(startup_items, baseline, engine.memory, engine.now()):
            results.append(engine.evaluate(obs))
    for fact in egress_facts or []:
        obs = observation_from_egress(fact)
        if obs is not None:
            results.append(engine.evaluate(obs))
    for fact in camera_facts or []:
        obs = observation_from_camera(fact)
        if obs is not None:
            results.append(engine.evaluate(obs))
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
                    name, value, _typ = winreg.EnumValue(key, index)
                except OSError:
                    break
                index += 1
                text = str(value or "").strip()
                exe = text.strip('"').split('"')[0].split()[0] if text else ""
                items.append(
                    {
                        "subject": f"startup:{name}",
                        "display_name": name,
                        "path": exe,
                        "source": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\" + name,
                    }
                )
    except OSError:
        return None
    return items


def default_handler_context(**overrides) -> HandlerContext:
    ctx = HandlerContext(lookup=default_lookup, close=default_close)
    for key, value in overrides.items():
        setattr(ctx, key, value)
    return ctx

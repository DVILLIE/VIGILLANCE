"""Turn existing monitor results into observations. No invented readings."""

from __future__ import annotations

from agent.engine.models import Observation
from agent.learn.memory import KeepOnMemory, SafetyBaseline
from agent.modules.security import SecurityStatus


def from_security(status: SecurityStatus) -> list[Observation]:
    """Only explicit False becomes 'protection off'. None stays unknown."""
    found: list[Observation] = []
    checks = (
        ("defender", status.defender_enabled, "Windows Defender looks turned off"),
        ("realtime", status.realtime_protection, "Real-time protection looks turned off"),
        ("firewall", status.firewall_enabled, "The firewall looks turned off"),
    )
    for component, state, title in checks:
        if state is not False:
            continue
        found.append(
            Observation(
                pillar="safety",
                kind="protection_off",
                subject_identity=f"protection:{component}",
                title_simple=title,
                why_it_matters=(
                    "If this protection is off, unwanted connections have an easier time reaching the computer. "
                    "DVielle only reports a status it could actually read."
                ),
                if_ignored="It stays off until you turn it on or tell DVielle to leave it.",
                evidence_refs=[f"{component} reported off."],
                severity="high",
                confidence="high",
                recommended_action="Turn it back on if you expect it to be on.",
                resolution_steps=["Turn protection on, or remember that you want it left as it is."],
                reversible="yes",
                identity_ok=True,
                expected=True,
                suspicious_mismatch=False,
                action_class="auto_protect_eligible",
                signals={"component": component, "state": "off"},
            )
        )
    return found


def from_speed_sample(
    *,
    name: str,
    pid: int,
    path: str = "",
    cpu_percent: float | None = None,
    memory_mb: float | None = None,
    identity_ok: bool = True,
    suspicious_mismatch: bool = False,
    measured: bool = True,
) -> Observation | None:
    if not measured or not name:
        return None
    detail_bits = []
    if cpu_percent is not None:
        detail_bits.append(f"about {cpu_percent:.0f}% processor")
    if memory_mb is not None:
        detail_bits.append(f"about {memory_mb:.0f} MB memory")
    detail = " and ".join(detail_bits) if detail_bits else "a heavy share of the computer"
    subject = f"proc:{path}" if path else f"procname:{name.lower()}"
    return Observation(
        pillar="speed",
        kind="resource_hog",
        subject_identity=subject,
        title_simple=f"{name} is using a lot of the computer",
        why_it_matters=f"{name} is using {detail}. When one app holds the processor or memory, other apps feel slow.",
        if_ignored="The computer can stay sluggish while that app keeps running.",
        evidence_refs=[f"App: {name}", f"Process id: {pid}"] + ([f"File: {path}"] if path else []),
        severity="medium",
        confidence="high" if identity_ok else "medium",
        recommended_action="Pause it if you are not using it, or tell DVielle this app is OK.",
        resolution_steps=["Keep it on, close it, or leave it for now."],
        reversible="partial",
        identity_ok=identity_ok and bool(name),
        expected=identity_ok and not suspicious_mismatch,
        suspicious_mismatch=suspicious_mismatch or not identity_ok,
        signals={"pid": pid, "name": name, "path": path, "start_token": str(pid)},
    )


def from_advice_offenders(advice_list) -> list[Observation]:
    found: list[Observation] = []
    for advice in advice_list:
        for offender in getattr(advice, "offenders", []) or []:
            obs = from_speed_sample(
                name=offender.name,
                pid=offender.pid,
                cpu_percent=getattr(offender, "cpu_percent", None),
                memory_mb=getattr(offender, "memory_mb", None),
                identity_ok=True,
                measured=True,
            )
            if obs is not None:
                found.append(obs)
    return found


def from_disk_status(status) -> Observation | None:
    """Low space is a measured fact. Reclaim size is filled in only at preview/free time."""
    if not getattr(status, "low_space", False):
        return None
    free_gb = float(status.free_gb)
    critical = free_gb < 1.0 or float(status.percent_used) >= 95.0
    return Observation(
        pillar="storage",
        kind="safe_temp",
        subject_identity=f"cleanup:safe_temp:{status.mount}",
        title_simple="Free space on this computer is very low" if critical else "Temporary files may be taking up space",
        why_it_matters=(
            f"About {free_gb:.1f} GB is free on {status.mount}. "
            "DVielle can remove leftover temporary files, and it will not delete documents."
        ),
        if_ignored="The disk can fill up, and saving files or updates may fail.",
        evidence_refs=[
            f"Free space: {free_gb:.2f} GB on {status.mount}",
            "Reclaim size is measured when you preview or free space, not guessed here.",
        ],
        severity="critical" if critical else "medium",
        confidence="high",
        recommended_action="Preview the list, then free safe temporary space if it looks right.",
        resolution_steps=["Preview what would be removed.", "Free safe temporary space, or leave it."],
        reversible="no",
        identity_ok=True,
        expected=True,
        suspicious_mismatch=False,
        quiet_on_allow=False,
        action_class="auto_protect_eligible" if critical else "ask_user",
        signals={"free_gb": free_gb, "mount": status.mount, "critical_free": critical, "percent_used": status.percent_used},
    )


def startup_observations(
    items: list[dict],
    baseline: SafetyBaseline,
    memory: KeepOnMemory,
    updated: str,
) -> list[Observation]:
    """items: subject, display_name, path, source, optional pid."""
    if not baseline.initialized:
        baseline.seed([(item["subject"], item["path"]) for item in items], updated)
        return []
    found: list[Observation] = []
    for item in items:
        subject = item["subject"]
        known = baseline.items.get(subject)
        if known is None:
            found.append(_startup(item, mismatch=False, new=True, expected_path=""))
            continue
        if known != item["path"]:
            found.append(_startup(item, mismatch=True, new=False, expected_path=known))
            continue
        if memory.get("safety", subject) is None:
            continue
        found.append(_startup(item, mismatch=False, new=False, expected_path=known, baseline=True))
    return found


def _startup(item: dict, *, mismatch: bool, new: bool, expected_path: str, baseline: bool = False) -> Observation:
    name = item.get("display_name") or item["subject"]
    if mismatch:
        title = f"Startup “{name}” is not the file it used to be"
        why = (
            "A program set to start with the computer points at a different file than the one already seen. "
            "That can be an update, or another file using a familiar name."
        )
        kind = "suspicious_startup"
        severity, confidence = "high", "high"
    elif new:
        title = f"A new program will start with the computer: {name}"
        why = "Something new is set to start when you sign in. That is not automatically dangerous."
        kind = "new_startup"
        severity, confidence = "medium", "medium"
    else:
        title = f"{name} is still set to start with the computer"
        why = "You already made a choice about this startup. DVielle is checking that it still matches."
        kind = "suspicious_startup"
        severity, confidence = "medium", "high"
    return Observation(
        pillar="safety",
        kind=kind,
        subject_identity=item["subject"],
        title_simple=title,
        why_it_matters=why,
        if_ignored="It can keep starting with the computer.",
        evidence_refs=[f"File now: {item['path']}", f"Expected file: {expected_path or 'not seen before'}", f"Source: {item.get('source', '')}"],
        severity=severity,
        confidence=confidence,
        recommended_action="Disable this startup, or keep it only if you recognize the file.",
        resolution_steps=["Compare the file.", "Disable the startup or close the process if you do not trust it."],
        reversible="partial",
        identity_ok=not mismatch,
        expected=not mismatch,
        suspicious_mismatch=mismatch,
        baseline_expected=baseline and not mismatch,
        signals={
            "name": name,
            "path": item["path"],
            "pid": int(item.get("pid") or 0),
            "startup_file": item.get("startup_file") or "",
            "expected_path": expected_path,
        },
    )

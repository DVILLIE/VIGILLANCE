"""Privacy, AI, and Camera observations. Facts in, options out. No images."""

from __future__ import annotations

from agent.engine.models import Observation

AI_HOST_SUFFIXES = (
    "openai.com",
    "chatgpt.com",
    "anthropic.com",
    "claude.ai",
    "generativelanguage.googleapis.com",
    "gemini.google.com",
    "api.groq.com",
    "perplexity.ai",
    "api.mistral.ai",
    "copilot.microsoft.com",
)

AI_PROCESS_NAMES = frozenset(
    {
        "chatgpt.exe",
        "chatgpt",
        "claude.exe",
        "claude",
        "copilot.exe",
        "perplexity.exe",
        "perplexity",
    }
)


def is_ai_host(host: str) -> bool:
    text = (host or "").lower().rstrip(".")
    if not text or " " in text:
        return False
    return any(text == suffix or text.endswith("." + suffix) for suffix in AI_HOST_SUFFIXES)


def _name(fact: dict) -> str:
    return str(fact.get("app_name") or "").strip()


def observation_from_egress(fact: dict) -> Observation | None:
    """One app's public connection. A named app that is not open is a mismatch."""
    name = _name(fact)
    if not name or "|" in name or "\n" in name:
        return None
    pillar = fact.get("pillar") or "privacy"
    if pillar not in ("privacy", "ai_data"):
        return None
    app_open = bool(fact.get("app_open"))
    try:
        pid = int(fact.get("pid") or 0)
    except (TypeError, ValueError):
        pid = 0
    path = str(fact.get("path") or "")
    remote = str(fact.get("remote") or fact.get("remote_ip") or "")
    host = str(fact.get("host") or "")
    identity_ok = app_open and pid > 1 and bool(name)
    mismatch = not app_open or bool(fact.get("suspicious_mismatch"))
    where = host or remote or "a public address"
    if pillar == "ai_data":
        subject = f"ai:{name.lower()}"
        if mismatch:
            title = f"An AI upload was named as {name}, but {name} is not open"
            why = (
                f"Traffic toward an online AI service was attributed to {name}, and that app is not actually running. "
                "This is not proof a model was trained on your files."
            )
        else:
            title = f"{name} appears to be sending data to an online AI service"
            why = (
                f"{name} has a connection that looks like an online AI service ({where}). "
                "Companies sometimes use that to improve their AI. "
                "This is not proof they trained a model on your files."
            )
        kind = "unexpected_upload"
        suggest = "Allow this AI app, or block its internet, after you pick one option."
    else:
        subject = f"egress:{name.lower()}"
        if mismatch:
            title = f"Internet use was named as {name}, but {name} is not open"
            why = (
                f"A connection was attributed to {name}, and that app is not actually running. "
                "That can be a different program using a familiar name."
            )
        else:
            title = f"{name} is talking to the internet"
            why = (
                f"{name} has a connection off this computer ({where}). "
                "That is not automatically dangerous. D\'Vielle did not read what was sent."
            )
        kind = "unexpected_egress"
        suggest = "Allow this app's internet, or block its network, after you pick one option."
    evidence = [
        f"App: {name}",
        f"Process id: {pid}" if pid else "Process id: not available",
        f"Remote: {where}",
        f"App open: {'yes' if app_open else 'no'}",
        "Connection contents were not read.",
    ]
    if path:
        evidence.append(f"File: {path}")
    return Observation(
        pillar=pillar,
        kind=kind,
        subject_identity=subject,
        title_simple=title,
        why_it_matters=why,
        if_ignored="The connection can continue until you allow it or block that app's network.",
        evidence_refs=evidence,
        severity="high" if mismatch else "medium",
        confidence="high" if identity_ok else "medium",
        recommended_action=suggest,
        resolution_steps=["Allow it, block its network, or leave it for now."],
        reversible="partial",
        identity_ok=identity_ok,
        expected=identity_ok and not mismatch,
        suspicious_mismatch=mismatch,
        signals={
            "pid": pid,
            "name": name,
            "path": path,
            "remote": remote,
            "host": host,
            "app_open": app_open,
            "frames_stored": False,
        },
    )


def observation_from_camera(fact: dict) -> Observation | None:
    """Local webcam/USB use only. Never carries an image."""
    name = _name(fact)
    if fact.get('evidence_kind') == 'windows_camera_activity_record':
        if not name or any(mark in name for mark in ('|', '\n', '\r')):
            return None
        return Observation(
            pillar='camera', kind='camera_activity_record',
            subject_identity='camera-record:' + name.casefold(),
            title_simple='Windows recorded camera access for ' + name,
            why_it_matters='This is Windows privacy activity metadata, not proof the camera is currently on or that a process still owns it.',
            if_ignored='Review unfamiliar recorded applications in Windows camera privacy settings.',
            evidence_refs=[str(fact.get('registry_key', '')), str(fact.get('last_start_utc', '')),
                           'No image, frame, or verified live process identity was collected.'],
            severity='low', confidence='low',
            recommended_action='Review Windows camera privacy settings.',
            resolution_steps=['Open Settings > Privacy & security > Camera.'],
            reversible='partial', identity_ok=False, expected=False, suspicious_mismatch=False,
            action_class='ask_user', signals=dict(fact))
    try:
        pid = int(fact.get("pid") or 0)
    except (TypeError, ValueError):
        pid = 0
    if "|" in name or "\n" in name:
        return None
    device = str(fact.get("device") or "local camera")
    if any(mark in device.lower() for mark in (".png", ".jpg", ".jpeg", ".bmp", "frame=")):
        return None
    app_open = bool(fact.get("app_open")) and bool(name)
    path = str(fact.get("path") or "")
    if name:
        subject = f"camera:{name.lower()}"
    elif pid > 1:
        subject = f"camera:pid:{pid}"
        name = ""
    else:
        return None
    mismatch = (not app_open) or bool(fact.get("suspicious_mismatch"))
    identity_ok = app_open and pid > 1 and bool(name)
    if not name:
        title = "The camera is in use, but the app could not be named"
        why = (
            "A local camera looks busy and D\'Vielle could not name the program. "
            "A hardware cover is still stronger than a software alert. No picture was stored."
        )
    elif mismatch:
        title = f"The camera turned on, but {name} isn't open"
        why = (
            f"Camera use was attributed to {name}, and that app is not actually running. "
            "That can mean another app is using it. "
            "A hardware cover or shutter is still the surest block. No picture was stored."
        )
    else:
        title = f"{name} is using the camera"
        why = (
            f"{name} appears to be using a local camera ({device}). "
            "If you already allowed this app and it is really open, D\'Vielle stays quiet. "
            "No picture was stored."
        )
    return Observation(
        pillar="camera",
        kind="camera_use",
        subject_identity=subject,
        title_simple=title,
        why_it_matters=why,
        if_ignored="The camera can stay in use until you pick an option. D\'Vielle will not turn it off by itself.",
        evidence_refs=[
            f"Device: {device}",
            f"App: {name or 'unnamed'}",
            f"Process id: {pid}" if pid else "Process id: not available",
            f"App open: {'yes' if app_open else 'no'}",
            "No image or frame was stored.",
            "Network and IP cameras are not covered here.",
        ],
        severity="high" if mismatch or not name else "medium",
        confidence="high" if identity_ok else "medium",
        recommended_action="Allow this app, or stop its camera use, after you pick one option.",
        resolution_steps=["Allow it, stop this app, or open system camera settings."],
        reversible="partial",
        identity_ok=identity_ok,
        expected=identity_ok and not mismatch,
        suspicious_mismatch=mismatch,
        action_class="ask_user",
        signals={
            "pid": pid,
            "name": name,
            "path": path,
            "device": device,
            "app_open": app_open,
            "frames_stored": False,
        },
    )


def observation_from_paste_run(fact: dict) -> Observation | None:
    """ClickFix/TerminalFix-class suspicion from cmdline or script-block text. No clipboard."""
    subject = str(fact.get("subject") or "").strip()
    snippet = str(fact.get("snippet") or "").strip()
    if not subject or not snippet or "|" in subject or "\n" in subject:
        return None
    tags = [str(t) for t in (fact.get("tags") or []) if t]
    channel = str(fact.get("channel") or "unknown")
    try:
        score = int(fact.get("score") or 0)
    except (TypeError, ValueError):
        score = 0
    process_name = str(fact.get("process_name") or "")
    try:
        pid = int(fact.get("pid") or 0)
    except (TypeError, ValueError):
        pid = 0
    lure = "cloudflare_lure" in tags
    title = (
        "A PowerShell script looked like a fake 'verify you are human' paste"
        if lure
        else "A PowerShell or cmd line looked like a download-and-run paste"
    )
    why = (
        "Websites sometimes trick people into pasting a command into PowerShell or Terminal "
        "(ClickFix / TerminalFix). D'Vielle did not read the clipboard. "
        "This is a suspicion from command text and public hunting patterns, not proof of infection."
    )
    evidence = [
        f"Channel: {channel}",
        f"Tags: {', '.join(tags) if tags else 'none'}",
        f"Score: {score}",
        f"Snippet: {snippet[:240]}",
        "Clipboard was not read.",
    ]
    if process_name:
        evidence.append(f"Process: {process_name}")
    if pid:
        evidence.append(f"Process id: {pid}")
    return Observation(
        pillar="safety",
        kind="paste_run_suspicion",
        subject_identity=subject,
        title_simple=title,
        why_it_matters=why,
        if_ignored="If the paste was real malware, it can keep running until you stop that process or reboot carefully.",
        evidence_refs=evidence,
        severity="high" if lure or score >= 6 else "medium",
        confidence="medium",
        recommended_action="Review the snippet, open Windows Security, and avoid pasting website commands into PowerShell.",
        resolution_steps=[
            "Do not paste website 'verification' commands into PowerShell or Terminal.",
            "Open Windows Security and run a quick scan if you already pasted something.",
            "Show why for the exact snippet D'Vielle saw.",
        ],
        reversible="yes",
        identity_ok=False,
        expected=False,
        suspicious_mismatch=True,
        action_class="ask_user",
        quiet_on_allow=False,
        signals={"channel": channel, "tags": tags, "score": score, "pid": pid, "process_name": process_name},
    )


def observation_from_exclusion(fact: dict) -> Observation | None:
    """New Defender exclusion or weakened preference after baseline."""
    subject = str(fact.get("subject") or "").strip()
    label = str(fact.get("label") or "").strip()
    kind = str(fact.get("kind") or "defender_exclusion_added")
    if not subject or not label or "|" in subject or "\n" in subject:
        return None
    channel = str(fact.get("channel") or "")
    if kind == "defender_preference_weakened":
        title = f"A Defender preference weakened: {label}"
        why = (
            "A Defender monitoring preference flipped to a weaker setting after D'Vielle stored a baseline. "
            "Attackers sometimes disable protections after they get in. This is not proof of malware."
        )
        obs_kind = "defender_preference_weakened"
    else:
        title = f"A new Defender exclusion appeared: {label}"
        why = (
            "Defender exclusion lists grew after D'Vielle stored a baseline. "
            "Legitimate software sometimes adds exclusions; malware also does. "
            "D'Vielle did not add this exclusion."
        )
        obs_kind = "defender_exclusion_added"
    return Observation(
        pillar="safety",
        kind=obs_kind,
        subject_identity=subject,
        title_simple=title,
        why_it_matters=why,
        if_ignored="Excluded paths or disabled monitors can hide later malware from Defender.",
        evidence_refs=[
            f"Label: {label}",
            f"Channel: {channel or 'preference'}",
            "Get-MpPreference was readable for this sample.",
            "D'Vielle never adds ExclusionPath from this observer.",
        ],
        severity="high",
        confidence="high",
        recommended_action="Review Windows Security exclusions / tamper settings after you pick an option.",
        resolution_steps=[
            "Open Windows Security → Virus & threat protection settings → Exclusions / Tamper Protection.",
            "Remove unfamiliar exclusions if you did not approve them.",
            "Show why for the exact change.",
        ],
        reversible="partial",
        identity_ok=True,
        expected=False,
        suspicious_mismatch=False,
        action_class="ask_user",
        quiet_on_allow=False,
        signals={"label": label, "channel": channel, "kind": kind},
    )

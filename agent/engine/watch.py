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
                "That is not automatically dangerous. DVielle did not read what was sent."
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
            "A local camera looks busy and DVielle could not name the program. "
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
            "If you already allowed this app and it is really open, DVielle stays quiet. "
            "No picture was stored."
        )
    return Observation(
        pillar="camera",
        kind="camera_use",
        subject_identity=subject,
        title_simple=title,
        why_it_matters=why,
        if_ignored="The camera can stay in use until you pick an option. DVielle will not turn it off by itself.",
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

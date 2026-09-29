"""Defender-safe privacy choices.

Prefer Required diagnostic data. Home and Pro cannot claim Security=Off.
MAPS, Windows Update, and CRL endpoints are never proposed for blocking.
A change counts only when a second read matches. Direct calls fail closed.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Callable

from agent.modules.defender_health import MAPS_GUIDANCE, MapsCheck, query_maps
from agent.net_identity import host_matches_domain, normalize_hostname
from agent.policy.dual import require_cortex_mutate
from agent.utils import IS_WINDOWS, run_powershell

Reader = Callable[[], dict[str, int | None]]
Runner = Callable[[str], tuple[str | None, bool]]

# Microsoft Learn, configure-windows-diagnostic-data-in-your-organization (2026-09-29):
# 0 Security (Enterprise, Education, Server only), 1 Required, 2 Enhanced, 3 Optional.
# Defender cloud: configure-network-connections-microsoft-defender-antivirus.
PROTECTED_DOMAINS: tuple[str, ...] = (
    "wdcp.microsoft.com",
    "wdcpalt.microsoft.com",
    "wd.microsoft.com",
    "windowsupdate.com",
    "update.microsoft.com",
    "download.microsoft.com",
    "delivery.mp.microsoft.com",
    "mp.microsoft.com",
    "crl.microsoft.com",
    "mscrl.microsoft.com",
    "ctldl.windowsupdate.com",
    "settings-win.data.microsoft.com",
)
BROAD_NAMES = frozenset({"*", "microsoft.com", "windows.com", "all"})

_MEANINGS = {0: "Security", 1: "Required", 2: "Enhanced", 3: "Optional"}
_KEYS = ("AllowTelemetryPolicy", "AllowTelemetryLocal", "AdvertisingId", "TailoredExperiences")
_LOCATIONS = {
    "AllowTelemetryPolicy": (
        r"HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection",
        "AllowTelemetry",
    ),
    "AllowTelemetryLocal": (
        r"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection",
        "AllowTelemetry",
    ),
    "AdvertisingId": (
        r"HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo",
        "Enabled",
    ),
    "TailoredExperiences": (
        r"HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent",
        "DisableTailoredExperiencesWithDiagnosticData",
    ),
}


def classify_edition(edition: str | None) -> tuple[str, int | None]:
    """Return a display class and the supported diagnostic floor. Unknown stays unknown."""
    token = (edition or "").strip().lower()
    if not token or token in {"unknown", "nonwindows"}:
        return "unknown", None
    if token.startswith(("core", "home")):
        return "Home", 1
    if token.startswith("professional") or token in {"pro", "proorhigher"}:
        return "Pro", 1
    if token.startswith(("enterprise", "education", "server", "iotenterprise")):
        return "EnterpriseOrEducation", 0
    return "unknown", None


def observe_privacy(*, edition: str | None = None, reader: Reader | None = None) -> dict[str, Any]:
    """Read supported privacy settings. Unreadable values stay unknown."""
    if reader is None:
        if not IS_WINDOWS:
            return _unavailable("Windows privacy settings are unavailable on this platform.")
        reader = windows_reader
        if edition is None:
            edition = _windows_edition()
    label, floor = classify_edition(edition)
    snapshot = reader() or {}
    observed: list[dict[str, Any]] = []
    unknown: list[str] = []
    for key in _KEYS:
        value = snapshot.get(key) if key in snapshot else None
        if _as_int(value) is not None:
            value = _as_int(value)
            observed.append({"name": key, "value": value, "meaning": _setting_meaning(key, value)})
        else:
            unknown.append(key)
    security_off = "unsupported" if floor == 1 else "supported_policy" if floor == 0 else "unknown"
    state = "observed" if observed and not unknown else "partial" if observed else "unavailable"
    return {
        "state": state,
        "edition": label,
        "floor": floor,
        "preferred": "Required",
        "security_off": security_off,
        "observed": observed,
        "unknown": unknown,
        "recommendation": _recommendation(label, security_off),
        "block_posture": "MAPS, Windows Update, and CRL endpoints are not proposed for blocking.",
        "assumptions": [
            "AllowTelemetry 0 is Diagnostic data off and is documented for Enterprise, Education, and Server.",
            "Home and Pro cannot claim Security=Off. A configured 0 does not establish that diagnostics are off.",
            "A registry value is not a measurement of traffic.",
            "Required is the preference. Optional and Enhanced send more than Required.",
        ],
    }


def assess_microsoft_block(
    targets: list[str],
    *,
    maps: MapsCheck | None = None,
    maps_reader: Callable[[], MapsCheck] | None = None,
) -> dict[str, Any]:
    """Refuse a block that would cover Defender cloud, update, or CRL endpoints.

    The MAPS result is the existing ValidateMapsConnection check. No firewall rule is returned.
    """
    protected = [target for target in targets if _is_protected(target)]
    broad = bool(protected) or any(_is_broad(target) for target in targets)
    if not broad:
        return {
            "proposed": False,
            "broad": False,
            "protected": [],
            "consequence": "",
            "maps": None,
            "detail": "This request did not name a MAPS, Windows Update, or CRL endpoint. No rule was created here.",
        }
    check = maps if maps is not None else (maps_reader or query_maps)()
    result = check.result if isinstance(check, MapsCheck) else "unavailable"
    consequence = (
        "DVielle will not block MAPS, Windows Update, or certificate revocation endpoints. "
        "Blocking them can degrade cloud-delivered protection, definition updates, and TLS validation. "
        f"MAPS ValidateMapsConnection result: {result}. {MAPS_GUIDANCE}"
    )
    return {
        "proposed": False,
        "broad": True,
        "protected": protected,
        "rule": None,
        "consequence": consequence,
        "maps": check.to_dict() if isinstance(check, MapsCheck) else {"result": result},
    }


def plan_choice(choice: str, edition: str | None) -> dict[str, Any] | None:
    """Return the single setting a choice may write, or None when the edition cannot claim it."""
    label, floor = classify_edition(edition)
    token = (choice or "").strip().lower()
    if token == "required_diagnostics":
        return {"key": "AllowTelemetryPolicy", "value": 1, "edition": label, "choice": token}
    if token == "security_off":
        if floor != 0:
            return None
        return {"key": "AllowTelemetryPolicy", "value": 0, "edition": label, "choice": token}
    if token == "advertising_off":
        return {"key": "AdvertisingId", "value": 0, "edition": label, "choice": token}
    if token == "tailored_off":
        return {"key": "TailoredExperiences", "value": 1, "edition": label, "choice": token}
    return None


def apply_privacy_choice(
    *,
    choice: str,
    edition: str | None,
    reader: Reader | None = None,
    runner: Runner | None = None,
    undo_path: Path | None = None,
) -> dict[str, Any]:
    """Apply one supported choice. Success is the second read, not the set command."""
    require_cortex_mutate()
    token = (choice or "").strip().lower()
    if token == "restore":
        return _restore(edition, reader, runner, undo_path)
    plan = plan_choice(token, edition)
    if plan is None:
        label, _floor = classify_edition(edition)
        if token == "security_off":
            return _refused(
                f"{label} cannot claim Security=Off. Diagnostic data off is not a supported claim on this edition. "
                "Nothing was changed. Required remains the preference."
            )
        return _refused("That privacy choice is not supported. Nothing was changed.")
    if reader is None:
        if not IS_WINDOWS:
            return _refused("Windows privacy settings are unavailable on this platform. Nothing was changed.")
        reader = windows_reader
    if runner is None:
        runner = _default_runner
    before = reader() or {}
    current = _as_int(before.get(plan["key"])) if plan["key"] in before else None
    if current == plan["value"]:
        return {
            "performed": True,
            "message": (
                f"Re-read {plan['key']} as {_MEANINGS.get(plan['value'], plan['value'])}. "
                "It was already that value. Nothing new was written. This is not a traffic measurement."
            ),
            "reversible": "yes",
            "verified": True,
        }
    script = _set_script(plan["key"], plan["value"])
    runner(script)
    after = reader() or {}
    seen = _as_int(after.get(plan["key"])) if plan["key"] in after else None
    if seen != plan["value"]:
        return _refused(
            f"The second read of {plan['key']} did not match. The choice was not applied.",
            verified=False,
        )
    _remember(undo_path, plan["key"], current)
    meaning = _setting_meaning(plan["key"], plan["value"])
    extra = ""
    if token == "security_off":
        extra = " Security (0) is a supported policy on this edition. It is not a claim that Microsoft traffic stopped."
    return {
        "performed": True,
        "message": (
            f"Re-read {plan['key']} as {meaning}. "
            "The effective setting is that re-read, not the set command. "
            "This is not a measurement of traffic."
            + extra
        ),
        "reversible": "yes",
        "verified": True,
        "observed": [{"name": plan["key"], "value": seen, "meaning": meaning}],
    }


def _restore(
    edition: str | None,
    reader: Reader | None,
    runner: Runner | None,
    undo_path: Path | None,
) -> dict[str, Any]:
    recorded = _recall(undo_path)
    if recorded is None:
        return _refused("No prior privacy value is recorded. Nothing was changed.")
    key, previous = recorded
    if key == "AllowTelemetryPolicy" and previous == 0 and classify_edition(edition)[1] != 0:
        return _refused("Restoring Security=Off is not a supported claim on this edition. Nothing was changed.")
    if reader is None:
        if not IS_WINDOWS:
            return _refused("Windows privacy settings are unavailable on this platform. Nothing was changed.")
        reader = windows_reader
    if runner is None:
        runner = _default_runner
    runner(_set_script(key, previous))
    after = reader() or {}
    seen = _as_int(after.get(key)) if key in after else None
    if seen != previous:
        return _refused("The second read did not match the recorded value. The restore was not applied.", verified=False)
    return {
        "performed": True,
        "message": f"Re-read {key} as the value recorded before the last change. This is not a traffic measurement.",
        "reversible": "yes",
        "verified": True,
    }


def _recommendation(label: str, security_off: str) -> str:
    if security_off == "unsupported":
        return (
            f"Prefer Required diagnostic data. {label} cannot claim Security=Off. "
            "Do not block MAPS, Windows Update, or CRL endpoints."
        )
    if security_off == "supported_policy":
        return (
            "Prefer Required diagnostic data. Diagnostic data off is a supported policy on this edition "
            "and is still not a claim that Microsoft traffic stopped."
        )
    return "Prefer Required diagnostic data. The edition is unknown, so Security=Off is not claimed."


def _is_protected(target: str) -> bool:
    host = _host(target)
    if host is None:
        return False
    return any(host_matches_domain(host, domain) for domain in PROTECTED_DOMAINS)


def _is_broad(target: str) -> bool:
    text = (target or "").strip().lower()
    if text in BROAD_NAMES:
        return True
    host = _host(target)
    return host in {"microsoft.com", "windows.com"}


def _host(target: str) -> str | None:
    text = (target or "").strip().lower()
    if text.startswith("*."):
        text = text[2:]
    return normalize_hostname(text)


def _set_script(key: str, value: int | None) -> str:
    path, name = _LOCATIONS[key]
    if value is None:
        body = f"Remove-ItemProperty -LiteralPath '{path}' -Name '{name}' -ErrorAction Stop"
    else:
        body = (
            f"New-Item -Path '{path}' -Force | Out-Null; "
            f"Set-ItemProperty -LiteralPath '{path}' -Name '{name}' -Type DWord -Value {int(value)}"
        )
    return f"""
$ErrorActionPreference = 'Stop'
# DVIELLE_PRIVACY_SET
try {{
  {body}
  Write-Output 'SET:OK'
}} catch {{
  $flat = (([string]$_.Exception.Message) -replace '\\s+', ' ')
  if ($flat -match 'denied|0x80070005|80070005|Unauthorized') {{
    Write-Output 'SET:ACCESS_DENIED'
  }} else {{
    Write-Output 'SET:FAILED'
  }}
  Write-Output ('DETAIL:' + $flat)
}}
exit 0
"""


def _remember(path: Path | None, key: str, previous: int | None) -> None:
    if path is None:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    token = "absent" if previous is None else str(int(previous))
    path.write_text(f"{key}|{token}\n", encoding="utf-8")


def _recall(path: Path | None) -> tuple[str, int | None] | None:
    if path is None or not path.is_file():
        return None
    try:
        line = path.read_text(encoding="utf-8").strip()
    except OSError:
        return None
    if "|" not in line:
        return None
    key, token = line.split("|", 1)
    if key not in _LOCATIONS:
        return None
    if token == "absent":
        return key, None
    if token.isdigit():
        return key, int(token)
    return None


def _setting_meaning(key: str, value: int) -> str:
    if key in {"AllowTelemetryPolicy", "AllowTelemetryLocal"}:
        return _MEANINGS.get(value, "unknown")
    if key == "AdvertisingId":
        return "off" if value == 0 else "on" if value == 1 else "unknown"
    if key == "TailoredExperiences":
        return "off" if value == 1 else "on" if value == 0 else "unknown"
    return "unknown"


def _as_int(value: Any) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value


def _refused(message: str, **extra: Any) -> dict[str, Any]:
    body = {"performed": False, "message": message, "reversible": "no", "verified": False}
    body.update(extra)
    return body


def _unavailable(detail: str) -> dict[str, Any]:
    return {
        "state": "unavailable",
        "edition": "unknown",
        "floor": None,
        "preferred": "Required",
        "security_off": "unknown",
        "observed": [],
        "unknown": list(_KEYS),
        "recommendation": "Prefer Required diagnostic data. Windows settings were not read.",
        "block_posture": "MAPS, Windows Update, and CRL endpoints are not proposed for blocking.",
        "detail": detail,
        "assumptions": ["This platform did not provide the Windows privacy settings."],
    }


def _default_runner(script: str) -> tuple[str | None, bool]:
    if not IS_WINDOWS:
        return None, False
    return run_powershell(script, timeout=25)


def windows_reader() -> dict[str, int | None]:
    if not IS_WINDOWS:
        return {}
    import winreg

    found: dict[str, int | None] = {}
    native = {
        "AllowTelemetryPolicy": (
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Policies\Microsoft\Windows\DataCollection",
            "AllowTelemetry",
        ),
        "AllowTelemetryLocal": (
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection",
            "AllowTelemetry",
        ),
        "AdvertisingId": (
            winreg.HKEY_CURRENT_USER,
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo",
            "Enabled",
        ),
        "TailoredExperiences": (
            winreg.HKEY_CURRENT_USER,
            r"SOFTWARE\Policies\Microsoft\Windows\CloudContent",
            "DisableTailoredExperiencesWithDiagnosticData",
        ),
    }
    for key, (hive, path, name) in native.items():
        found[key] = _dword(winreg, hive, path, name)
    return found


def _dword(winreg: Any, hive: Any, path: str, name: str) -> int | None:
    try:
        with winreg.OpenKey(hive, path) as handle:
            value, kind = winreg.QueryValueEx(handle, name)
    except OSError:
        return None
    if kind != winreg.REG_DWORD or isinstance(value, bool) or not isinstance(value, int):
        return None
    return value


def _windows_edition() -> str | None:
    if not IS_WINDOWS:
        return None
    import winreg

    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion") as handle:
            value, _kind = winreg.QueryValueEx(handle, "EditionID")
    except OSError:
        return None
    return value if isinstance(value, str) and value else None

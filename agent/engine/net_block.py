"""Per-app network block. Only after a selected option. Never an IP attack rule."""

from __future__ import annotations

from pathlib import Path

from agent.modules.resource_advisor import SYSTEM_PROTECTED
from agent.utils import IS_WINDOWS

HONEST_FAIL = "DVielle did not add a firewall rule. Traffic was not stopped."
HONEST_OK = "Added an outbound firewall rule for this program. This does not prove every connection already stopped."


def block_app_network(name: str, path: str, *, runner=None) -> tuple[bool, str]:
    """Block outbound traffic for one program file. Does not kill the process."""
    if not name or name.lower() in SYSTEM_PROTECTED:
        return False, f"DVielle will not block the network for {name or 'that process'}. Traffic was not stopped."
    if any(ch in (path or "") for ch in ("'", '"', "\n", "&", "|")):
        return False, "The program path was not safe to pass to the firewall. Traffic was not stopped."
    exe = Path(path) if path else None
    if exe is None or not exe.is_file():
        return False, "No program file was identified. " + HONEST_FAIL
    if not IS_WINDOWS:
        return False, "No per-app firewall helper is available on this system. " + HONEST_FAIL
    run = runner or _windows_outbound_rule
    try:
        ok, detail = run(name, str(exe))
    except OSError:
        return False, HONEST_FAIL
    if not ok:
        return False, (detail or HONEST_FAIL)
    text = detail or HONEST_OK
    if "does not prove" not in text.lower():
        text = text.rstrip(".") + ". This does not prove every connection already stopped."
    return True, text


def _windows_outbound_rule(name: str, path: str) -> tuple[bool, str]:
    """Windows-only. Not used on this Linux agent host."""
    import subprocess

    rule = f"DVielle block {name}"[:60]
    script = (
        "New-NetFirewallRule "
        f"-DisplayName '{rule}' "
        "-Direction Outbound "
        f"-Program '{path}' "
        "-Action Block "
        "-Profile Any "
        "-ErrorAction Stop | Out-Null; "
        "Write-Output 'added'"
    )
    result = subprocess.run(
        ["powershell", "-NoProfile", "-Command", script],
        capture_output=True,
        text=True,
        timeout=30,
        creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, "CREATE_NO_WINDOW") else 0,
    )
    if result.returncode == 0 and "added" in (result.stdout or "").lower():
        return True, HONEST_OK
    return False, HONEST_FAIL

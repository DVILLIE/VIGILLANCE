"""Windows Firewall app-rule apply, used only by the privileged helper.

The Limited agent does not import this module to mutate. ``apply_verified``
refuses to run unless the helper dispatcher opened the apply scope. Success is
a parsed ``Get-NetFirewallRule`` transcript for every requested address family.
"""

from __future__ import annotations

import contextvars
import hashlib
import ipaddress
from typing import Any, Callable

from agent.modules.firewall_assist import LEAK_WARNING
from agent.utils import IS_WINDOWS, run_powershell

Runner = Callable[[str], tuple[str | None, bool]]

_apply_depth: contextvars.ContextVar[int] = contextvars.ContextVar("dvielle_fw_apply", default=0)

HONEST_FAIL = "DVielle did not add a firewall rule. Traffic was not stopped."
HONEST_OK = (
    "Added Windows Firewall outbound block rules for this program on the chosen profile. "
    "This does not prove every connection already stopped."
)


def apply_scope():
    """Helper dispatcher only. A direct caller stays outside the scope."""
    return _Scope()


class _Scope:
    def __enter__(self) -> None:
        self._token = _apply_depth.set(_apply_depth.get() + 1)

    def __exit__(self, *_exc: object) -> None:
        _apply_depth.reset(self._token)


def _ps_quote(text: str) -> str:
    if "'" in text or any(ch in text for ch in "\r\n"):
        raise ValueError("unsafe powershell literal")
    return "'" + text + "'"


def rule_names(program: str, profile: str, families: list[str], remotes: list[str]) -> list[tuple[str, str]]:
    material = "\n".join([program, profile, ",".join(remotes)])
    digest = hashlib.sha256(material.encode("utf-8")).hexdigest()[:12]
    suffix = {"IPv4": "v4", "IPv6": "v6"}
    ordered = [family for family in ("IPv4", "IPv6") if family in families]
    return [(f"DVielle-restrict-{digest}-{suffix[family]}", family) for family in ordered]


def apply_script(params: dict[str, Any]) -> str:
    names = rule_names(
        params["program"],
        params["profile"],
        list(params["address_families"]),
        list(params["remote_addresses"]),
    )
    program = _ps_quote(params["program"])
    profile = params["profile"]
    remote = ",".join(params["remote_addresses"])
    remote_literal = _ps_quote(remote)
    entries = "\n".join(
        f"  @{{ Name = '{name}'; Family = '{family}' }}" for name, family in names
    )
    comments = "\n".join(f"# FAMILY:{family}:{name}" for name, family in names)
    return f"""
$ErrorActionPreference = 'Stop'
# DVIELLE_FW_APPLY
# PROGRAM:{params["program"]}
# PROFILE:{profile}
# REMOTE:{remote}
{comments}
$planned = @(
{entries}
)
$program = {program}
$profile = '{profile}'
$remote = {remote_literal}
foreach ($item in $planned) {{
  $name = $item.Name
  $existing = Get-NetFirewallRule -Name $name -ErrorAction SilentlyContinue
  if (-not $existing) {{
    $params = @{{
      Name = $name
      DisplayName = $name
      Group = 'DVielle'
      Direction = 'Outbound'
      Action = 'Block'
      Program = $program
      Profile = $profile
      AddressFamily = $item.Family
      Enabled = 'True'
      ErrorAction = 'Stop'
    }}
    if ($remote) {{ $params.RemoteAddress = $remote }}
    New-NetFirewallRule @params | Out-Null
  }}
  $rule = Get-NetFirewallRule -Name $name -ErrorAction SilentlyContinue
  if (-not $rule) {{
    Write-Output ('VERIFY:MISSING:' + $name)
    continue
  }}
  $app = Get-NetFirewallApplicationFilter -AssociatedNetFirewallRule $rule -ErrorAction SilentlyContinue
  $addr = Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $rule -ErrorAction SilentlyContinue
  $prog = ''
  $fam = ''
  $rem = ''
  if ($app) {{ $prog = ([string]$app.Program) -replace '[|\\r\\n]', ' ' }}
  if ($addr) {{
    $fam = ([string]$addr.AddressFamily) -replace '[|\\r\\n]', ' '
    $rem = ((@($addr.RemoteAddress) -join ',')) -replace '[|\\r\\n]', ' '
  }}
  Write-Output ('VERIFY:' + [string]$rule.Name + '|' + [string]$rule.Enabled + '|' + [string]$rule.Direction + '|' + [string]$rule.Action + '|' + [string]$rule.Profile + '|' + $fam + '|' + $prog + '|' + $rem)
}}
Write-Output 'STATUS:OK'
exit 0
"""


def remove_script(names: list[str]) -> str:
    listed = "\n".join(f"  '{name}'" for name in names)
    return f"""
$ErrorActionPreference = 'Stop'
# DVIELLE_FW_REMOVE
$names = @(
{listed}
)
foreach ($name in $names) {{
  $rule = Get-NetFirewallRule -Name $name -ErrorAction SilentlyContinue
  if ($rule -and ([string]$rule.DisplayName).StartsWith('DVielle-restrict-')) {{
    Remove-NetFirewallRule -Name $name -ErrorAction SilentlyContinue
  }}
  $still = Get-NetFirewallRule -Name $name -ErrorAction SilentlyContinue
  if ($still) {{ Write-Output ('REMOVE:STILL:' + $name) }} else {{ Write-Output ('REMOVE:GONE:' + $name) }}
}}
Write-Output 'STATUS:OK'
exit 0
"""


def _default_runner(script: str) -> tuple[str | None, bool]:
    if not IS_WINDOWS:
        return None, False
    return run_powershell(script, timeout=30)


def parse_verify(stdout: str | None) -> list[dict[str, str]]:
    found: list[dict[str, str]] = []
    if not stdout:
        return found
    for raw in stdout.splitlines():
        line = raw.strip()
        if line.startswith("VERIFY:MISSING:"):
            found.append({"name": line.split(":", 2)[2], "missing": "yes"})
            continue
        if not line.startswith("VERIFY:"):
            continue
        parts = line.split(":", 1)[1].split("|")
        if len(parts) != 8:
            continue
        name, enabled, direction, action, profile, family, program, remote = parts
        found.append(
            {
                "name": name,
                "enabled": enabled,
                "direction": direction,
                "action": action,
                "profile": profile,
                "address_family": family,
                "program": program,
                "remote": remote,
                "missing": "no",
            }
        )
    return found


def _profile_ok(requested: str, observed: str) -> bool:
    if observed.strip().lower() == requested.lower():
        return True
    if requested == "Any" and observed.strip().lower() in {"any", "domain, private, public"}:
        return True
    return False


def _remote_ok(requested: list[str], observed: str) -> bool:
    text = observed.strip().lower().replace(" ", "")
    if not requested:
        return text in {"", "any", "*"}
    for item in requested:
        network = ipaddress.ip_network(item, strict=False)
        host = str(network.network_address).lower()
        if host not in text and item.lower() not in text:
            return False
    return True


def _matches(rows: list[dict[str, str]], params: dict[str, Any]) -> bool:
    names = rule_names(
        params["program"],
        params["profile"],
        list(params["address_families"]),
        list(params["remote_addresses"]),
    )
    by_name = {row["name"]: row for row in rows if row.get("missing") != "yes"}
    if len(by_name) != len(names):
        return False
    for name, family in names:
        row = by_name.get(name)
        if row is None:
            return False
        if row.get("enabled", "").lower() not in {"true", "enabled"}:
            return False
        if row.get("direction", "").lower() != "outbound":
            return False
        if row.get("action", "").lower() != "block":
            return False
        if not _profile_ok(params["profile"], row.get("profile", "")):
            return False
        if row.get("address_family", "").lower() != family.lower():
            return False
        if row.get("program", "").lower() != params["program"].lower():
            return False
        if not _remote_ok(list(params["remote_addresses"]), row.get("remote", "")):
            return False
    return True


def _refused(message: str, *, code: str = "refused") -> dict[str, Any]:
    return {
        "ok": False,
        "code": code,
        "performed": False,
        "message": message,
        "verified": [],
    }


def apply_verified(params: dict[str, Any], runner: Runner | None = None) -> dict[str, Any]:
    """Create the planned rules and keep them only when the second read matches."""
    if _apply_depth.get() <= 0:
        return _refused(
            "Firewall changes run only inside the privileged helper. " + HONEST_FAIL,
        )
    runner = runner or _default_runner
    try:
        script = apply_script(params)
        undo = remove_script(
            [
                name
                for name, _family in rule_names(
                    params["program"],
                    params["profile"],
                    list(params["address_families"]),
                    list(params["remote_addresses"]),
                )
            ]
        )
    except ValueError:
        return _refused("The firewall request was not safe to pass to PowerShell. " + HONEST_FAIL, code="bad_params")
    if "Stop-Service" in script or "Set-Service" in script or "Stop-Service" in undo:
        return _refused("Refusing a firewall script that would stop a service. " + HONEST_FAIL)
    stdout, timed_out = runner(script)
    rows = parse_verify(stdout)
    if timed_out or not _matches(rows, params):
        runner(undo)
        why = "the firewall command timed out" if timed_out else "the live rule did not match the request"
        return _refused(f"{HONEST_FAIL} The change was not kept because {why}.", code="verify_failed")
    message = HONEST_OK + " " + LEAK_WARNING
    if set(params["address_families"]) != {"IPv4", "IPv6"}:
        message += " This request does not cover every address family."
    return {
        "ok": True,
        "code": "ok",
        "performed": True,
        "message": message,
        "verified": rows,
    }

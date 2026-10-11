"""Helper-only Windows Firewall changes with exact filters and owned rollback.

NetSecurity has no AddressFamily rule parameter or address-filter property.
Families are expressed through RemoteAddress networks. Configuration evidence
does not establish that every packet was stopped.
"""

from __future__ import annotations

import contextvars
import hashlib
import ipaddress
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from agent.modules.firewall_assist import LEAK_WARNING
from agent.local_files import atomic_text, file_lock
from agent.utils import IS_WINDOWS, run_powershell

Runner = Callable[[str], tuple[str | None, bool]]
_apply_depth: contextvars.ContextVar[int] = contextvars.ContextVar("dvielle_fw_apply", default=0)
OWNER_GROUP = "DVielle"
OWNER_PREFIX = "DVielle invocation "
HONEST_FAIL = "D\'Vielle did not verify the requested firewall protection. Traffic stopping is unconfirmed."
HONEST_OK = (
    "Verified Windows Firewall outbound block rules for this program on the chosen profile. "
    "This does not prove every connection already stopped."
)


def apply_scope():
    return _Scope()


class _Scope:
    def __enter__(self) -> None:
        self._token = _apply_depth.set(_apply_depth.get() + 1)

    def __exit__(self, *_exc: object) -> None:
        _apply_depth.reset(self._token)


def _ps_quote(text: str) -> str:
    if "'" in text or any(ord(ch) < 32 for ch in text):
        raise ValueError("unsafe powershell literal")
    return "'" + text + "'"


def _family_remotes(family: str, remotes: list[str]) -> list[str]:
    version = {"IPv4": 4, "IPv6": 6}[family]
    if not remotes:
        return ["0.0.0.0/0" if version == 4 else "::/0"]
    return sorted({str(ipaddress.ip_network(item, strict=False)) for item in remotes
                   if ipaddress.ip_network(item, strict=False).version == version})


def rule_names(program: str, profile: str, families: list[str], remotes: list[str]) -> list[tuple[str, str]]:
    material = "\n".join([program, profile, ",".join(sorted(remotes))])
    digest = hashlib.sha256(material.encode("utf-8")).hexdigest()[:12]
    suffix = {"IPv4": "v4", "IPv6": "v6"}
    # An IPv4 destination must not produce an unrelated all-IPv6 block.
    return [(f"DVielle-restrict-{digest}-{suffix[family]}", family)
            for family in ("IPv4", "IPv6")
            if family in families and _family_remotes(family, remotes)]


def apply_script(params: dict[str, Any], *, ownership_token: str | None = None) -> str:
    names = rule_names(params["program"], params["profile"],
                       list(params["address_families"]), list(params["remote_addresses"]))
    if not names:
        raise ValueError("no matching address-family destinations")
    tag = OWNER_PREFIX + (ownership_token or uuid.uuid4().hex)
    entries = "\n".join(
        "  @{ Name = " + _ps_quote(name) + "; Remote = @("
        + ",".join(_ps_quote(item) for item in _family_remotes(family, params["remote_addresses"])) + ") }"
        for name, family in names
    )
    comments = "\n".join(f"# FAMILY:{family}:{name}" for name, family in names)
    return f"""
$ErrorActionPreference = 'Stop'
# DVIELLE_FW_APPLY
# PROGRAM:{params['program']}
# PROFILE:{params['profile']}
# REMOTE:{','.join(params['remote_addresses'])}
# OWNER:{tag}
{comments}
$planned = @(
{entries}
)
$program = {_ps_quote(params['program'])}
$profile = {_ps_quote(params['profile'])}
$tag = {_ps_quote(tag)}
try {{
  # Read the store with Stop, then filter in memory. SilentlyContinue on a
  # named lookup would turn access/read failures into a false 'absent' result.
  $persistent = @(Get-NetFirewallRule -PolicyStore PersistentStore -ErrorAction Stop)
  foreach ($item in $planned) {{
    $name = $item.Name
    $existing = @($persistent | Where-Object {{ [string]$_.Name -eq $name }})
    if ($existing.Count -gt 1) {{ throw 'Ambiguous firewall rule ownership' }}
    if ($existing.Count -eq 1) {{
      if ([string]$existing[0].Group -ne 'DVielle' -or [string]$existing[0].DisplayName -ne $name -or
          -not ([string]$existing[0].Description).StartsWith('DVielle invocation ')) {{
        throw 'Firewall name collides with a rule not owned by DVielle'
      }}
    }} else {{
      $new = @{{ Name = $name; DisplayName = $name; Group = 'DVielle'; Description = $tag;
                Direction = 'Outbound'; Action = 'Block'; Program = $program;
                Profile = $profile; RemoteAddress = @($item.Remote); Enabled = 'True';
                PolicyStore = 'PersistentStore'; ErrorAction = 'Stop' }}
      New-NetFirewallRule @new | Out-Null
      Write-Output ('CREATED:' + $name)
    }}
  }}
  $active = @(Get-NetFirewallRule -PolicyStore ActiveStore -ErrorAction Stop)
  foreach ($item in $planned) {{
    $name = $item.Name
    $rules = @($active | Where-Object {{ [string]$_.Name -eq $name }})
    if ($rules.Count -ne 1) {{ Write-Output ('VERIFY:MISSING:' + $name); continue }}
    $rule = $rules[0]
    $app = @(Get-NetFirewallApplicationFilter -AssociatedNetFirewallRule $rule -ErrorAction Stop)
    $addr = @(Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $rule -ErrorAction Stop)
    if ($app.Count -ne 1 -or $addr.Count -ne 1) {{ Write-Output ('VERIFY:MISSING:' + $name); continue }}
    $prog = ([string]$app[0].Program) -replace '[|\\r\\n]', ' '
    $rem = (@($addr[0].RemoteAddress) -join ',') -replace '[|\\r\\n]', ' '
    $group = ([string]$rule.Group) -replace '[|\\r\\n]', ' '
    $description = ([string]$rule.Description) -replace '[|\\r\\n]', ' '
    Write-Output ('VERIFY:' + [string]$rule.Name + '|' + [string]$rule.Enabled + '|' +
                  [string]$rule.Direction + '|' + [string]$rule.Action + '|' + [string]$rule.Profile +
                  '|derived|' + $prog + '|' + $rem + '|' + $group + '|' + $description)
  }}
  Write-Output 'STATUS:OK'
}} catch {{
  Write-Output 'STATUS:FAILED'
  Write-Output ('DETAIL:' + (([string]$_.Exception.Message) -replace '\\s+', ' '))
}}
exit 0
"""


def remove_script(names: list[str], *, ownership_token: str | None = None,
                  expected: dict[str, Any] | None = None) -> str:
    """Remove only this invocation's marked rules, never a pre-existing rule."""
    listed = "\n".join("  " + _ps_quote(name) for name in names)
    tag = OWNER_PREFIX + ownership_token if ownership_token is not None else ""
    guard = ""
    if expected is not None:
        destinations = "\n".join(
            "    " + _ps_quote(name) + " = @("
            + ",".join(_ps_quote(remote) for remote in _family_remotes(family, expected["remote_addresses"])) + ")"
            for name, family in rule_names(expected["program"], expected["profile"],
                                         expected["address_families"], expected["remote_addresses"])
        )
        guard = f"""
        $expectedRemote = @{{
{destinations}
        }}
        $app = @(Get-NetFirewallApplicationFilter -AssociatedNetFirewallRule $rule -ErrorAction Stop)
        $addr = @(Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $rule -ErrorAction Stop)
        $ports = @(Get-NetFirewallPortFilter -AssociatedNetFirewallRule $rule -ErrorAction Stop)
        $interfaces = @(Get-NetFirewallInterfaceFilter -AssociatedNetFirewallRule $rule -ErrorAction Stop)
        $types = @(Get-NetFirewallInterfaceTypeFilter -AssociatedNetFirewallRule $rule -ErrorAction Stop)
        $services = @(Get-NetFirewallServiceFilter -AssociatedNetFirewallRule $rule -ErrorAction Stop)
        $security = @(Get-NetFirewallSecurityFilter -AssociatedNetFirewallRule $rule -ErrorAction Stop)
        $wanted = ConvertTo-DvielleRemoteSet @($expectedRemote[$name])
        $actual = if ($addr.Count -eq 1) {{ ConvertTo-DvielleRemoteSet @($addr[0].RemoteAddress) }} else {{ '' }}
        if ([string]$rule.Enabled -ne 'True' -or [string]$rule.Direction -ne 'Outbound' -or
            [string]$rule.Action -ne 'Block' -or [string]$rule.Profile -ne {_ps_quote(expected['profile'])} -or
            $app.Count -ne 1 -or [string]$app[0].Program -ne {_ps_quote(expected['program'])} -or $actual -ne $wanted -or
            $addr.Count -ne 1 -or (@($addr[0].LocalAddress) -join ',') -ne 'Any' -or
            $ports.Count -ne 1 -or [string]$ports[0].Protocol -ne 'Any' -or
            (@($ports[0].LocalPort) -join ',') -ne 'Any' -or (@($ports[0].RemotePort) -join ',') -ne 'Any' -or
            $interfaces.Count -ne 1 -or (@($interfaces[0].InterfaceAlias) -join ',') -ne 'Any' -or
            $types.Count -ne 1 -or [string]$types[0].InterfaceType -ne 'Any' -or
            $services.Count -ne 1 -or [string]$services[0].Service -ne 'Any' -or
            ($app[0].PSObject.Properties.Name -notcontains 'Package') -or
            [string]$app[0].Package -notin @('', 'Any') -or [string]$ports[0].DynamicTarget -ne 'Any' -or
            (@($ports[0].IcmpType) -join ',') -ne 'Any' -or
            $security.Count -ne 1 -or [string]$security[0].Authentication -ne 'NotRequired' -or
            [string]$security[0].Encryption -ne 'NotRequired' -or [string]$security[0].OverrideBlockRules -ne 'False' -or
            [string]$security[0].LocalUser -ne 'Any' -or [string]$security[0].RemoteUser -ne 'Any' -or
            [string]$security[0].RemoteMachine -ne 'Any' -or [string]$rule.EdgeTraversalPolicy -ne 'Block' -or
            [string]$rule.LocalOnlyMapping -ne 'False' -or [string]$rule.LooseSourceMapping -ne 'False' -or
            [string]$rule.Owner -ne '' -or (@($rule.Platform) -join ',') -ne '' -or
            (@($rule.RemoteDynamicKeywordAddresses) -join ',') -ne '') {{
          Write-Output ('REMOVE:FAILED:' + $name)
          $untouched[$name] = $true
          continue
        }}
"""
    return f"""
$ErrorActionPreference = 'Stop'
# DVIELLE_FW_REMOVE
# OWNER:{tag}
function ConvertTo-DvielleRemoteSet($values) {{
  $normalized = foreach ($value in $values) {{
    $parts = ([string]$value).Split('/')
    $ip = $null
    if ($parts.Count -gt 2 -or -not [Net.IPAddress]::TryParse($parts[0],[ref]$ip)) {{ throw 'Unrecognized remote address.' }}
    $bytes = $ip.GetAddressBytes()
    $maximum = $bytes.Length * 8
    $prefix = $maximum
    if ($parts.Count -eq 2 -and (-not [int]::TryParse($parts[1],[ref]$prefix) -or $prefix -lt 0 -or $prefix -gt $maximum)) {{ throw 'Unrecognized remote prefix.' }}
    for ($index = 0; $index -lt $bytes.Length; $index++) {{
      $bits = [Math]::Min(8,[Math]::Max(0,$prefix - $index * 8))
      $bytes[$index] = $bytes[$index] -band (256 - [int][Math]::Pow(2,8 - $bits))
    }}
    $network = New-Object Net.IPAddress(,$bytes)
    $network.ToString().ToLowerInvariant() + '/' + $prefix
  }}
  return (@($normalized) | Sort-Object -Unique) -join ','
}}
$names = @(
{listed}
)
$tag = {_ps_quote(tag)}
try {{
  $persistent = @(Get-NetFirewallRule -PolicyStore PersistentStore -ErrorAction Stop)
  $untouched = @{{}}
  foreach ($name in $names) {{
    $rules = @($persistent | Where-Object {{ [string]$_.Name -eq $name }})
    if ($rules.Count -gt 1) {{ Write-Output ('REMOVE:FAILED:' + $name); continue }}
    if ($rules.Count -eq 1) {{
      $rule = $rules[0]
      if ($tag -and [string]$rule.Group -eq 'DVielle' -and [string]$rule.DisplayName -eq $name -and
          [string]$rule.Description -eq $tag) {{
{guard}
        Remove-NetFirewallRule -InputObject $rule -ErrorAction Stop
      }} else {{ $untouched[$name] = $true }}
    }}
  }}
  $after = @(Get-NetFirewallRule -PolicyStore PersistentStore -ErrorAction Stop)
  foreach ($name in $names) {{
    $still = @($after | Where-Object {{ [string]$_.Name -eq $name }})
    if ($untouched.ContainsKey($name)) {{ Write-Output ('REMOVE:UNTOUCHED:' + $name) }}
    elseif ($still.Count) {{ Write-Output ('REMOVE:STILL:' + $name) }}
    else {{ Write-Output ('REMOVE:GONE:' + $name) }}
  }}
  Write-Output 'STATUS:OK'
}} catch {{
  Write-Output ('REMOVE:ERROR:' + $_.Exception.Message)
  Write-Output 'STATUS:FAILED'
}}
exit 0
"""


def _default_runner(script: str) -> tuple[str | None, bool]:
    if not IS_WINDOWS:
        return None, False
    return run_powershell(script, timeout=30)


def _remote_set(text: str) -> set[str] | None:
    """Normalize hosts, CIDRs and Windows' start-end range representation."""
    networks = []
    try:
        for item in text.split(","):
            item = item.strip()
            if "-" in item:
                first, last = item.split("-", 1)
                networks.extend(ipaddress.summarize_address_range(ipaddress.ip_address(first), ipaddress.ip_address(last)))
            else:
                networks.append(ipaddress.ip_network(item, strict=False))
    except ValueError:
        return None
    normalized = set()
    for version in (4, 6):
        normalized.update(str(n) for n in ipaddress.collapse_addresses(n for n in networks if n.version == version))
    return normalized


def parse_verify(stdout: str | None) -> list[dict[str, str]]:
    found = []
    for raw in (stdout or "").splitlines():
        line = raw.strip()
        if line.startswith("VERIFY:MISSING:"):
            found.append({"name": line.split(":", 2)[2], "missing": "yes"})
        elif line.startswith("VERIFY:"):
            parts = line.split(":", 1)[1].split("|")
            if len(parts) != 10:
                continue
            keys = ("name", "enabled", "direction", "action", "profile", "address_family", "program", "remote", "group", "description")
            row = dict(zip(keys, parts))
            remotes = _remote_set(row["remote"])
            versions = {ipaddress.ip_network(item).version for item in remotes or set()}
            row["address_family"] = {frozenset({4}): "IPv4", frozenset({6}): "IPv6"}.get(frozenset(versions), "Unknown")
            row["missing"] = "no"
            found.append(row)
    return found


def _profile_ok(requested: str, observed: str) -> bool:
    observed_set = {item.strip().lower() for item in observed.split(",")}
    return observed_set == {requested.lower()} or (requested == "Any" and observed_set == {"domain", "private", "public"})


def _remote_ok(requested: list[str], observed: str) -> bool:
    return _remote_set(",".join(requested)) == _remote_set(observed) if requested else False


def _matches(rows: list[dict[str, str]], params: dict[str, Any]) -> bool:
    names = rule_names(params["program"], params["profile"], list(params["address_families"]), list(params["remote_addresses"]))
    if len(rows) != len(names) or len({row["name"] for row in rows}) != len(names):
        return False
    by_name = {row["name"]: row for row in rows if row.get("missing") != "yes"}
    for name, family in names:
        row = by_name.get(name)
        if row is None or row.get("enabled", "").lower() not in {"true", "enabled"}:
            return False
        if row.get("direction", "").lower() != "outbound" or row.get("action", "").lower() != "block":
            return False
        if not _profile_ok(params["profile"], row.get("profile", "")) or row.get("address_family") != family:
            return False
        if row.get("program", "").lower() != params["program"].lower():
            return False
        if row.get("group") != OWNER_GROUP or not row.get("description", "").startswith(OWNER_PREFIX):
            return False
        if not _remote_ok(_family_remotes(family, params["remote_addresses"]), row.get("remote", "")):
            return False
    return bool(names)


def _refused(message: str, *, code: str = "refused", **extra: Any) -> dict[str, Any]:
    return {"ok": False, "code": code, "performed": False, "message": message, "verified": [], **extra}


def apply_verified(params: dict[str, Any], runner: Runner | None = None, *,
                   journal_path: Path | None = None) -> dict[str, Any]:
    """Live operations require intent durability before any Windows mutation.

    Explicit injected runners preserve the existing non-elevated unit-adapter
    path; production's default OS runner cannot execute without a journal.
    The future protected helper must own the supplied journal location.
    """
    if _apply_depth.get() <= 0:
        return _refused("Firewall changes run only inside the privileged helper. " + HONEST_FAIL)
    if journal_path is None:
        if runner is None:
            return _refused("A durable firewall recovery journal is required. Nothing was changed.",
                            code="journal_unavailable")
        return _apply_verified_core(params, runner, uuid.uuid4().hex)
    path = Path(journal_path)
    try:
        with file_lock(path.with_suffix(path.suffix + ".lock")):
            if path.exists():
                if path.stat().st_size > 262144:
                    return _refused("The firewall recovery journal is oversized. Nothing was changed.", code="recovery_required")
                prior = json.loads(path.read_text(encoding="utf-8"))
                if not isinstance(prior, dict) or prior.get("version") != 1 or prior.get("state") != "restored":
                    return _refused("An existing firewall intent requires reconciliation. Nothing was changed.",
                                    code="recovery_required")
            token = uuid.uuid4().hex
            # Build/validate both scripts before recording a planned mutation.
            apply_script(params, ownership_token=token)
            names = [name for name, _ in rule_names(params["program"], params["profile"],
                     list(params["address_families"]), list(params["remote_addresses"]))]
            record = {"version": 1, "state": "intent_durable", "created_at": datetime.now(timezone.utc).isoformat(),
                      "ownership_token": token, "params": params, "rule_names": names}
            atomic_text(path, json.dumps(record, indent=2, allow_nan=False))
            result = _apply_verified_core(params, runner or _default_runner, token)
            record["result"] = result
            record["state"] = ("configuration_verified" if result.get("ok") else
                               "restored" if result.get("rollback_verified") is True else "outcome_unknown")
            atomic_text(path, json.dumps(record, indent=2, allow_nan=False))
            result["journal_state"] = record["state"]
            return result
    except (OSError, ValueError, KeyError, TypeError, TimeoutError):
        # Persistence could have failed AFTER mutation. Keep this unknown and
        # leave any durable intent intact; do not report 'nothing changed'.
        return _refused("Firewall journal processing did not complete. Inspect the retained intent before retrying.",
                        code="outcome_unknown", state_unknown=True)


def _apply_verified_core(params: dict[str, Any], runner: Runner, ownership_token: str) -> dict[str, Any]:
    if _apply_depth.get() <= 0:
        return _refused("Firewall changes require the helper scope.")
    try:
        names = [name for name, _ in rule_names(params["program"], params["profile"],
                                               list(params["address_families"]), list(params["remote_addresses"]))]
        script = apply_script(params, ownership_token=ownership_token)
        undo = remove_script(names, ownership_token=ownership_token, expected=params)
    except (ValueError, KeyError, TypeError):
        return _refused("The firewall request was not safe to pass to PowerShell. " + HONEST_FAIL, code="bad_params")
    try:
        stdout, timed_out = runner(script)
    except Exception:
        stdout, timed_out = None, True
    rows = parse_verify(stdout)
    if timed_out or "STATUS:OK" not in (stdout or "").splitlines() or not _matches(rows, params):
        try:
            rollback_out, rollback_timed = runner(undo)
        except Exception:
            rollback_out, rollback_timed = None, True
        removal = set((rollback_out or "").splitlines())
        rollback_verified = not rollback_timed and "STATUS:OK" in removal and "STATUS:FAILED" not in removal and not any(
            line.startswith("REMOVE:FAILED:") for line in removal
        ) and all(
            f"REMOVE:GONE:{name}" in removal or f"REMOVE:UNTOUCHED:{name}" in removal for name in names
        )
        detail = (
            " Any rules owned by this attempt were removed; pre-existing rules were left untouched."
            if rollback_verified else
            " Cleanup was not verified. Rules from this attempt may remain; review Windows Firewall."
        )
        return _refused(HONEST_FAIL + detail, code="verify_failed", rollback_verified=rollback_verified,
                        state_unknown=not rollback_verified)
    message = HONEST_OK + " " + LEAK_WARNING
    actual_families = {row["address_family"] for row in rows}
    if actual_families != {"IPv4", "IPv6"}:
        message += " This request does not cover every address family."
    return {"ok": True, "code": "ok", "performed": True, "message": message, "verified": rows}


def restore_journal(journal_path: Path, runner: Runner | None = None) -> dict[str, Any]:
    """Helper-scoped recovery. Edited rules are retained and recovery stays pending.

    The service must protect this path against user writes. This function does
    not install a service, authenticate a caller, or establish consent.
    """
    if _apply_depth.get() <= 0:
        return _refused("Firewall recovery requires the privileged helper scope.")
    from agent.privilege.contract import validate_restrict_params
    path = Path(journal_path)
    try:
        with file_lock(path.with_suffix(path.suffix + ".lock")):
            if path.stat().st_size > 262144:
                raise ValueError("oversized journal")
            record = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(record, dict) or record.get("version") != 1:
                raise ValueError("invalid journal")
            if record.get("state") == "restored":
                return {"ok": True, "code": "already_restored", "performed": False}
            if record.get("state") not in {"intent_durable", "configuration_verified", "outcome_unknown"}:
                raise ValueError("invalid state")
            token = record.get("ownership_token")
            if not isinstance(token, str) or len(token) != 32 or any(ch not in "0123456789abcdef" for ch in token):
                raise ValueError("invalid ownership token")
            params, error = validate_restrict_params(record.get("params"), recovery_only=True)
            if params is None:
                raise ValueError(error)
            names = [name for name, _ in rule_names(params["program"], params["profile"],
                     params["address_families"], params["remote_addresses"])]
            if not names or names != record.get("rule_names"):
                raise ValueError("journal rule mismatch")
            # Flush the recovery intention before issuing any removal.
            record["state"] = "outcome_unknown"
            atomic_text(path, json.dumps(record, indent=2, allow_nan=False))
            output, timed_out = (runner or _default_runner)(
                remove_script(names, ownership_token=token, expected=params))
            lines = set((output or "").splitlines())
            verified = (not timed_out and "STATUS:OK" in lines and "STATUS:FAILED" not in lines
                        and not any(line.startswith("REMOVE:FAILED:") for line in lines)
                        and all(f"REMOVE:GONE:{name}" in lines or f"REMOVE:UNTOUCHED:{name}" in lines for name in names))
            record["state"] = "restored" if verified else "outcome_unknown"
            record["recovery_checked_at"] = datetime.now(timezone.utc).isoformat()
            atomic_text(path, json.dumps(record, indent=2, allow_nan=False))
            return {"ok": verified, "code": "restored" if verified else "recovery_required",
                    "performed": True, "journal_state": record["state"],
                    "message": "Owned-rule cleanup verified; other rules preserved." if verified else
                               "Cleanup is incomplete. Edited or unreadable rules require review."}
    except Exception:
        return _refused("Recovery was not verified. Retain the journal and review the firewall.",
                        code="recovery_required", state_unknown=True)

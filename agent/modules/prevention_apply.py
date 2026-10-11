"""Dual-gated ASR and CFA preference changes.

The mutator re-reads live preferences, accepts only a planned action, applies
one setting, then re-reads. Success is the second read, not the set command's
own text. Direct calls fail closed because they are outside the Cortex mutate
context.
"""

from __future__ import annotations

import json
import os
import tempfile
import contextvars
from contextlib import ExitStack
from functools import wraps
from pathlib import Path
from typing import Any, Callable
from uuid import UUID

from agent.local_files import file_lock
from agent.modules.defender_health import DefenderHealth, MapsCheck, query_defender_health, query_maps
from agent.modules.prevention import (
    ASR_BY_GUID,
    ASR_MODE_NAMES,
    CFA_MODE_NAMES,
    OBSERVE_PS,
    PreventionPosture,
    allowed_asr_actions,
    allowed_cfa_modes,
    build_promotion,
    parse_prevention,
)
from agent.policy.dual import require_cortex_mutate
from agent.utils import IS_WINDOWS, run_powershell

Runner = Callable[..., tuple[str | None, bool]]
HealthReader = Callable[[], DefenderHealth]
MapsReader = Callable[[], MapsCheck]

UNDO_NAME = "prevention_undo.txt"
_change_active: contextvars.ContextVar[bool] = contextvars.ContextVar("dvielle_prevention_active", default=False)


def _serialized_change(fn):
    """One lock covers every ASR/CFA read, journal, command, and verification."""
    @wraps(fn)
    def wrapped(*args, **kwargs):
        require_cortex_mutate()
        if _change_active.get():
            return _refused("A prevention change is already executing in this context. Nested changes were refused.")
        path = kwargs.get("undo_path")
        if path is None:
            return fn(*args, **kwargs)
        token = _change_active.set(True)
        try:
            with ExitStack() as stack:
                try:
                    stack.enter_context(file_lock(Path(path).with_suffix(Path(path).suffix + ".lock")))
                except (OSError, TimeoutError):
                    return _refused("The prevention recovery journal could not be locked. Nothing was changed.")
                return fn(*args, **kwargs)
        finally:
            _change_active.reset(token)
    return wrapped


def _default_runner(script: str, timeout: float = 25) -> tuple[str | None, bool]:
    if not IS_WINDOWS:
        return None, False
    return run_powershell(script, timeout=timeout)


def _refused(message: str, **extra: Any) -> dict[str, Any]:
    body = {"performed": False, "message": message, "reversible": "no"}
    body.update(extra)
    return body


def _set_outcome(stdout: str | None, timed_out: bool) -> tuple[bool, str]:
    if timed_out:
        return False, "the preference command timed out"
    if not stdout or not stdout.strip():
        return False, "the preference command returned no output"
    if any(line.startswith("SET:ACCESS_DENIED") for line in stdout.splitlines()):
        return False, "the preference command was access denied"
    if any(line.startswith("SET:OK") for line in stdout.splitlines()) and not any(
        line.startswith("SET:FAILED") for line in stdout.splitlines()
    ):
        return True, "the preference command returned ok"
    detail = ""
    for line in stdout.splitlines():
        if line.startswith("DETAIL:"):
            detail = line.split(":", 1)[1].strip()
    return False, detail or "the preference command failed"


def _configured_rules(posture: PreventionPosture) -> dict[str, int]:
    """Include rules unknown to our catalog; absent catalog entries are not preferences."""
    rules = {guid: action for guid, action in posture.rules.items() if action != 5}
    for item in posture.unknown_rules:
        guid, action = str(UUID(item["guid"])), int(item["action"])
        if action != 5:
            if guid in rules:
                raise ValueError("duplicate ASR rule")
            rules[guid] = action
    return rules


def _asr_set_script(guid: str, action: int, before: dict[str, int]) -> str:
    """Re-check the complete map in the writer before an Add, Set, or Remove.

    Set-MpPreference replaces both arrays. It must receive all existing rules,
    including rules absent from D\'Vielle's catalog. Add is used only for a new ID.
    The comparison detects intervening changes before the cmdlet; Windows does
    not provide an atomic compare-and-swap against other policy writers.
    """
    expected = dict(before)
    if action == 5:
        expected.pop(guid, None)
        operation = (
            f"Remove-MpPreference -AttackSurfaceReductionRules_Ids '{guid}' "
            f"-AttackSurfaceReductionRules_Actions {before[guid]}"
        )
        marker = "DVIELLE_ASR_REMOVE"
    elif guid not in before:
        expected[guid] = action
        operation = (
            f"Add-MpPreference -AttackSurfaceReductionRules_Ids '{guid}' "
            f"-AttackSurfaceReductionRules_Actions {action}"
        )
        marker = "DVIELLE_ASR_SET"
    else:
        expected[guid] = action
        ids = ",".join(f"'{str(UUID(key))}'" for key in sorted(expected))
        actions = ",".join(str(expected[key]) for key in sorted(expected))
        operation = (
            f"Set-MpPreference -AttackSurfaceReductionRules_Ids @({ids}) "
            f"-AttackSurfaceReductionRules_Actions @({actions})"
        )
        marker = "DVIELLE_ASR_SET"
    baseline = json.dumps(before, sort_keys=True, separators=(",", ":"))
    return f"""
$ErrorActionPreference = 'Stop'
# {marker}
# DVIELLE_ASR_EXPECTED:{json.dumps(expected, sort_keys=True, separators=(",", ":"))}
try {{
  $baseline = ConvertFrom-Json '{baseline}'
  $pref = Get-MpPreference -ErrorAction Stop
  $ids = @($pref.AttackSurfaceReductionRules_Ids | Where-Object {{ $null -ne $_ }})
  $actions = @($pref.AttackSurfaceReductionRules_Actions | Where-Object {{ $null -ne $_ }})
  $live = @{{}}
  if ($ids.Count -ne $actions.Count) {{ throw 'ASR preference arrays differ in length' }}
  for ($i = 0; $i -lt $ids.Count; $i++) {{
    $id = ([string]$ids[$i]).ToLowerInvariant()
    if ($live.ContainsKey($id)) {{ throw 'Duplicate ASR rule in live preferences' }}
    if ([int]$actions[$i] -ne 5) {{ $live[$id] = [int]$actions[$i] }}
  }}
  $properties = @($baseline.PSObject.Properties)
  if ($live.Count -ne $properties.Count) {{ throw 'ASR preferences changed before apply' }}
  foreach ($item in $properties) {{
    if (-not $live.ContainsKey($item.Name) -or $live[$item.Name] -ne [int]$item.Value) {{
      throw 'ASR preferences changed before apply'
    }}
  }}
  {operation}
  Write-Output 'SET:OK'
}} catch {{
  $flat = (([string]$_.Exception.Message) -replace '\\s+', ' ')
  if ($flat -match 'denied|0x80070005|80070005|Unauthorized|Tamper') {{
    Write-Output 'SET:ACCESS_DENIED'
  }} else {{
    Write-Output 'SET:FAILED'
  }}
  Write-Output ('DETAIL:' + $flat)
}}
exit 0
"""


def _cfa_set_script(mode: int, before_mode: int, before_rules: dict[str, int]) -> str:
    baseline = json.dumps(before_rules, sort_keys=True, separators=(",", ":"))
    return f"""
$ErrorActionPreference = 'Stop'
# DVIELLE_CFA_SET
try {{
  $baseline = ConvertFrom-Json '{baseline}'
  $pref = Get-MpPreference -ErrorAction Stop
  if ($null -eq $pref.EnableControlledFolderAccess -or [int]$pref.EnableControlledFolderAccess -ne {before_mode}) {{
    throw 'CFA mode changed before apply'
  }}
  $ids = @($pref.AttackSurfaceReductionRules_Ids | Where-Object {{ $null -ne $_ }})
  $actions = @($pref.AttackSurfaceReductionRules_Actions | Where-Object {{ $null -ne $_ }})
  $live = @{{}}
  if ($ids.Count -ne $actions.Count) {{ throw 'ASR preference arrays differ in length' }}
  for ($i = 0; $i -lt $ids.Count; $i++) {{
    $id = ([string]$ids[$i]).ToLowerInvariant()
    if ($live.ContainsKey($id)) {{ throw 'Duplicate ASR rule in live preferences' }}
    if ([int]$actions[$i] -ne 5) {{ $live[$id] = [int]$actions[$i] }}
  }}
  $properties = @($baseline.PSObject.Properties)
  if ($live.Count -ne $properties.Count) {{ throw 'ASR preferences changed before CFA apply' }}
  foreach ($item in $properties) {{
    if (-not $live.ContainsKey($item.Name) -or $live[$item.Name] -ne [int]$item.Value) {{
      throw 'ASR preferences changed before CFA apply'
    }}
  }}
  Set-MpPreference -EnableControlledFolderAccess {int(mode)}
  Write-Output 'SET:OK'
}} catch {{
  $flat = (([string]$_.Exception.Message) -replace '\\s+', ' ')
  if ($flat -match 'denied|0x80070005|80070005|Unauthorized|Tamper') {{
    Write-Output 'SET:ACCESS_DENIED'
  }} else {{
    Write-Output 'SET:FAILED'
  }}
  Write-Output ('DETAIL:' + $flat)
}}
exit 0
"""


def _read_undo(path: Path | None) -> dict[str, str]:
    if path is None:
        return {}
    found: dict[str, str] = {}
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return {}
    if not text.strip() or len(text) > 1024 * 1024:
        raise ValueError("empty or oversized prevention journal")
    for line in text.splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        if "|" not in line:
            raise ValueError("malformed prevention journal line")
        kind, _, rest = line.partition("|")
        kind, rest = kind.strip(), rest.strip()
        if not rest or kind in found:
            raise ValueError("empty or duplicate prevention journal entry")
        if kind.startswith("asr:"):
            UUID(kind.split(":", 1)[1])
            if rest != "absent" and (not rest.isdigit() or int(rest) not in ASR_MODE_NAMES):
                raise ValueError("invalid ASR undo mode")
        elif kind == "cfa":
            if not rest.isdigit() or int(rest) not in CFA_MODE_NAMES:
                raise ValueError("invalid CFA undo mode")
        elif kind in {"asr_snapshot", "asr_pending", "cfa_pending"}:
            data = json.loads(rest)
            if not isinstance(data, dict):
                raise ValueError("invalid prevention recovery record")
            if kind == "asr_snapshot":
                maps = [data]
            elif kind == "asr_pending":
                if set(data) != {"guid", "before", "expected"}:
                    raise ValueError("incomplete ASR recovery record")
                UUID(data["guid"])
                maps = [data["before"], data["expected"]]
            else:
                if set(data) != {"before", "expected", "asr_before"}:
                    raise ValueError("incomplete CFA recovery record")
                if any(isinstance(data[key], bool) or data[key] not in CFA_MODE_NAMES for key in ("before", "expected")):
                    raise ValueError("invalid CFA recovery mode")
                maps = [data["asr_before"]]
            for preference_map in maps:
                if not isinstance(preference_map, dict):
                    raise ValueError("invalid ASR recovery map")
                for guid, action in preference_map.items():
                    UUID(guid)
                    if isinstance(action, bool) or not isinstance(action, int) or action not in ASR_MODE_NAMES:
                        raise ValueError("invalid ASR recovery action")
        else:
            raise ValueError("unknown prevention journal entry")
        found[kind] = rest
    return found


def _write_undo(path: Path | None, records: dict[str, str]) -> None:
    if path is None:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = ["# D\'Vielle prevention undo. Previous mode before the last verified change."]
    for kind in sorted(records):
        if records[kind]:
            lines.append(f"{kind}|{records[kind]}")
    temporary: str | None = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent, delete=False) as stream:
            temporary = stream.name
            stream.write("\n".join(lines) + "\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if temporary is not None:
            Path(temporary).unlink(missing_ok=True)


def _undo_action(records: dict[str, str], key: str) -> int | None:
    raw = records.get(key)
    if raw is None or raw == "":
        return None
    token = raw.split("|", 1)[0].strip()
    if token in {"", "absent"}:
        return 5
    try:
        value = int(token)
    except ValueError:
        return None
    return value


def _clear_pending(records: dict[str, str], key: str, path: Path) -> bool:
    """Clear a failed attempt only after the entire original state was observed."""
    restored = dict(records)
    restored.pop(key, None)
    try:
        _write_undo(path, restored)
    except OSError:
        return False
    return True


def _observe(runner: Runner) -> PreventionPosture:
    stdout, timed_out = runner(OBSERVE_PS, timeout=25)
    posture = parse_prevention(stdout, timed_out=timed_out)
    ids = [line.split(":", 1)[1].split("=", 1)[0].strip().lower()
           for line in (stdout or "").splitlines() if line.startswith("RULE:")]
    if posture.coverage == "complete" and len(set(ids)) != len(ids):
        posture.coverage = "partial"
        posture.coverage_detail = "ASR collection contained duplicate rule IDs."
    return posture


@_serialized_change
def apply_asr_rule(
    *,
    guid: str,
    action: Any,
    runner: Runner | None = None,
    health_reader: HealthReader | None = None,
    maps_reader: MapsReader | None = None,
    undo_path: Path | None = None,
    sku: str | None = None,
) -> dict[str, Any]:
    """Set one catalogued ASR rule. Caller must already be inside DualGate.perform."""
    require_cortex_mutate()
    token = str(guid or "").strip().lower()
    rule = ASR_BY_GUID.get(token)
    if rule is None:
        return _refused("That ASR rule is not in the D\'Vielle catalog. Nothing was changed.")
    if isinstance(action, bool) or not isinstance(action, int) or action not in ASR_MODE_NAMES:
        return _refused("That ASR action is not a documented mode. Nothing was changed.")
    if undo_path is None:
        return _refused("A durable recovery journal is required for ASR changes. Nothing was changed.")
    runner = runner or _default_runner
    health = (health_reader or query_defender_health)()
    maps = (maps_reader or query_maps)()
    before = _observe(runner)
    if before.coverage != "complete":
        return _refused(before.coverage_detail + " Nothing was changed.", live_action=None)
    promotion = build_promotion(before, health, maps, sku=sku)
    try:
        records = _read_undo(undo_path)
    except (OSError, ValueError, TypeError, AttributeError):
        return _refused("The existing prevention recovery journal was unreadable or corrupt. Nothing was changed.")
    if "asr_pending" in records or "cfa_pending" in records:
        return _refused("An earlier prevention change has unresolved recovery information. Review it before another change.",
                        recovery_pending=True)
    previous = _undo_action(records, f"asr:{token}")
    allowed = allowed_asr_actions(promotion, token, previous)
    live = before.rules.get(token, 5)
    if action not in allowed:
        return _refused(
            "That ASR change is not allowed from the live mode. Nothing was changed.",
            live_action=live,
            requested_action=action,
        )
    try:
        baseline = _configured_rules(before)
        expected = dict(baseline)
        if action == 5:
            expected.pop(token, None)
        else:
            expected[token] = action
        script = _asr_set_script(token, action, baseline)
    except (ValueError, KeyError):
        return _refused("The complete ASR preference map could not be preserved. Nothing was changed.")
    # Recovery evidence must exist before a mutation. Keep the prior verified
    # per-rule undo entry until this operation is verified successfully.
    records["asr_pending"] = json.dumps(
        {"guid": token, "before": baseline, "expected": expected}, sort_keys=True, separators=(",", ":")
    )
    try:
        _write_undo(undo_path, records)
    except OSError:
        return _refused("ASR recovery information could not be saved. Nothing was changed.")
    set_out, set_timed = runner(script, timeout=25)
    command_ok, command_detail = _set_outcome(set_out, set_timed)
    after = _observe(runner)
    try:
        verified = (
            after.coverage == "complete"
            and _configured_rules(after) == expected
            and after.cfa_mode == before.cfa_mode
        )
    except (ValueError, KeyError):
        verified = False
    if not command_ok or not verified:
        live_after = after.rules.get(token) if after.coverage == "complete" else None
        try:
            unchanged = after.coverage == "complete" and _configured_rules(after) == baseline and after.cfa_mode == before.cfa_mode
        except (ValueError, KeyError):
            unchanged = False
        cleared = unchanged and _clear_pending(records, "asr_pending", undo_path)
        return _refused(
            "The complete live ASR preference map was not verified. "
            + command_detail
            + " D\'Vielle does not record this as applied.",
            live_action=live_after,
            requested_action=action,
            recovery_pending=not cleared,
            live_state_unknown=after.coverage != "complete",
        )
    records[f"asr:{token}"] = "absent" if live == 5 else str(live)
    records["asr_snapshot"] = json.dumps(baseline, sort_keys=True, separators=(",", ":"))
    records.pop("asr_pending", None)
    try:
        _write_undo(undo_path, records)
    except OSError:
        return {
            "performed": True,
            "message": "The complete ASR change was verified, but its recovery journal could not be finalized.",
            "reversible": "unknown",
            "recovery_pending": True,
            "previous_action": live,
            "live_action": action,
        }
    return {
        "performed": True,
        "message": f"ASR rule {rule.name} is {ASR_MODE_NAMES[action]} in the live preference.",
        "reversible": "yes" if undo_path is not None else "no",
        "previous_action": live,
        "live_action": action,
        "requested_action": action,
    }


@_serialized_change
def apply_cfa_mode(
    *,
    mode: Any,
    runner: Runner | None = None,
    health_reader: HealthReader | None = None,
    maps_reader: MapsReader | None = None,
    undo_path: Path | None = None,
    sku: str | None = None,
) -> dict[str, Any]:
    """Set CFA mode. Caller must already be inside DualGate.perform."""
    require_cortex_mutate()
    if isinstance(mode, bool) or not isinstance(mode, int) or mode not in CFA_MODE_NAMES:
        return _refused("That CFA mode is not a documented value. Nothing was changed.")
    if undo_path is None:
        return _refused("A durable recovery journal is required for CFA changes. Nothing was changed.")
    runner = runner or _default_runner
    health = (health_reader or query_defender_health)()
    maps = (maps_reader or query_maps)()
    before = _observe(runner)
    if before.coverage != "complete" or before.cfa_mode is None:
        return _refused((before.coverage_detail or "CFA mode was not read") + " Nothing was changed.")
    promotion = build_promotion(before, health, maps, sku=sku)
    try:
        records = _read_undo(undo_path)
    except (OSError, ValueError, TypeError, AttributeError):
        return _refused("The existing prevention recovery journal was unreadable or corrupt. Nothing was changed.")
    if "asr_pending" in records or "cfa_pending" in records:
        return _refused("An earlier prevention change has unresolved recovery information. Review it before another change.",
                        recovery_pending=True)
    previous = _undo_action(records, "cfa")
    allowed = allowed_cfa_modes(promotion, previous)
    if mode not in allowed:
        return _refused(
            "That CFA change is not allowed from the live mode. Nothing was changed.",
            live_mode=before.cfa_mode,
            requested_mode=mode,
        )
    try:
        asr_before = _configured_rules(before)
        records["cfa_pending"] = json.dumps(
            {"before": before.cfa_mode, "expected": mode, "asr_before": asr_before},
            sort_keys=True, separators=(",", ":"),
        )
        _write_undo(undo_path, records)
    except (OSError, ValueError, KeyError):
        return _refused("CFA recovery information could not be saved. Nothing was changed.")
    set_out, set_timed = runner(_cfa_set_script(mode, before.cfa_mode, asr_before), timeout=25)
    command_ok, command_detail = _set_outcome(set_out, set_timed)
    after = _observe(runner)
    try:
        verified = after.coverage == "complete" and after.cfa_mode == mode and _configured_rules(after) == asr_before
    except (ValueError, KeyError):
        verified = False
    if not command_ok or not verified:
        try:
            unchanged = after.coverage == "complete" and after.cfa_mode == before.cfa_mode and _configured_rules(after) == asr_before
        except (ValueError, KeyError):
            unchanged = False
        cleared = unchanged and _clear_pending(records, "cfa_pending", undo_path)
        return _refused(
            "The live CFA mode does not match the request. "
            + command_detail
            + " D\'Vielle does not record this as applied.",
            live_mode=after.cfa_mode,
            requested_mode=mode,
            recovery_pending=not cleared,
        )
    records["cfa"] = str(before.cfa_mode)
    records.pop("cfa_pending", None)
    try:
        _write_undo(undo_path, records)
    except OSError:
        return {
            "performed": True,
            "message": "The CFA change was verified, but its recovery journal could not be finalized.",
            "reversible": "unknown",
            "recovery_pending": True,
            "previous_mode": before.cfa_mode,
            "live_mode": mode,
        }
    return {
        "performed": True,
        "message": (
            f"Controlled folder access is {CFA_MODE_NAMES[mode]} in the live preference. "
            "This is a modification shield. Offline backups and a restore test are still required."
        ),
        "reversible": "yes" if undo_path is not None else "no",
        "previous_mode": before.cfa_mode,
        "live_mode": mode,
        "requested_mode": mode,
    }


def undo_path_for(learn_dir: Path | None) -> Path | None:
    if learn_dir is None:
        return None
    return Path(learn_dir) / UNDO_NAME

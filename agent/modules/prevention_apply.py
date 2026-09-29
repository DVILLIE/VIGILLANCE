"""Dual-gated ASR and CFA preference changes.

The mutator re-reads live preferences, accepts only a planned action, applies
one setting, then re-reads. Success is the second read, not the set command's
own text. Direct calls fail closed because they are outside the Cortex mutate
context.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Callable

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


def _asr_set_script(guid: str, action: int) -> str:
    return f"""
$ErrorActionPreference = 'Stop'
# DVIELLE_ASR_SET
try {{
  Set-MpPreference -AttackSurfaceReductionRules_Ids '{guid}' -AttackSurfaceReductionRules_Actions {int(action)}
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


def _asr_remove_script(guid: str, live_action: int) -> str:
    return f"""
$ErrorActionPreference = 'Stop'
# DVIELLE_ASR_REMOVE
try {{
  Remove-MpPreference -AttackSurfaceReductionRules_Ids '{guid}' -AttackSurfaceReductionRules_Actions {int(live_action)}
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


def _cfa_set_script(mode: int) -> str:
    return f"""
$ErrorActionPreference = 'Stop'
# DVIELLE_CFA_SET
try {{
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
    if path is None or not path.exists():
        return {}
    found: dict[str, str] = {}
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return {}
    for line in text.splitlines():
        if not line.strip() or line.startswith("#") or "|" not in line:
            continue
        kind, _, rest = line.partition("|")
        found[kind.strip()] = rest.strip()
    return found


def _write_undo(path: Path | None, records: dict[str, str]) -> None:
    if path is None:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = ["# DVielle prevention undo. Previous mode before the last verified change."]
    for kind in sorted(records):
        if records[kind]:
            lines.append(f"{kind}|{records[kind]}")
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text("\n".join(lines) + "\n", encoding="utf-8")
    temporary.replace(path)


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


def _observe(runner: Runner) -> PreventionPosture:
    stdout, timed_out = runner(OBSERVE_PS, timeout=25)
    return parse_prevention(stdout, timed_out=timed_out)


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
        return _refused("That ASR rule is not in the DVielle catalog. Nothing was changed.")
    if isinstance(action, bool) or not isinstance(action, int) or action not in ASR_MODE_NAMES:
        return _refused("That ASR action is not a documented mode. Nothing was changed.")
    runner = runner or _default_runner
    health = (health_reader or query_defender_health)()
    maps = (maps_reader or query_maps)()
    before = _observe(runner)
    if before.coverage != "complete":
        return _refused(before.coverage_detail + " Nothing was changed.", live_action=None)
    promotion = build_promotion(before, health, maps, sku=sku)
    records = _read_undo(undo_path)
    previous = _undo_action(records, f"asr:{token}")
    allowed = allowed_asr_actions(promotion, token, previous)
    live = before.rules.get(token, 5)
    if action not in allowed:
        return _refused(
            "That ASR change is not allowed from the live mode. Nothing was changed.",
            live_action=live,
            requested_action=action,
        )
    if action == 5:
        script = _asr_remove_script(token, live if live in ASR_MODE_NAMES and live != 5 else 0)
    else:
        script = _asr_set_script(token, action)
    set_out, set_timed = runner(script, timeout=25)
    command_ok, command_detail = _set_outcome(set_out, set_timed)
    after = _observe(runner)
    verified = after.coverage == "complete" and after.rules.get(token, 5) == action
    if not command_ok or not verified:
        live_after = after.rules.get(token) if after.coverage == "complete" else None
        return _refused(
            "The live ASR preference does not match the request. "
            + command_detail
            + " DVielle does not record this as applied.",
            live_action=live_after,
            requested_action=action,
        )
    records[f"asr:{token}"] = "absent" if live == 5 else str(live)
    _write_undo(undo_path, records)
    return {
        "performed": True,
        "message": f"ASR rule {rule.name} is {ASR_MODE_NAMES[action]} in the live preference.",
        "reversible": "yes",
        "previous_action": live,
        "live_action": action,
        "requested_action": action,
    }


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
    runner = runner or _default_runner
    health = (health_reader or query_defender_health)()
    maps = (maps_reader or query_maps)()
    before = _observe(runner)
    if before.coverage != "complete" or before.cfa_mode is None:
        return _refused((before.coverage_detail or "CFA mode was not read") + " Nothing was changed.")
    promotion = build_promotion(before, health, maps, sku=sku)
    records = _read_undo(undo_path)
    previous = _undo_action(records, "cfa")
    allowed = allowed_cfa_modes(promotion, previous)
    if mode not in allowed:
        return _refused(
            "That CFA change is not allowed from the live mode. Nothing was changed.",
            live_mode=before.cfa_mode,
            requested_mode=mode,
        )
    set_out, set_timed = runner(_cfa_set_script(mode), timeout=25)
    command_ok, command_detail = _set_outcome(set_out, set_timed)
    after = _observe(runner)
    verified = after.coverage == "complete" and after.cfa_mode == mode
    if not command_ok or not verified:
        return _refused(
            "The live CFA mode does not match the request. "
            + command_detail
            + " DVielle does not record this as applied.",
            live_mode=after.cfa_mode,
            requested_mode=mode,
        )
    records["cfa"] = str(before.cfa_mode)
    _write_undo(undo_path, records)
    return {
        "performed": True,
        "message": (
            f"Controlled folder access is {CFA_MODE_NAMES[mode]} in the live preference. "
            "This is a modification shield. Offline backups and a restore test are still required."
        ),
        "reversible": "yes",
        "previous_mode": before.cfa_mode,
        "live_mode": mode,
        "requested_mode": mode,
    }


def undo_path_for(learn_dir: Path | None) -> Path | None:
    if learn_dir is None:
        return None
    return Path(learn_dir) / UNDO_NAME

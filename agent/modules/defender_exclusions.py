"""Observe Defender exclusion and tamper-related preference changes.

Read-only. Never adds ExclusionPath (install contracts forbid that). Access
denial stays partial — not an all-clear. Baseline lives under data/learn.
"""

from __future__ import annotations

import json
import logging
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Literal

from agent.utils import DEFAULT_DATA_DIR, IS_WINDOWS, run_powershell

logger = logging.getLogger("dvielle.defender_exclusions")

Coverage = Literal["complete", "partial", "unavailable"]

ASSUMPTIONS: tuple[str, ...] = (
    "Exclusion lists require Get-MpPreference; Limited tokens often get access denied.",
    "Access denial is incomplete observation, not proof that exclusions are empty.",
    "D'Vielle never adds ExclusionPath from this module.",
    "A new exclusion after baseline is a suspicion ticket, not proof of compromise.",
    "DisableRealtimeMonitoring / DisableIOAVProtection are preference fields when readable.",
)

_OBSERVE_PS = r"""
$ErrorActionPreference = 'Stop'
try {
  $p = Get-MpPreference -ErrorAction Stop
  Write-Output 'STATUS:OK'
  $paths = @()
  if ($null -ne $p.ExclusionPath) { $paths = @($p.ExclusionPath) }
  $procs = @()
  if ($null -ne $p.ExclusionProcess) { $procs = @($p.ExclusionProcess) }
  $exts = @()
  if ($null -ne $p.ExclusionExtension) { $exts = @($p.ExclusionExtension) }
  Write-Output ('PATH_COUNT:' + $paths.Count)
  foreach ($x in $paths) {
    $flat = (([string]$x) -replace '\s+', ' ').Trim()
    if ($flat.Length -gt 240) { $flat = $flat.Substring(0, 240) }
    Write-Output ('PATH:' + $flat)
  }
  Write-Output ('PROC_COUNT:' + $procs.Count)
  foreach ($x in $procs) {
    $flat = (([string]$x) -replace '\s+', ' ').Trim()
    if ($flat.Length -gt 120) { $flat = $flat.Substring(0, 120) }
    Write-Output ('PROC:' + $flat)
  }
  Write-Output ('EXT_COUNT:' + $exts.Count)
  foreach ($x in $exts) {
    $flat = (([string]$x) -replace '\s+', ' ').Trim()
    if ($flat.Length -gt 40) { $flat = $flat.Substring(0, 40) }
    Write-Output ('EXT:' + $flat)
  }
  Write-Output ('DisableRealtimeMonitoring:' + [string]$p.DisableRealtimeMonitoring)
  Write-Output ('DisableIOAVProtection:' + [string]$p.DisableIOAVProtection)
  Write-Output ('DisableBehaviorMonitoring:' + [string]$p.DisableBehaviorMonitoring)
} catch {
  $flat = (([string]$_.Exception.Message) -replace '\s+', ' ')
  if ($flat -match 'denied|0x80070005|80070005|Unauthorized|administrator') {
    Write-Output 'STATUS:ACCESS_DENIED'
  } else {
    Write-Output 'STATUS:UNAVAILABLE'
  }
  Write-Output ('DETAIL:' + $flat)
}
exit 0
"""


@dataclass
class ExclusionSnapshot:
    coverage: Coverage
    coverage_detail: str
    paths: list[str] = field(default_factory=list)
    processes: list[str] = field(default_factory=list)
    extensions: list[str] = field(default_factory=list)
    disable_realtime: bool | None = None
    disable_ioav: bool | None = None
    disable_behavior: bool | None = None
    assumptions: list[str] = field(default_factory=lambda: list(ASSUMPTIONS))

    @property
    def coverage_complete(self) -> bool:
        return self.coverage == "complete"

    def fingerprint(self) -> dict[str, Any]:
        return {
            "paths": sorted(self.paths),
            "processes": sorted(self.processes),
            "extensions": sorted(self.extensions),
            "disable_realtime": self.disable_realtime,
            "disable_ioav": self.disable_ioav,
            "disable_behavior": self.disable_behavior,
        }

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ExclusionBatch:
    coverage: Coverage
    coverage_detail: str
    snapshot: ExclusionSnapshot | None = None
    facts: list[dict[str, Any]] = field(default_factory=list)
    assumptions: list[str] = field(default_factory=lambda: list(ASSUMPTIONS))

    @property
    def coverage_complete(self) -> bool:
        return self.coverage == "complete"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _bool_field(raw: str | None) -> bool | None:
    if raw is None:
        return None
    return {"true": True, "false": False}.get(raw.strip().lower())


def parse_exclusion_transcript(stdout: str | None, *, timed_out: bool = False) -> ExclusionSnapshot:
    if timed_out:
        return ExclusionSnapshot("partial", "Defender exclusion collection timed out")
    if not stdout or not stdout.strip():
        return ExclusionSnapshot("unavailable", "Defender exclusion collection returned no output")
    lines = stdout.splitlines()
    if any(line.startswith("STATUS:ACCESS_DENIED") for line in lines):
        detail = next((line[7:] for line in lines if line.startswith("DETAIL:")), "")
        extra = f": {detail}" if detail else ""
        return ExclusionSnapshot("partial", "Defender exclusions incomplete: access denied" + extra)
    fields: dict[str, str] = {}
    paths: list[str] = []
    procs: list[str] = []
    exts: list[str] = []
    for line in lines:
        if line.startswith("STATUS:"):
            fields["STATUS"] = line.split(":", 1)[1].strip().upper()
        elif line.startswith("DETAIL:"):
            fields["DETAIL"] = line.split(":", 1)[1].strip()
        elif line.startswith("PATH:"):
            paths.append(line.split(":", 1)[1].strip())
        elif line.startswith("PROC:") and not line.startswith("PROC_COUNT:"):
            procs.append(line.split(":", 1)[1].strip())
        elif line.startswith("EXT:") and not line.startswith("EXT_COUNT:"):
            exts.append(line.split(":", 1)[1].strip())
        elif ":" in line and line.split(":", 1)[0] in {
            "DisableRealtimeMonitoring",
            "DisableIOAVProtection",
            "DisableBehaviorMonitoring",
            "PATH_COUNT",
            "PROC_COUNT",
            "EXT_COUNT",
        }:
            key, val = line.split(":", 1)
            fields[key] = val.strip()
    status = fields.get("STATUS", "")
    if status == "UNAVAILABLE":
        extra = f": {fields.get('DETAIL', '')}" if fields.get("DETAIL") else ""
        return ExclusionSnapshot("unavailable", "Defender exclusions unavailable" + extra)
    if status != "OK":
        return ExclusionSnapshot("partial", "Defender exclusion status was not read")
    return ExclusionSnapshot(
        "complete",
        "Defender exclusion preferences were read",
        paths=paths,
        processes=procs,
        extensions=exts,
        disable_realtime=_bool_field(fields.get("DisableRealtimeMonitoring")),
        disable_ioav=_bool_field(fields.get("DisableIOAVProtection")),
        disable_behavior=_bool_field(fields.get("DisableBehaviorMonitoring")),
    )


def _baseline_path(learn_dir: Path) -> Path:
    return learn_dir / "baseline_defender_exclusions.json"


def load_baseline(learn_dir: Path) -> dict[str, Any] | None:
    path = _baseline_path(learn_dir)
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def save_baseline(learn_dir: Path, fingerprint: dict[str, Any]) -> None:
    learn_dir.mkdir(parents=True, exist_ok=True)
    path = _baseline_path(learn_dir)
    path.write_text(json.dumps(fingerprint, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def diff_facts(previous: dict[str, Any] | None, current: ExclusionSnapshot) -> list[dict[str, Any]]:
    """Emit tickets for new exclusions or newly disabled monitors after a baseline exists."""
    if current.coverage != "complete":
        return []
    fp = current.fingerprint()
    if previous is None:
        return []
    facts: list[dict[str, Any]] = []
    old_paths = set(previous.get("paths") or [])
    for path in fp["paths"]:
        if path not in old_paths:
            facts.append(
                {
                    "kind": "defender_exclusion_added",
                    "subject": f"exclusion:path:{path.lower()}",
                    "label": path,
                    "channel": "ExclusionPath",
                    "fresh": True,
                }
            )
    old_procs = set(previous.get("processes") or [])
    for proc in fp["processes"]:
        if proc not in old_procs:
            facts.append(
                {
                    "kind": "defender_exclusion_added",
                    "subject": f"exclusion:proc:{proc.lower()}",
                    "label": proc,
                    "channel": "ExclusionProcess",
                    "fresh": True,
                }
            )
    old_exts = set(previous.get("extensions") or [])
    for ext in fp["extensions"]:
        if ext not in old_exts:
            facts.append(
                {
                    "kind": "defender_exclusion_added",
                    "subject": f"exclusion:ext:{ext.lower()}",
                    "label": ext,
                    "channel": "ExclusionExtension",
                    "fresh": True,
                }
            )
    for field_name, key, label in (
        ("disable_realtime", "disable_realtime", "real-time monitoring disabled via preference"),
        ("disable_ioav", "disable_ioav", "IOAV protection disabled via preference"),
        ("disable_behavior", "disable_behavior", "behavior monitoring disabled via preference"),
    ):
        was = previous.get(key)
        now = fp.get(key)
        if was is False and now is True:
            facts.append(
                {
                    "kind": "defender_preference_weakened",
                    "subject": f"exclusion:pref:{field_name}",
                    "label": label,
                    "channel": field_name,
                    "fresh": True,
                }
            )
    return facts


def collect_exclusion_batch(learn_dir: Path | None = None) -> ExclusionBatch:
    if not IS_WINDOWS:
        return ExclusionBatch("unavailable", "Defender exclusion watch is Windows-only")
    out, timed_out = run_powershell(_OBSERVE_PS, timeout=25)
    snap = parse_exclusion_transcript(out, timed_out=timed_out)
    if snap.coverage != "complete":
        return ExclusionBatch(snap.coverage, snap.coverage_detail, snapshot=snap)

    root = learn_dir or (DEFAULT_DATA_DIR / "learn")
    previous = load_baseline(root)
    facts = diff_facts(previous, snap)
    if previous is None:
        save_baseline(root, snap.fingerprint())
        detail = snap.coverage_detail + "; first baseline stored (no change tickets yet)"
    else:
        # Refresh baseline to current after diff so removals do not re-alert forever;
        # new additions still fire once relative to prior baseline.
        save_baseline(root, snap.fingerprint())
        detail = snap.coverage_detail + (f"; {len(facts)} change(s)" if facts else "; no exclusion changes")
    logger.info("defender_exclusions coverage=%s facts=%s", snap.coverage, len(facts))
    return ExclusionBatch(snap.coverage, detail, snapshot=snap, facts=facts)

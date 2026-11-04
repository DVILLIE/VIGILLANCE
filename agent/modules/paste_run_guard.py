"""Paste-and-run / ClickFix-class observer (no clipboard).

Detects suspicious PowerShell / cmd *command lines* and optional PowerShell
script-block (4104) lure text that Microsoft and Elastic document for
TerminalFix / ClickFix. Never reads the clipboard. Never kills a process.
Access denial and missing script-block logging stay partial/unavailable —
not an all-clear.
"""

from __future__ import annotations

import hashlib
import logging
import re
from dataclasses import asdict, dataclass, field
from typing import Any, Literal

from agent.utils import IS_WINDOWS, run_powershell

logger = logging.getLogger("dvielle.paste_run")

Coverage = Literal["complete", "partial", "unavailable"]

ASSUMPTIONS: tuple[str, ...] = (
    "This module never reads the clipboard.",
    "Process command lines come from Win32_Process.CommandLine when readable.",
    "Script-block text requires Microsoft-Windows-PowerShell/Operational event 4104.",
    "Missing 4104 logging is unavailable for that channel, not proof of safety.",
    "A match is a suspicion ticket, not proof of malware infection.",
    "Patterns follow public TerminalFix/ClickFix hunting guidance (Microsoft 2026-08-28, Elastic).",
)

# Defensive hunting strings only — from public TerminalFix/ClickFix writeups.
_LURE = re.compile(
    r"cloudflare\s+(verification|id:)|i(?:'m| am) not a robot|starting cloudflare",
    re.I,
)
_RETRIEVE = re.compile(
    r"\biex\b|\binvoke-expression\b|\birm\b|\binvoke-restmethod\b|"
    r"downloadstring|downloadfile|wget\s+|curl\s+.*\|.*iex|"
    r"-enc(?:odedcommand)?\b|frombase64string",
    re.I,
)
_STAGE = re.compile(
    r"programdata\\|\\users\\[^\\]+\\appdata\\local\\temp\\|"
    r"1\.bat|lockscreencentserver|expand-archive|start-process",
    re.I,
)
_HIDDEN = re.compile(r"-windowstyle\s+hidden|-w(?:indowstyle)?\s+h(?:idden)?|-nop(?:rofile)?", re.I)

_HOSTS = frozenset(
    {
        "powershell.exe",
        "pwsh.exe",
        "powershell_ise.exe",
        "cmd.exe",
        "windowsterminal.exe",
        "wt.exe",
    }
)


@dataclass
class PasteRunBatch:
    coverage: Coverage
    coverage_detail: str
    facts: list[dict[str, Any]] = field(default_factory=list)
    assumptions: list[str] = field(default_factory=lambda: list(ASSUMPTIONS))

    @property
    def coverage_complete(self) -> bool:
        return self.coverage == "complete"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def score_script(text: str) -> tuple[int, list[str]]:
    """Return (score, matched_tags). Higher = more ClickFix-like."""
    blob = text or ""
    tags: list[str] = []
    score = 0
    if _LURE.search(blob):
        tags.append("cloudflare_lure")
        score += 4
    if _RETRIEVE.search(blob):
        tags.append("remote_retrieve")
        score += 3
    if _STAGE.search(blob):
        tags.append("staging_path")
        score += 2
    if _HIDDEN.search(blob) and _RETRIEVE.search(blob):
        tags.append("hidden_retrieve")
        score += 2
    return score, tags


def _fact(
    *,
    channel: str,
    snippet: str,
    tags: list[str],
    score: int,
    pid: int = 0,
    process_name: str = "",
) -> dict[str, Any]:
    digest = hashlib.sha256(f"{channel}|{snippet[:800]}".encode("utf-8", errors="replace")).hexdigest()[:16]
    return {
        "channel": channel,
        "pid": pid,
        "process_name": process_name,
        "snippet": snippet[:500],
        "tags": tags,
        "score": score,
        "subject": f"paste_run:{digest}",
        "fresh": True,
    }


_PROCESS_PS = r"""
$ErrorActionPreference = 'Continue'
try {
  $names = @('powershell.exe','pwsh.exe','powershell_ise.exe','cmd.exe')
  Get-CimInstance Win32_Process -ErrorAction Stop |
    Where-Object { $names -contains $_.Name.ToLower() -and $_.CommandLine } |
    Select-Object -First 40 ProcessId, Name, CommandLine |
    ForEach-Object {
      $line = (($_.CommandLine) -replace '\s+', ' ').Trim()
      if ($line.Length -gt 900) { $line = $line.Substring(0, 900) }
      Write-Output ('PROC:' + $_.ProcessId + '|' + $_.Name + '|' + $line)
    }
  Write-Output 'PROC_STATUS:OK'
} catch {
  $flat = (([string]$_.Exception.Message) -replace '\s+', ' ')
  if ($flat -match 'denied|0x80070005|Unauthorized') { Write-Output 'PROC_STATUS:ACCESS_DENIED' }
  else { Write-Output 'PROC_STATUS:UNAVAILABLE' }
  Write-Output ('PROC_DETAIL:' + $flat)
}
exit 0
"""

_SCRIPTBLOCK_PS = r"""
$ErrorActionPreference = 'Continue'
try {
  $log = 'Microsoft-Windows-PowerShell/Operational'
  $events = @(Get-WinEvent -LogName $log -MaxEvents 40 -ErrorAction Stop |
    Where-Object { $_.Id -eq 4104 } |
    Select-Object -First 25)
  foreach ($e in $events) {
    $msg = (($e.Message) -replace '\s+', ' ').Trim()
    if ($msg.Length -gt 900) { $msg = $msg.Substring(0, 900) }
    Write-Output ('SB:' + $e.TimeCreated.ToUniversalTime().ToString('o') + '|' + $msg)
  }
  Write-Output 'SB_STATUS:OK'
} catch {
  $flat = (([string]$_.Exception.Message) -replace '\s+', ' ')
  if ($flat -match 'denied|0x80070005|Unauthorized') { Write-Output 'SB_STATUS:ACCESS_DENIED' }
  elseif ($flat -match 'No events|cannot find|does not exist|not found') { Write-Output 'SB_STATUS:UNAVAILABLE' }
  else { Write-Output 'SB_STATUS:UNAVAILABLE' }
  Write-Output ('SB_DETAIL:' + $flat)
}
exit 0
"""


def parse_process_transcript(stdout: str | None, *, timed_out: bool = False) -> tuple[Coverage, str, list[dict[str, Any]]]:
    if timed_out:
        return "partial", "Process command-line collection timed out", []
    if not stdout or not stdout.strip():
        return "unavailable", "Process command-line collection returned no output", []
    lines = stdout.splitlines()
    if any(line.startswith("PROC_STATUS:ACCESS_DENIED") for line in lines):
        return "partial", "Process command lines incomplete: access denied", []
    if any(line.startswith("PROC_STATUS:UNAVAILABLE") for line in lines):
        return "unavailable", "Process command lines unavailable", []
    if not any(line.startswith("PROC_STATUS:OK") for line in lines):
        return "partial", "Process command-line status was not read", []
    facts: list[dict[str, Any]] = []
    for line in lines:
        if not line.startswith("PROC:"):
            continue
        body = line[5:]
        parts = body.split("|", 2)
        if len(parts) != 3:
            continue
        try:
            pid = int(parts[0])
        except ValueError:
            pid = 0
        name = parts[1].strip()
        cmd = parts[2]
        if name.lower() not in _HOSTS and not name.lower().endswith(".exe"):
            continue
        score, tags = score_script(cmd)
        # Require retrieve+something, or lure alone, to cut noise from benign -NoProfile.
        if score < 3 and "cloudflare_lure" not in tags:
            continue
        if "remote_retrieve" not in tags and "cloudflare_lure" not in tags:
            continue
        facts.append(_fact(channel="process_cmdline", snippet=cmd, tags=tags, score=score, pid=pid, process_name=name))
    return "complete", "Process command lines were read", facts


def parse_scriptblock_transcript(stdout: str | None, *, timed_out: bool = False) -> tuple[Coverage, str, list[dict[str, Any]]]:
    if timed_out:
        return "partial", "Script-block collection timed out", []
    if not stdout or not stdout.strip():
        return "unavailable", "Script-block collection returned no output", []
    lines = stdout.splitlines()
    if any(line.startswith("SB_STATUS:ACCESS_DENIED") for line in lines):
        return "partial", "Script-block logging incomplete: access denied", []
    if any(line.startswith("SB_STATUS:UNAVAILABLE") for line in lines):
        return "unavailable", "Script-block logging unavailable (enable PowerShell Script Block Logging for 4104)", []
    if not any(line.startswith("SB_STATUS:OK") for line in lines):
        return "partial", "Script-block status was not read", []
    facts: list[dict[str, Any]] = []
    for line in lines:
        if not line.startswith("SB:"):
            continue
        body = line[3:]
        _ts, _, msg = body.partition("|")
        score, tags = score_script(msg)
        if "cloudflare_lure" not in tags and score < 5:
            continue
        if "cloudflare_lure" in tags or ("remote_retrieve" in tags and "staging_path" in tags):
            facts.append(_fact(channel="script_block_4104", snippet=msg, tags=tags, score=score))
    return "complete", "Script-block events were read", facts


def _merge_coverage(a: Coverage, b: Coverage) -> Coverage:
    order = {"unavailable": 0, "partial": 1, "complete": 2}
    # Overall complete only if both channels are complete.
    if a == "complete" and b == "complete":
        return "complete"
    if order[a] <= order[b]:
        return a if a != "complete" else b
    return b if b != "complete" else a


def collect_paste_run_facts() -> PasteRunBatch:
    """Observe suspicious paste-and-run indicators. No clipboard. No mutation."""
    if not IS_WINDOWS:
        return PasteRunBatch("unavailable", "Paste-and-run watch is Windows-only")

    proc_out, proc_to = run_powershell(_PROCESS_PS, timeout=25)
    proc_cov, proc_detail, proc_facts = parse_process_transcript(proc_out, timed_out=proc_to)

    sb_out, sb_to = run_powershell(_SCRIPTBLOCK_PS, timeout=25)
    sb_cov, sb_detail, sb_facts = parse_scriptblock_transcript(sb_out, timed_out=sb_to)

    coverage = _merge_coverage(proc_cov, sb_cov)
    detail = f"cmdline: {proc_detail}; scriptblock: {sb_detail}"
    # Deduplicate by subject.
    seen: set[str] = set()
    facts: list[dict[str, Any]] = []
    for fact in proc_facts + sb_facts:
        key = fact["subject"]
        if key in seen:
            continue
        seen.add(key)
        facts.append(fact)
    logger.info("paste_run coverage=%s facts=%s", coverage, len(facts))
    return PasteRunBatch(coverage, detail, facts=facts)

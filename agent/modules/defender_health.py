"""Read-only Defender health and MAPS connectivity.

Observations come from Get-MpComputerStatus and MpCmdRun -ValidateMapsConnection.
Access denial and a missed cloud check stay partial. They are not an all-clear.
This module does not change Defender preferences, exclusions, or firewall rules.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field, replace
from typing import Any, Literal

from agent.utils import IS_WINDOWS, run_powershell

CapState = Literal["AVAILABLE", "LIMITED", "UNKNOWN", "UNAVAILABLE"]
Coverage = Literal["complete", "partial", "unavailable"]
MapsResult = Literal["pass", "fail", "unavailable"]

# Microsoft Learn: command-line arguments for Microsoft Defender Antivirus.
# ValidateMapsConnection verifies cloud-service reachability (Windows 10 1703+).
MAPS_GUIDANCE = (
    "DVielle does not block Microsoft Defender cloud endpoints. "
    "Cloud-delivered protection needs those endpoints reachable."
)

HEALTH_ASSUMPTIONS: tuple[str, ...] = (
    "Active mode means Get-MpComputerStatus AMRunningMode is Normal. Passive and EDR Block Mode are not active mode.",
    "Real-time protection is taken only from RealTimeProtectionEnabled. A missing value is unknown.",
    "Signature currency uses DefenderSignaturesOutOfDate when that boolean is present. The age in days is reported beside it.",
    "AMEngineVersion is observed only. DVielle does not compare it with Microsoft's current engine catalog, so engine freshness stays UNKNOWN.",
    "ValidateMapsConnection exit 0 without a documented failure is pass. Elevation-required, service-disabled, and unsupported-OS results stay unavailable.",
    "A pass verifies cloud reachability. It is not a malware-efficacy claim.",
)

_DEFENDER_PS = r"""
$ErrorActionPreference = 'Stop'
try {
  $mp = Get-MpComputerStatus -ErrorAction Stop
  Write-Output 'STATUS:OK'
  Write-Output ('AMRunningMode:' + $mp.AMRunningMode)
  Write-Output ('AntivirusEnabled:' + $mp.AntivirusEnabled)
  Write-Output ('RealTimeProtectionEnabled:' + $mp.RealTimeProtectionEnabled)
  Write-Output ('AntivirusSignatureAge:' + $mp.AntivirusSignatureAge)
  Write-Output ('AntivirusSignatureLastUpdated:' + $mp.AntivirusSignatureLastUpdated)
  Write-Output ('AntivirusSignatureVersion:' + $mp.AntivirusSignatureVersion)
  Write-Output ('AMEngineVersion:' + $mp.AMEngineVersion)
  Write-Output ('AMProductVersion:' + $mp.AMProductVersion)
  Write-Output ('DefenderSignaturesOutOfDate:' + $mp.DefenderSignaturesOutOfDate)
  Write-Output ('AMServiceEnabled:' + $mp.AMServiceEnabled)
} catch {
  $flat = (([string]$_.Exception.Message) -replace '\s+', ' ')
  if ($flat -match 'denied|0x80070005|80070005|Unauthorized') {
    Write-Output 'STATUS:ACCESS_DENIED'
  } else {
    Write-Output 'STATUS:UNAVAILABLE'
  }
  Write-Output ('DETAIL:' + $flat)
}
exit 0
"""

# Learn: MpCmdRun.exe lives under Platform\<version> (preferred) or Program Files\Windows Defender.
# The script always exits 0 so a native failure still returns its text. Python interprets that text.
_MAPS_PS = r"""
$ErrorActionPreference = 'Continue'
$exe = $null
$platform = Join-Path $env:ProgramData 'Microsoft\Windows Defender\Platform'
if (Test-Path -LiteralPath $platform) {
  $dirs = @(Get-ChildItem -LiteralPath $platform -Directory -ErrorAction SilentlyContinue | Sort-Object Name -Descending)
  foreach ($dir in $dirs) {
    $candidate = Join-Path $dir.FullName 'MpCmdRun.exe'
    if (Test-Path -LiteralPath $candidate) { $exe = $candidate; break }
  }
}
if (-not $exe) {
  $fallback = Join-Path $env:ProgramFiles 'Windows Defender\MpCmdRun.exe'
  if (Test-Path -LiteralPath $fallback) { $exe = $fallback }
}
if (-not $exe) {
  Write-Output 'MAPS:UNAVAILABLE'
  Write-Output 'DETAIL:MpCmdRun.exe was not found'
  exit 0
}
Write-Output 'MAPS:RAN'
$out = & $exe -ValidateMapsConnection 2>&1 | Out-String
Write-Output ('EXIT:' + $LASTEXITCODE)
Write-Output $out
exit 0
"""

_ELEVATION = ("80070005", "0x80070005")
_SERVICE_DISABLED = ("800106ba", "0x800106ba")
_UNSUPPORTED = ("80070667", "0x80070667")
_CONNECT_FAIL = ("80070006", "80508015", "0x80508015", "80072ee7", "80004005", "800722f0d", "0x800722f0d")


@dataclass
class DefenderHealth:
    coverage: Coverage
    coverage_detail: str
    am_running_mode: str | None = None
    antivirus_enabled: bool | None = None
    realtime_protection: bool | None = None
    signature_age_days: int | None = None
    signature_last_updated: str | None = None
    signature_version: str | None = None
    engine_version: str | None = None
    product_version: str | None = None
    signatures_out_of_date: bool | None = None
    active_mode: CapState = "UNKNOWN"
    realtime: CapState = "UNKNOWN"
    signature_freshness: CapState = "UNKNOWN"
    engine_freshness: CapState = "UNKNOWN"
    query_state: CapState = "UNKNOWN"
    overall: CapState = "UNKNOWN"
    all_clear: bool = False
    maps_result: MapsResult = "unavailable"
    assumptions: list[str] = field(default_factory=lambda: list(HEALTH_ASSUMPTIONS))

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class MapsCheck:
    result: MapsResult
    detail: str
    method: str
    exit_code: int | None = None
    assumptions: list[str] = field(default_factory=lambda: [
        "Method is MpCmdRun -ValidateMapsConnection when the executable is found.",
        "A Limited scheduled task may be unable to complete this check. That result stays unavailable, not pass.",
        MAPS_GUIDANCE,
    ])

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _blank_health(coverage: Coverage, detail: str, query_state: CapState, overall: CapState) -> DefenderHealth:
    return DefenderHealth(
        coverage=coverage,
        coverage_detail=detail,
        query_state=query_state,
        overall=overall,
        all_clear=False,
        engine_freshness="UNKNOWN",
    )


def _parse_bool(raw: str | None) -> bool | None:
    if raw is None:
        return None
    return {"true": True, "false": False}.get(raw.strip().lower())


def _parse_int(raw: str | None) -> int | None:
    if raw is None:
        return None
    text = raw.strip()
    if not text or text.lower() in {"none", "null"}:
        return None
    try:
        value = int(text)
    except ValueError:
        return None
    # FullScanAge uses 4294967295 as "never". Reject that sentinel for signature age.
    if value < 0 or value >= 4294967295:
        return None
    return value


def _parse_fields(stdout: str) -> dict[str, str]:
    fields: dict[str, str] = {}
    for line in stdout.splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        fields[key.strip()] = value.strip()
    return fields


def _active_state(mode: str | None, antivirus_enabled: bool | None) -> CapState:
    if antivirus_enabled is False:
        return "UNAVAILABLE"
    if not mode:
        return "UNKNOWN"
    token = mode.strip().lower()
    if token == "normal":
        return "AVAILABLE"
    if "passive" in token or "edr" in token or token in {"off", "disabled"}:
        return "LIMITED"
    return "UNKNOWN"


def _signature_state(out_of_date: bool | None) -> CapState:
    if out_of_date is True:
        return "LIMITED"
    if out_of_date is False:
        return "AVAILABLE"
    return "UNKNOWN"


def _realtime_state(enabled: bool | None) -> CapState:
    if enabled is True:
        return "AVAILABLE"
    if enabled is False:
        return "LIMITED"
    return "UNKNOWN"


def _combine(health: DefenderHealth, maps_result: MapsResult) -> DefenderHealth:
    """Recompute the conclusion after the cloud check. Engine currency stays UNKNOWN."""
    active = health.active_mode
    realtime = health.realtime
    signature = health.signature_freshness
    if health.coverage == "unavailable":
        overall: CapState = "UNAVAILABLE"
    elif health.coverage != "complete":
        overall = "UNKNOWN"
    elif active == "UNAVAILABLE":
        overall = "UNAVAILABLE"
    elif active == "AVAILABLE" and realtime == "AVAILABLE" and signature == "AVAILABLE" and maps_result == "pass":
        overall = "AVAILABLE"
    elif active == "UNKNOWN" or realtime == "UNKNOWN":
        overall = "UNKNOWN"
    else:
        overall = "LIMITED"
    all_clear = (
        health.coverage == "complete"
        and overall == "AVAILABLE"
        and maps_result == "pass"
        and health.signatures_out_of_date is False
        and health.antivirus_enabled is True
        and health.realtime_protection is True
        and (health.am_running_mode or "").strip().lower() == "normal"
    )
    return replace(
        health,
        maps_result=maps_result,
        overall=overall,
        all_clear=all_clear,
        engine_freshness="UNKNOWN",
    )


def parse_defender_status(stdout: str | None, *, timed_out: bool = False) -> DefenderHealth:
    """Parse a Get-MpComputerStatus transcript. Incomplete reads are not healthy."""
    if timed_out:
        return _blank_health(
            "partial",
            "Defender health collection incomplete: Get-MpComputerStatus timed out",
            "LIMITED",
            "UNKNOWN",
        )
    if not stdout or not stdout.strip():
        return _blank_health(
            "unavailable",
            "Defender health unavailable: Get-MpComputerStatus returned no output",
            "UNKNOWN",
            "UNKNOWN",
        )
    # A denial anywhere in the transcript wins. Later OK lines must not rehabilitate it.
    if any(line.startswith("STATUS:ACCESS_DENIED") for line in stdout.splitlines()):
        fields = _parse_fields(stdout)
        detail = fields.get("DETAIL") or ""
        extra = f": {detail}" if detail else ""
        return _blank_health(
            "partial",
            "Defender health collection incomplete: access denied" + extra,
            "LIMITED",
            "UNKNOWN",
        )
    fields = _parse_fields(stdout)
    status = fields.get("STATUS", "").upper()
    detail = fields.get("DETAIL") or ""
    if status == "ACCESS_DENIED":
        extra = f": {detail}" if detail else ""
        return _blank_health(
            "partial",
            "Defender health collection incomplete: access denied" + extra,
            "LIMITED",
            "UNKNOWN",
        )
    if status == "UNAVAILABLE":
        extra = f": {detail}" if detail else ""
        return _blank_health(
            "unavailable",
            "Defender health unavailable" + extra,
            "UNAVAILABLE",
            "UNAVAILABLE",
        )
    mode = fields.get("AMRunningMode") or None
    antivirus = _parse_bool(fields.get("AntivirusEnabled"))
    realtime = _parse_bool(fields.get("RealTimeProtectionEnabled"))
    out_of_date = _parse_bool(fields.get("DefenderSignaturesOutOfDate"))
    age = _parse_int(fields.get("AntivirusSignatureAge"))
    engine = fields.get("AMEngineVersion") or None
    missing: list[str] = []
    if status != "OK":
        missing.append("status")
    if not mode:
        missing.append("AMRunningMode")
    if antivirus is None:
        missing.append("AntivirusEnabled")
    if realtime is None:
        missing.append("RealTimeProtectionEnabled")
    if out_of_date is None:
        missing.append("DefenderSignaturesOutOfDate")
    if not engine:
        missing.append("AMEngineVersion")
    coverage: Coverage = "partial" if missing else "complete"
    if missing:
        detail_text = "Defender health collection incomplete: missing " + ", ".join(missing)
        query_state: CapState = "LIMITED"
    else:
        detail_text = "Defender health fields were read"
        query_state = "AVAILABLE"
    health = DefenderHealth(
        coverage=coverage,
        coverage_detail=detail_text,
        am_running_mode=mode,
        antivirus_enabled=antivirus,
        realtime_protection=realtime,
        signature_age_days=age,
        signature_last_updated=fields.get("AntivirusSignatureLastUpdated") or None,
        signature_version=fields.get("AntivirusSignatureVersion") or None,
        engine_version=engine,
        product_version=fields.get("AMProductVersion") or None,
        signatures_out_of_date=out_of_date,
        active_mode=_active_state(mode, antivirus),
        realtime=_realtime_state(realtime),
        signature_freshness=_signature_state(out_of_date),
        engine_freshness="UNKNOWN",
        query_state=query_state,
        all_clear=False,
    )
    return _combine(health, "unavailable")


def interpret_maps_output(stdout: str | None, *, timed_out: bool = False, ran: bool = True) -> MapsCheck:
    """Interpret ValidateMapsConnection text. Never recommend blocking Defender cloud."""
    method = "MpCmdRun -ValidateMapsConnection"
    if not ran:
        return MapsCheck("unavailable", f"MAPS check not run. {MAPS_GUIDANCE}", "not_run")
    if timed_out:
        return MapsCheck(
            "unavailable",
            f"MAPS check unavailable: ValidateMapsConnection timed out. {MAPS_GUIDANCE}",
            method,
        )
    if stdout is None or not stdout.strip():
        return MapsCheck(
            "unavailable",
            f"MAPS check unavailable: no output. {MAPS_GUIDANCE}",
            method,
        )
    text = stdout
    lower = text.lower()
    if "maps:unavailable" in lower or "mpcmdrun.exe was not found" in lower:
        return MapsCheck(
            "unavailable",
            f"MAPS check unavailable: MpCmdRun.exe was not found. {MAPS_GUIDANCE}",
            "not_run",
        )
    exit_code = _exit_code(text)
    if any(code in lower for code in _ELEVATION):
        return MapsCheck(
            "unavailable",
            "MAPS check unavailable: ValidateMapsConnection requires elevation "
            f"(80070005). This is not a pass. {MAPS_GUIDANCE}",
            method,
            exit_code,
        )
    if any(code in lower for code in _SERVICE_DISABLED):
        return MapsCheck(
            "unavailable",
            "MAPS check unavailable: Defender Antivirus service is disabled (800106BA). "
            f"Connectivity was not verified. {MAPS_GUIDANCE}",
            method,
            exit_code,
        )
    if any(code in lower for code in _UNSUPPORTED):
        return MapsCheck(
            "unavailable",
            "MAPS check unavailable: ValidateMapsConnection is not supported on this "
            f"Windows version (0x80070667). {MAPS_GUIDANCE}",
            method,
            exit_code,
        )
    failed = "validatemapsconnection failed" in lower or "failed to establish" in lower
    if failed or any(code in lower for code in _CONNECT_FAIL):
        return MapsCheck(
            "fail",
            "Defender cloud connectivity check failed. "
            f"A firewall or TLS inspection may be blocking the connection. {MAPS_GUIDANCE}",
            method,
            exit_code,
        )
    if exit_code == 0:
        return MapsCheck(
            "pass",
            "ValidateMapsConnection completed without a documented failure. "
            "This verifies cloud reachability, not malware blocking efficacy. "
            f"{MAPS_GUIDANCE}",
            method,
            exit_code,
        )
    return MapsCheck(
        "unavailable",
        f"MAPS result was not a documented pass or failure. {MAPS_GUIDANCE}",
        method,
        exit_code,
    )


def _exit_code(text: str) -> int | None:
    for line in text.splitlines():
        if line.startswith("EXIT:"):
            raw = line.split(":", 1)[1].strip()
            try:
                return int(raw)
            except ValueError:
                return None
    return None


def combine_health(health: DefenderHealth, maps: MapsCheck) -> DefenderHealth:
    return _combine(health, maps.result)


def query_defender_health() -> DefenderHealth:
    if not IS_WINDOWS:
        return _blank_health(
            "unavailable",
            "Defender health unavailable: not Windows",
            "UNAVAILABLE",
            "UNAVAILABLE",
        )
    stdout, timed_out = run_powershell(_DEFENDER_PS, timeout=20)
    return parse_defender_status(stdout, timed_out=timed_out)


def query_maps() -> MapsCheck:
    if not IS_WINDOWS:
        return MapsCheck(
            "unavailable",
            f"MAPS check unavailable: not Windows. {MAPS_GUIDANCE}",
            "not_run",
        )
    stdout, timed_out = run_powershell(_MAPS_PS, timeout=25)
    return interpret_maps_output(stdout, timed_out=timed_out, ran=True)

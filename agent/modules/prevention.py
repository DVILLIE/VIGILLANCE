"""ASR, CFA, and recovery observations for the P1 prevention path.

Read-only parsing lives here. Preference changes live in prevention_apply and
only run inside the dual mutate gate.

Authority (fetched 2026-09-29):
- https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-overview
- https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-configure
- https://learn.microsoft.com/en-us/defender-endpoint/controlled-folder-access-configure
- https://www.cisa.gov/stopransomware/ransomware-guide

ASR is a Defender Antivirus feature on any edition that includes Defender,
including Windows Home. Local PowerShell does not require Microsoft 365 E5.
CFA is a modification and delete shield. This module does not claim it stops
reads or exfiltration.
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Literal

from agent.modules.defender_health import DefenderHealth, MapsCheck
from agent.utils import IS_WINDOWS, run_powershell

Coverage = Literal["complete", "partial", "unavailable"]
TriState = Literal["yes", "no", "unknown"]

# Microsoft Learn ASR overview, standard-protection section, 2026-09-29.
# The WMI rule is standard but is not Block-eligible here: Configuration
# Manager depends on WMI, and Learn says not to Block it without extensive Audit.
DRIVER_GUID = "56a863a9-875e-4185-98a7-b882c64b5ce5"
LSASS_GUID = "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2"
WMI_GUID = "e6db77e5-3df2-4cf1-b95a-636979351e5b"

ASR_MODE_NAMES = {
    0: "Off",
    1: "Block",
    2: "Audit",
    5: "NotConfigured",
    6: "Warn",
}
CFA_MODE_NAMES = {
    0: "Disabled",
    1: "Enabled",
    2: "Audit",
    3: "BlockDiskModificationOnly",
    4: "AuditDiskModificationOnly",
}

CFA_MODIFICATION_COPY = (
    "Controlled folder access helps block untrusted apps from modifying or deleting "
    "files in protected folders. In full Enabled mode it also helps block untrusted "
    "boot-sector writes. DVielle does not claim CFA prevents reading or exfiltration."
)
CISA_BACKUP_COPY = (
    "Offline, encrypted backups and a restore test remain required. "
    "CISA #StopRansomware: a backup job is not proof you can restore."
)
HOME_ASR_COPY = (
    "ASR and CFA are Microsoft Defender Antivirus features on Windows Home and Pro. "
    "DVielle does not treat Home as missing ASR."
)
E5_NOT_REQUIRED_COPY = (
    "Configuring ASR with local PowerShell does not require Microsoft 365 E5. "
    "E5 adds centralized management and reporting. It is not a prerequisite for this setting."
)

# Product windows, not intervals mandated by CISA.
BACKUP_FRESH_DAYS = 14
RESTORE_VERIFIED_DAYS = 90

_GUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)

_ASR_TOKENS = {
    "0": 0,
    "disabled": 0,
    "off": 0,
    "1": 1,
    "enabled": 1,
    "block": 1,
    "2": 2,
    "auditmode": 2,
    "audit": 2,
    "5": 5,
    "notconfigured": 5,
    "6": 6,
    "warn": 6,
    "warning": 6,
}
_CFA_TOKENS = {
    "0": 0,
    "disabled": 0,
    "off": 0,
    "1": 1,
    "enabled": 1,
    "block": 1,
    "2": 2,
    "auditmode": 2,
    "audit": 2,
    "3": 3,
    "blockdiskmodificationonly": 3,
    "4": 4,
    "auditdiskmodificationonly": 4,
}


@dataclass(frozen=True)
class AsrRule:
    guid: str
    name: str
    family: str
    block_eligible: bool
    hold_note: str = ""


def _rule(guid: str, name: str, family: str, block_eligible: bool, hold_note: str = "") -> AsrRule:
    return AsrRule(guid.lower(), name, family, block_eligible, hold_note)


ASR_RULES: tuple[AsrRule, ...] = (
    _rule(DRIVER_GUID, "Block abuse of exploited vulnerable signed drivers", "standard", True),
    _rule(
        LSASS_GUID,
        "Block credential stealing from the Windows local security authority subsystem",
        "standard",
        True,
        "Learn notes this rule is redundant when LSA protection is already on. Audit is still required before Block.",
    ),
    _rule(
        WMI_GUID,
        "Block persistence through WMI event subscription",
        "standard",
        False,
        "Microsoft documents that Configuration Manager depends on WMI. DVielle does not set this rule to Block.",
    ),
    _rule("7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c", "Block Adobe Reader from creating child processes", "other", False),
    _rule("d4f940ab-401b-4efc-aadc-ad5f3c50688a", "Block all Office applications from creating child processes", "other", False),
    _rule("be9ba2d9-53ea-4cdc-84e5-9b1eeee46550", "Block executable content from email client and webmail", "other", False),
    _rule(
        "01443614-cd74-433a-b99e-2ecdc07bfc25",
        "Block executable files from running unless they meet a prevalence, age, or trusted list criterion",
        "other",
        False,
    ),
    _rule("5beb7efe-fd9a-4556-801d-275e5ffc04cc", "Block execution of potentially obfuscated scripts", "other", False),
    _rule(
        "d3e037e1-3eb8-44c8-a917-57927947596d",
        "Block JavaScript or VBScript from launching downloaded executable content",
        "other",
        False,
    ),
    _rule("3b576869-a4ec-4529-8536-b80a7769e899", "Block Office applications from creating executable content", "other", False),
    _rule("75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84", "Block Office applications from injecting code into other processes", "other", False),
    _rule(
        "26190899-1602-49e8-8b27-eb1d0a1ce869",
        "Block Office communication application from creating child processes",
        "other",
        False,
    ),
    _rule("d1e49aac-8f56-4280-b9ba-993a6d77406c", "Block process creations originating from PSExec and WMI commands", "other", False),
    _rule("33ddedf1-c6e0-47cb-833e-de6133960387", "Block rebooting machine in Safe Mode", "other", False),
    _rule("b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4", "Block untrusted and unsigned processes that run from USB", "other", False),
    _rule("c0033c00-d16d-4114-a5a0-dc9b3a7d2ceb", "Block use of copied or impersonated system tools", "other", False),
    _rule("a8f5898e-1dc8-49a9-9878-85004b8a61e6", "Block Webshell creation for Servers", "other", False),
    _rule("92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b", "Block Win32 API calls from Office macros", "other", False),
    _rule("c1db55ab-c21a-4637-bb3f-a12568109d35", "Use advanced protection against ransomware", "other", False),
)

ASR_BY_GUID = {rule.guid: rule for rule in ASR_RULES}

PREVENTION_ASSUMPTIONS: tuple[str, ...] = (
    "ASR rule actions follow Microsoft Learn: 0 Off, 1 Block, 2 Audit, 5 Not configured, 6 Warn.",
    "A rule missing from Get-MpPreference is Not configured. That is not Audit evidence.",
    "Standard-protection Block is offered only for the driver and LSASS rules, and only while the live action is Audit.",
    "The WMI persistence rule and every non-standard rule are Audit-only. DVielle does not blanket-Block them.",
    "Warn is not Audit evidence and is not converted to Block.",
    "CFA modes follow EnableControlledFolderAccess: 0 Disabled, 1 Enabled, 2 Audit, 3 Block disk modification only, 4 Audit disk modification only.",
    "Full CFA Block is offered only while the live mode is Audit (2). Disk-only audit is not folder-audit evidence.",
    "Prerequisites are Defender Active (AMRunningMode Normal), real-time protection on, and a MAPS pass. A partial health read is not enough.",
    E5_NOT_REQUIRED_COPY,
    HOME_ASR_COPY,
    CFA_MODIFICATION_COPY,
    CISA_BACKUP_COPY,
    "Group Policy or tamper protection can override a local preference. The apply path re-reads the live value and does not claim success when it differs.",
    "Engine freshness remains UNKNOWN. Signature age is reported by the health check and is not this gate.",
)

OBSERVE_PS = r"""
$ErrorActionPreference = 'Stop'
try {
  $p = Get-MpPreference -ErrorAction Stop
  Write-Output 'OBSERVE:ASR_CFA'
  Write-Output 'STATUS:OK'
  $ids = @()
  if ($null -ne $p.AttackSurfaceReductionRules_Ids) { $ids = @($p.AttackSurfaceReductionRules_Ids) }
  $actions = @()
  if ($null -ne $p.AttackSurfaceReductionRules_Actions) { $actions = @($p.AttackSurfaceReductionRules_Actions) }
  Write-Output ('COUNT:' + $ids.Count + ':' + $actions.Count)
  $n = [Math]::Min($ids.Count, $actions.Count)
  for ($i = 0; $i -lt $n; $i++) {
    Write-Output ('RULE:' + [string]$ids[$i] + '=' + [string]$actions[$i])
  }
  Write-Output ('CFA:' + [string]$p.EnableControlledFolderAccess)
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


@dataclass
class PreventionPosture:
    coverage: Coverage
    coverage_detail: str
    rules: dict[str, int] = field(default_factory=dict)
    unknown_rules: list[dict[str, str]] = field(default_factory=list)
    cfa_mode: int | None = None
    cfa_mode_name: str = "Unread"
    assumptions: list[str] = field(default_factory=lambda: list(PREVENTION_ASSUMPTIONS))

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class RulePlan:
    guid: str
    name: str
    family: str
    block_eligible: bool
    observed_action: int | None
    observed_name: str
    allowed_actions: list[int]
    block_allowed: bool
    audit_allowed: bool
    reason: str
    hold_note: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class CfaPlan:
    observed_mode: int | None
    observed_name: str
    allowed_modes: list[int]
    block_allowed: bool
    audit_allowed: bool
    reason: str
    modification_copy: str = CFA_MODIFICATION_COPY
    backup_copy: str = CISA_BACKUP_COPY

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class RecoveryReport:
    backup_configured: TriState
    backup_fresh: TriState
    restore_verified: TriState
    source: str
    last_backup_at: str | None = None
    last_restore_test_at: str | None = None
    notice: str = CISA_BACKUP_COPY
    detail: str = ""
    assumptions: list[str] = field(default_factory=lambda: [
        "BackupConfigured, BackupFresh, and RestoreVerified are separate states.",
        "A timestamp on a backup does not verify a restore.",
        f"BackupFresh is yes only when a declared backup timestamp is within {BACKUP_FRESH_DAYS} days. That window is DVielle's, not a CISA number.",
        f"RestoreVerified is yes only when a declared restore-test timestamp is within {RESTORE_VERIFIED_DAYS} days.",
        "This file is a user declaration. It is not a backup engine. Deleting it clears the declaration.",
        CISA_BACKUP_COPY,
    ])

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _blank_posture(coverage: Coverage, detail: str) -> PreventionPosture:
    return PreventionPosture(coverage=coverage, coverage_detail=detail, cfa_mode_name="Unread")


def _parse_token(raw: str, table: dict[str, int]) -> int | None:
    return table.get(re.sub(r"[\s_-]", "", raw.strip().lower()))


def parse_prevention(stdout: str | None, *, timed_out: bool = False) -> PreventionPosture:
    """Parse a Get-MpPreference transcript. Access denial does not become Off."""
    if timed_out:
        return _blank_posture("partial", "ASR and CFA collection incomplete: Get-MpPreference timed out")
    if not stdout or not stdout.strip():
        return _blank_posture("unavailable", "ASR and CFA collection unavailable: Get-MpPreference returned no output")
    lines = stdout.splitlines()
    if any(line.startswith("STATUS:ACCESS_DENIED") for line in lines):
        detail = _detail(lines)
        extra = f": {detail}" if detail else ""
        return _blank_posture("partial", "ASR and CFA collection incomplete: access denied" + extra)
    fields = _header_fields(lines)
    status = fields.get("STATUS", "").upper()
    detail = fields.get("DETAIL") or ""
    if status == "UNAVAILABLE":
        extra = f": {detail}" if detail else ""
        return _blank_posture("unavailable", "ASR and CFA collection unavailable" + extra)
    if status != "OK":
        return _blank_posture("partial", "ASR and CFA collection incomplete: status was not read")
    count = fields.get("COUNT", "")
    if count.count(":") != 1:
        return _blank_posture("partial", "ASR and CFA collection incomplete: rule counts were not read")
    left, right = count.split(":", 1)
    try:
        id_count, action_count = int(left), int(right)
    except ValueError:
        return _blank_posture("partial", "ASR and CFA collection incomplete: rule counts were not numbers")
    if id_count != action_count:
        return _blank_posture(
            "partial",
            "ASR and CFA collection incomplete: rule ids and actions differ in length",
        )
    rules: dict[str, int] = {}
    unknown: list[dict[str, str]] = []
    seen = 0
    for line in lines:
        if not line.startswith("RULE:"):
            continue
        body = line.split(":", 1)[1]
        if "=" not in body:
            return _blank_posture("partial", "ASR and CFA collection incomplete: a rule line could not be read")
        guid_raw, action_raw = body.split("=", 1)
        guid = guid_raw.strip().lower()
        if not _GUID_RE.match(guid):
            return _blank_posture("partial", "ASR and CFA collection incomplete: a rule id was not a GUID")
        action = _parse_token(action_raw, _ASR_TOKENS)
        if action is None:
            return _blank_posture("partial", f"ASR and CFA collection incomplete: unrecognized ASR action {action_raw.strip()}")
        seen += 1
        if guid in ASR_BY_GUID:
            rules[guid] = action
        else:
            unknown.append({"guid": guid, "action": str(action)})
    if seen != id_count:
        return _blank_posture("partial", "ASR and CFA collection incomplete: rule lines do not match the count")
    if "CFA" not in fields:
        return _blank_posture("partial", "ASR and CFA collection incomplete: CFA mode was not read")
    cfa = _parse_token(fields["CFA"], _CFA_TOKENS)
    if cfa is None:
        return _blank_posture("partial", "ASR and CFA collection incomplete: CFA mode was not recognized")
    for rule in ASR_RULES:
        rules.setdefault(rule.guid, 5)
    return PreventionPosture(
        coverage="complete",
        coverage_detail="ASR rules and CFA mode were read",
        rules=rules,
        unknown_rules=unknown,
        cfa_mode=cfa,
        cfa_mode_name=CFA_MODE_NAMES[cfa],
    )


def _detail(lines: list[str]) -> str:
    for line in lines:
        if line.startswith("DETAIL:"):
            return line.split(":", 1)[1].strip()
    return ""


def _header_fields(lines: list[str]) -> dict[str, str]:
    fields: dict[str, str] = {}
    for line in lines:
        if line.startswith("RULE:") or ":" not in line:
            continue
        key, value = line.split(":", 1)
        if key in {"STATUS", "DETAIL", "COUNT", "CFA", "OBSERVE"}:
            fields[key] = value.strip()
    return fields


def promotion_prerequisites(health: DefenderHealth, maps: MapsCheck) -> tuple[bool, list[str]]:
    """Defender Active, real-time protection, and a MAPS pass. E5 is not consulted."""
    gaps: list[str] = []
    if health.coverage != "complete":
        gaps.append(health.coverage_detail or "Defender health collection is incomplete")
    if health.active_mode != "AVAILABLE":
        gaps.append("Defender is not in Active mode (AMRunningMode must be Normal)")
    if health.realtime != "AVAILABLE":
        gaps.append("Real-time protection is not on")
    if maps.result != "pass":
        gaps.append(
            "MAPS cloud-delivered protection is not verified. "
            "DVielle does not block Microsoft Defender cloud endpoints."
        )
    return (not gaps, gaps)


def _unread_rule(rule: AsrRule, reason: str) -> RulePlan:
    return RulePlan(
        guid=rule.guid,
        name=rule.name,
        family=rule.family,
        block_eligible=rule.block_eligible,
        observed_action=None,
        observed_name="Unread",
        allowed_actions=[],
        block_allowed=False,
        audit_allowed=False,
        reason=reason,
        hold_note=rule.hold_note,
    )


def _plan_rule(rule: AsrRule, action: int, prereq_ok: bool, gaps: list[str]) -> RulePlan:
    observed = ASR_MODE_NAMES.get(action, "Unknown")
    base = dict(
        guid=rule.guid,
        name=rule.name,
        family=rule.family,
        block_eligible=rule.block_eligible,
        observed_action=action,
        observed_name=observed,
        hold_note=rule.hold_note,
    )
    if not prereq_ok:
        return RulePlan(
            **base,
            allowed_actions=[],
            block_allowed=False,
            audit_allowed=False,
            reason="Prerequisites not met: " + "; ".join(gaps),
        )
    if action == 2 and rule.block_eligible:
        return RulePlan(
            **base,
            allowed_actions=[1],
            block_allowed=True,
            audit_allowed=False,
            reason="Live mode is Audit. This standard-protection rule may move to Block.",
        )
    if action == 2:
        note = rule.hold_note or "Already in Audit. DVielle does not blanket-Block this rule."
        return RulePlan(**base, allowed_actions=[], block_allowed=False, audit_allowed=False, reason=note)
    if action in (0, 5):
        return RulePlan(
            **base,
            allowed_actions=[2],
            block_allowed=False,
            audit_allowed=True,
            reason="Live mode is not Audit. The next mode is Audit, not Block.",
        )
    if action == 1:
        return RulePlan(
            **base,
            allowed_actions=[],
            block_allowed=False,
            audit_allowed=False,
            reason="Already in Block. This observation does not change it.",
        )
    if action == 6:
        return RulePlan(
            **base,
            allowed_actions=[],
            block_allowed=False,
            audit_allowed=False,
            reason="Warn is not Audit evidence. DVielle does not convert Warn to Block.",
        )
    return RulePlan(
        **base,
        allowed_actions=[],
        block_allowed=False,
        audit_allowed=False,
        reason="That ASR action is not one DVielle will change.",
    )


def _plan_cfa(mode: int | None, name: str, prereq_ok: bool, gaps: list[str], *, readable: bool) -> CfaPlan:
    if not readable or mode is None:
        return CfaPlan(None, "Unread", [], False, False, "CFA mode was not read. Nothing is changed.")
    if not prereq_ok:
        return CfaPlan(mode, name, [], False, False, "Prerequisites not met: " + "; ".join(gaps))
    if mode == 2:
        return CfaPlan(
            mode,
            name,
            [1],
            True,
            False,
            "Live CFA mode is Audit. Enabled is a modification shield, not a read or exfiltration control.",
        )
    if mode == 0:
        return CfaPlan(mode, name, [2], False, True, "CFA is off. The next mode is Audit, not Block.")
    if mode == 4:
        return CfaPlan(
            mode,
            name,
            [2],
            False,
            True,
            "Audit of disk modification only does not record folder changes. It is not evidence for full Block. The next mode is folder Audit.",
        )
    if mode == 3:
        return CfaPlan(
            mode,
            name,
            [],
            False,
            False,
            "Block disk modification only is a narrower setting. DVielle does not escalate it to full Enabled without folder Audit.",
        )
    if mode == 1:
        return CfaPlan(
            mode,
            name,
            [],
            False,
            False,
            "CFA is already Enabled. That setting blocks modification and boot-sector writes. It is not a claim about reading or exfiltration.",
        )
    return CfaPlan(mode, name, [], False, False, "That CFA mode is not one DVielle will change.")


def _option(option_id: str, label: str, what: str, handler: str, action: int, guid: str | None) -> dict[str, Any]:
    return {
        "id": option_id,
        "label": label,
        "what_we_will_do": what,
        "handler": handler,
        "action": action,
        "guid": guid,
    }


def build_promotion(
    posture: PreventionPosture,
    health: DefenderHealth,
    maps: MapsCheck,
    *,
    sku: str | None = None,
) -> dict[str, Any]:
    """Options only. This function does not call Set-MpPreference."""
    prereq_ok, gaps = promotion_prerequisites(health, maps)
    if sku == "NonWindows":
        prereq_ok = False
        gaps = ["ASR and CFA collection is not available off Windows", *gaps]
    readable = posture.coverage == "complete" and sku != "NonWindows"
    if not readable:
        reason = posture.coverage_detail
        rules = [_unread_rule(rule, reason) for rule in ASR_RULES]
        cfa = _plan_cfa(None, "Unread", False, gaps, readable=False)
        cfa.reason = reason
    else:
        rules = [_plan_rule(rule, posture.rules.get(rule.guid, 5), prereq_ok, gaps) for rule in ASR_RULES]
        cfa = _plan_cfa(posture.cfa_mode, posture.cfa_mode_name, prereq_ok, gaps, readable=True)
    options: list[dict[str, Any]] = []
    for plan in rules:
        if plan.audit_allowed:
            options.append(
                _option(
                    f"asr-audit-{plan.guid}",
                    f"Audit: {plan.name}",
                    "Set only this ASR rule to Audit, then read the live preference back. Block is not applied.",
                    "safety.set_asr_rule",
                    2,
                    plan.guid,
                )
            )
        elif plan.block_allowed:
            options.append(
                _option(
                    f"asr-block-{plan.guid}",
                    f"Block: {plan.name}",
                    "Set only this standard-protection rule to Block after the live mode is still Audit "
                    "and Defender Active, real-time protection, and MAPS still pass. Then read it back.",
                    "safety.set_asr_rule",
                    1,
                    plan.guid,
                )
            )
    if cfa.audit_allowed and cfa.allowed_modes == [2]:
        options.append(
            _option(
                "cfa-audit",
                "Audit controlled folder access",
                "Set CFA to Audit, then read the live mode back. " + CFA_MODIFICATION_COPY + " " + CISA_BACKUP_COPY,
                "safety.set_cfa_mode",
                2,
                None,
            )
        )
    elif cfa.block_allowed:
        options.append(
            _option(
                "cfa-block",
                "Block modifications with controlled folder access",
                "Set CFA to Enabled (modification and boot-sector shield) only while live mode is still Audit "
                "and the Defender prerequisites still pass, then read it back. "
                + CFA_MODIFICATION_COPY
                + " "
                + CISA_BACKUP_COPY,
                "safety.set_cfa_mode",
                1,
                None,
            )
        )
    return {
        "prerequisites_met": prereq_ok and readable,
        "prerequisite_gaps": [] if prereq_ok and readable else gaps,
        "sku": sku,
        "rules": [plan.to_dict() for plan in rules],
        "cfa": cfa.to_dict(),
        "options": options,
        "cfa_copy": CFA_MODIFICATION_COPY,
        "backup_copy": CISA_BACKUP_COPY,
        "home_copy": HOME_ASR_COPY,
        "e5_copy": E5_NOT_REQUIRED_COPY,
        "assumptions": list(PREVENTION_ASSUMPTIONS),
    }


def rule_plan(promotion: dict[str, Any], guid: str) -> dict[str, Any] | None:
    for row in promotion.get("rules") or []:
        if str(row.get("guid", "")).lower() == guid.lower():
            return row
    return None


def allowed_asr_actions(promotion: dict[str, Any], guid: str, undo_previous: int | None) -> set[int]:
    """Forward plan, plus a non-Block undo. Undo cannot invent a Block."""
    plan = rule_plan(promotion, guid)
    allowed = set(plan.get("allowed_actions") or []) if plan else set()
    if isinstance(undo_previous, int) and not isinstance(undo_previous, bool) and undo_previous != 1:
        allowed.add(undo_previous)
    return allowed


def allowed_cfa_modes(promotion: dict[str, Any], undo_previous: int | None) -> set[int]:
    cfa = promotion.get("cfa") or {}
    allowed = set(cfa.get("allowed_modes") or [])
    if isinstance(undo_previous, int) and not isinstance(undo_previous, bool) and undo_previous != 1:
        if undo_previous in CFA_MODE_NAMES:
            allowed.add(undo_previous)
    return allowed


def query_prevention_posture() -> PreventionPosture:
    if not IS_WINDOWS:
        return _blank_posture("unavailable", "ASR and CFA collection unavailable: not Windows")
    stdout, timed_out = run_powershell(OBSERVE_PS, timeout=25)
    return parse_prevention(stdout, timed_out=timed_out)


def _parse_stamp(value: str | None) -> datetime | None:
    if value is None:
        return None
    text = value.strip()
    if not text:
        return None
    try:
        stamp = datetime.fromisoformat(text)
    except ValueError:
        return None
    if stamp.tzinfo is None:
        return None
    return stamp.astimezone(timezone.utc)


def _state_from_parts(
    configured: str,
    last_backup: datetime | None,
    last_restore: datetime | None,
    now: datetime,
    *,
    source: str,
    detail: str,
    backup_text: str | None,
    restore_text: str | None,
) -> RecoveryReport:
    if configured not in {"yes", "no", "unknown"}:
        configured = "unknown"
    if last_backup is None:
        fresh: TriState = "unknown"
    else:
        age = now - last_backup
        if age.total_seconds() < 0:
            fresh = "unknown"
        elif age <= timedelta(days=BACKUP_FRESH_DAYS):
            fresh = "yes"
        else:
            fresh = "no"
    if last_restore is None:
        verified: TriState = "unknown"
    else:
        age = now - last_restore
        if age.total_seconds() < 0:
            verified = "unknown"
        elif age <= timedelta(days=RESTORE_VERIFIED_DAYS):
            verified = "yes"
        else:
            verified = "no"
    return RecoveryReport(
        backup_configured=configured,  # type: ignore[arg-type]
        backup_fresh=fresh,
        restore_verified=verified,
        source=source,
        last_backup_at=backup_text if last_backup is not None else None,
        last_restore_test_at=restore_text if last_restore is not None else None,
        detail=detail,
    )


def load_recovery(path: Path, *, now: datetime | None = None) -> RecoveryReport:
    """Read a user declaration. A missing file is unknown, not a failed backup."""
    moment = now or datetime.now(timezone.utc)
    if not path.exists():
        return _state_from_parts(
            "unknown",
            None,
            None,
            moment,
            source="absent",
            detail="No recovery declaration is stored. That is unknown, not a statement that backups are missing.",
            backup_text=None,
            restore_text=None,
        )
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        return _state_from_parts(
            "unknown",
            None,
            None,
            moment,
            source="unreadable",
            detail=f"Recovery declaration could not be read ({exc.__class__.__name__}). States stay unknown.",
            backup_text=None,
            restore_text=None,
        )
    values: dict[str, str] = {}
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, value = stripped.split("=", 1)
        values[key.strip()] = value.strip()
    configured = values.get("backup_configured") or "unknown"
    if configured not in {"yes", "no", "unknown"}:
        configured = "unknown"
    backup_text = values.get("last_backup_at") or ""
    restore_text = values.get("last_restore_test_at") or ""
    backup_stamp = _parse_stamp(backup_text) if backup_text else None
    restore_stamp = _parse_stamp(restore_text) if restore_text else None
    if backup_text and backup_stamp is None:
        return _state_from_parts(
            "unknown",
            None,
            None,
            moment,
            source="unreadable",
            detail="last_backup_at is not a timezone-aware timestamp. The declaration was not trusted.",
            backup_text=None,
            restore_text=None,
        )
    if restore_text and restore_stamp is None:
        return _state_from_parts(
            "unknown",
            None,
            None,
            moment,
            source="unreadable",
            detail="last_restore_test_at is not a timezone-aware timestamp. The declaration was not trusted.",
            backup_text=None,
            restore_text=None,
        )
    return _state_from_parts(
        configured,
        backup_stamp,
        restore_stamp,
        moment,
        source="user_declared",
        detail="These states are what was declared in the local marker. They are not a backup job DVielle ran.",
        backup_text=backup_text or None,
        restore_text=restore_text or None,
    )


def _atomic_write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(text, encoding="utf-8")
    temporary.replace(path)


def write_recovery_declaration(
    path: Path,
    *,
    configured: str,
    last_backup_at: str | None = None,
    last_restore_test_at: str | None = None,
    now: datetime | None = None,
) -> RecoveryReport:
    """Store a reversible user declaration. Invalid timestamps are refused and not written."""
    if configured not in {"yes", "no", "unknown"}:
        raise ValueError("backup_configured must be yes, no, or unknown")
    if last_backup_at:
        if _parse_stamp(last_backup_at) is None:
            raise ValueError("last_backup_at must be a timezone-aware ISO timestamp")
    if last_restore_test_at:
        if _parse_stamp(last_restore_test_at) is None:
            raise ValueError("last_restore_test_at must be a timezone-aware ISO timestamp")
    body = "\n".join(
        [
            "# DVielle recovery acknowledgment. User declaration only. Not a backup.",
            f"backup_configured={configured}",
            f"last_backup_at={last_backup_at or ''}",
            f"last_restore_test_at={last_restore_test_at or ''}",
            "",
        ]
    )
    _atomic_write(path, body)
    return load_recovery(path, now=now)


def clear_recovery_declaration(path: Path, *, now: datetime | None = None) -> RecoveryReport:
    """Delete the marker. States return to unknown."""
    if path.exists():
        path.unlink()
    leftover = path.with_suffix(path.suffix + ".tmp")
    if leftover.exists():
        leftover.unlink()
    return load_recovery(path, now=now)

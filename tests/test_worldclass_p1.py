"""P1 ASR, CFA, and recovery. Fixtures only — no live Defender and no live processes."""

from __future__ import annotations

import json
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from agent.edition_matrix import build_edition_matrix
from agent.engine.loop import ResolutionEngine
from agent.engine.models import PolicyDenied
from agent.modules import security
from agent.modules.defender_health import interpret_maps_output, parse_defender_status
from agent.modules.prevention import (
    ASR_RULES,
    CFA_MODIFICATION_COPY,
    CISA_BACKUP_COPY,
    DRIVER_GUID,
    E5_NOT_REQUIRED_COPY,
    HOME_ASR_COPY,
    LSASS_GUID,
    OBSERVE_PS,
    WMI_GUID,
    build_promotion,
    clear_recovery_declaration,
    load_recovery,
    parse_prevention,
    query_prevention_posture,
    write_recovery_declaration,
)
from agent.modules.prevention_apply import apply_asr_rule, apply_cfa_mode
from agent.policy.actions import USER_APPROVED_ONLY, ActionKind
from agent.store.db import AgentStore
from agent.version import get_version
from dvielle.gui.observations import prevention_evidence_line

ROOT = Path(__file__).resolve().parents[1]
OFFICE_GUID = "d4f940ab-401b-4efc-aadc-ad5f3c50688a"
NOW = datetime(2026, 9, 29, 12, 0, tzinfo=timezone.utc)

HEALTHY = """STATUS:OK
AMRunningMode:Normal
AntivirusEnabled:True
RealTimeProtectionEnabled:True
AntivirusSignatureAge:0
AntivirusSignatureLastUpdated:2026-09-29
AntivirusSignatureVersion:1.413.1.0
AMEngineVersion:1.1.25000.5
AMProductVersion:4.18.25000.7
DefenderSignaturesOutOfDate:False
AMServiceEnabled:True
"""
MAPS_PASS = "MAPS:RAN\nEXIT:0\nValidateMapsConnection completed\n"


def _health(text: str = HEALTHY):
    return parse_defender_status(text)


def _maps(text: str = MAPS_PASS):
    return interpret_maps_output(text)


def _transcript(rules: dict[str, int], cfa: int) -> str:
    listed = [(guid, action) for guid, action in rules.items() if action != 5]
    lines = ["OBSERVE:ASR_CFA", "STATUS:OK", f"COUNT:{len(listed)}:{len(listed)}"]
    lines.extend(f"RULE:{guid}={action}" for guid, action in listed)
    lines.append(f"CFA:{cfa}")
    return "\n".join(lines) + "\n"


def _promo(rules: dict[str, int] | None = None, cfa: int = 0, *, sku: str = "Home", health=None, maps=None):
    posture = parse_prevention(_transcript(rules or {}, cfa))
    return build_promotion(posture, health or _health(), maps or _maps(), sku=sku)


def _plan(promotion: dict, guid: str) -> dict:
    return next(row for row in promotion["rules"] if row["guid"] == guid)


class _Prefs:
    def __init__(self) -> None:
        self.rules: dict[str, int] = {}
        self.cfa = 0
        self.deny = False
        self.stick = True
        self.calls: list[str] = []

    def runner(self, script: str, timeout: float = 25):
        self.calls.append(script)
        if "DVIELLE_ASR_SET" in script:
            guid, action = _asr_set_args(script)
            if self.deny:
                return "SET:ACCESS_DENIED\nDETAIL:Access is denied\n", False
            if self.stick:
                self.rules[guid] = action
            return "SET:OK\n", False
        if "DVIELLE_ASR_REMOVE" in script:
            guid = _guid(script)
            if self.deny:
                return "SET:ACCESS_DENIED\nDETAIL:Access is denied\n", False
            if self.stick:
                self.rules.pop(guid, None)
            return "SET:OK\n", False
        if "DVIELLE_CFA_SET" in script:
            mode = int(script.split("-EnableControlledFolderAccess", 1)[1].split()[0])
            if self.deny:
                return "SET:ACCESS_DENIED\nDETAIL:Access is denied\n", False
            if self.stick:
                self.cfa = mode
            return "SET:OK\n", False
        if "Get-MpPreference" in script:
            return _transcript(self.rules, self.cfa), False
        return "SET:FAILED\n", False


def _guid(script: str) -> str:
    match = re.search(r"[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}", script)
    assert match is not None
    return match.group(0).lower()


def _asr_set_args(script: str) -> tuple[str, int]:
    action = int(script.split("-AttackSurfaceReductionRules_Actions", 1)[1].split()[0])
    return _guid(script), action


def _invoke(tmp_path: Path, prefs: _Prefs, handler: str, signals: dict):
    engine = ResolutionEngine(
        AgentStore(tmp_path / "agent.db"),
        learn_dir=tmp_path / "learn",
        log_dir=tmp_path / "logs",
    )
    engine.handler_ctx.powershell = prefs.runner
    engine.handler_ctx.defender_health_reader = lambda: _health()
    engine.handler_ctx.maps_reader = lambda: _maps()
    engine.handler_ctx.learn_dir = tmp_path / "learn"
    subject = f"asr:{signals['guid']}" if "guid" in signals else "cfa"
    finding = {
        "id": "finding-1",
        "subject_identity": subject,
        "title_simple": "Apply the prevention option",
        "evidence_refs": ["live Defender preference"],
        "signals": signals,
    }
    token = engine.policy.issue(finding["id"], handler, auto=False, subject=subject)
    return engine, engine.handlers.invoke(handler, finding, engine.handler_ctx, token)


def test_version_is_past_the_1_9_0_prevention_release():
    assert get_version() == "2.4.1"
    text = (ROOT / "docs" / "FUNCTION_SPEC.md").read_text(encoding="utf-8")
    assert "1.9.0" in text


def test_catalog_matches_learn_standard_and_other_split():
    assert len(ASR_RULES) == 19
    standard = [rule for rule in ASR_RULES if rule.family == "standard"]
    assert [rule.guid for rule in standard] == [DRIVER_GUID, LSASS_GUID, WMI_GUID]
    assert [rule.block_eligible for rule in standard] == [True, True, False]
    assert all(rule.block_eligible is False for rule in ASR_RULES if rule.family == "other")


def test_home_and_pro_share_the_same_asr_path():
    rules = {DRIVER_GUID: 2}
    home = _promo(rules, sku="Home")
    pro = _promo(rules, sku="ProOrHigher")
    assert _plan(home, DRIVER_GUID)["allowed_actions"] == _plan(pro, DRIVER_GUID)["allowed_actions"] == [1]
    blob = json.dumps(home).lower()
    assert "does not treat home as missing asr" in blob
    assert "does not require microsoft 365 e5" in blob
    assert "not supported on home" not in blob
    assert build_edition_matrix("Home").features["asr"] == "AVAILABLE"
    assert build_edition_matrix("ProOrHigher").features["asr"] == "AVAILABLE"


def test_access_denied_is_partial_and_not_a_row_of_off_rules():
    posture = parse_prevention("STATUS:ACCESS_DENIED\nDETAIL:Access is denied\n" + _transcript({}, 0))
    assert posture.coverage == "partial"
    assert posture.rules == {}
    assert posture.cfa_mode is None
    promotion = build_promotion(posture, _health(), _maps(), sku="Home")
    assert promotion["options"] == []
    assert all(row["observed_name"] == "Unread" for row in promotion["rules"])
    assert all(row["block_allowed"] is False for row in promotion["rules"])
    assert "access denied" in posture.coverage_detail


def test_mismatched_counts_and_timeout_stay_partial():
    mismatch = parse_prevention("STATUS:OK\nCOUNT:2:1\nRULE:" + DRIVER_GUID + "=2\nCFA:0\n")
    assert mismatch.coverage == "partial"
    assert mismatch.rules == {}
    timed = parse_prevention(_transcript({}, 0), timed_out=True)
    assert timed.coverage == "partial"
    assert timed.cfa_mode is None


def test_missing_rule_is_not_configured_and_block_needs_live_audit():
    promotion = _promo({}, sku="ProOrHigher")
    driver = _plan(promotion, DRIVER_GUID)
    assert driver["observed_action"] == 5
    assert driver["observed_name"] == "NotConfigured"
    assert driver["audit_allowed"] is True
    assert driver["block_allowed"] is False
    assert 1 not in driver["allowed_actions"]


def test_standard_block_only_from_audit_and_wmi_never_blocks():
    audited = _promo({DRIVER_GUID: 2, LSASS_GUID: 2, WMI_GUID: 2})
    assert _plan(audited, DRIVER_GUID)["block_allowed"] is True
    assert _plan(audited, LSASS_GUID)["block_allowed"] is True
    wmi = _plan(audited, WMI_GUID)
    assert wmi["block_allowed"] is False
    assert wmi["allowed_actions"] == []
    assert "does not set this rule to block" in wmi["reason"].lower()
    other = _plan(audited, OFFICE_GUID)
    assert other["observed_action"] == 5
    assert other["block_allowed"] is False
    assert other["audit_allowed"] is True


def test_other_rules_audit_but_do_not_blanket_block():
    promotion = _promo({OFFICE_GUID: 2, "92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b": 0})
    office = _plan(promotion, OFFICE_GUID)
    assert office["block_allowed"] is False
    assert office["allowed_actions"] == []
    assert "does not blanket-block" in office["reason"].lower()
    macros = _plan(promotion, "92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b")
    assert macros["allowed_actions"] == [2]
    assert macros["block_allowed"] is False


def test_warn_is_not_audit_evidence():
    promotion = _promo({DRIVER_GUID: 6})
    plan = _plan(promotion, DRIVER_GUID)
    assert plan["block_allowed"] is False
    assert plan["allowed_actions"] == []
    assert "warn is not audit evidence" in plan["reason"].lower()


def test_prerequisites_block_promotion_until_active_realtime_and_maps():
    passive = HEALTHY.replace("AMRunningMode:Normal", "AMRunningMode:Passive")
    realtime_off = HEALTHY.replace("RealTimeProtectionEnabled:True", "RealTimeProtectionEnabled:False")
    for health, maps in (
        (_health(passive), _maps()),
        (_health(realtime_off), _maps()),
        (_health(), interpret_maps_output("MAPS:RAN\nEXIT:1\nValidateMapsConnection failed\n")),
        (_health("STATUS:ACCESS_DENIED\nDETAIL:Access is denied\n"), _maps()),
    ):
        promotion = _promo({DRIVER_GUID: 2}, health=health, maps=maps)
        assert _plan(promotion, DRIVER_GUID)["block_allowed"] is False
        assert promotion["options"] == []
        assert promotion["prerequisites_met"] is False


def test_unknown_guid_is_observed_and_not_actionable():
    foreign = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
    posture = parse_prevention(_transcript({foreign: 2, DRIVER_GUID: 2}, 0))
    assert posture.coverage == "complete"
    assert posture.unknown_rules == [{"guid": foreign, "action": "2"}]
    promotion = build_promotion(posture, _health(), _maps(), sku="Home")
    assert all(row["guid"] != foreign for row in promotion["rules"])
    assert _plan(promotion, DRIVER_GUID)["block_allowed"] is True


def test_cfa_disk_only_block_is_not_escalated():
    promotion = _promo({}, cfa=3)
    assert promotion["cfa"]["allowed_modes"] == []
    assert promotion["cfa"]["block_allowed"] is False
    assert "does not escalate" in promotion["cfa"]["reason"].lower()


def test_cfa_copy_is_a_modification_shield_and_backup_stays_required():
    off = _promo({}, cfa=0)
    assert off["cfa"]["audit_allowed"] is True
    assert off["cfa"]["block_allowed"] is False
    audited = _promo({}, cfa=2)
    assert audited["cfa"]["block_allowed"] is True
    assert audited["cfa"]["allowed_modes"] == [1]
    disk = _promo({}, cfa=4)
    assert disk["cfa"]["block_allowed"] is False
    assert disk["cfa"]["allowed_modes"] == [2]
    enabled = _promo({}, cfa=1)
    assert enabled["cfa"]["allowed_modes"] == []
    blob = json.dumps(audited)
    assert CFA_MODIFICATION_COPY in blob
    assert CISA_BACKUP_COPY in blob
    assert HOME_ASR_COPY in blob
    assert E5_NOT_REQUIRED_COPY in blob
    lowered = blob.lower()
    assert "does not claim cfa prevents reading or exfiltration" in lowered
    assert "stops reads" not in lowered
    assert "blocks reads" not in lowered
    assert "ransomware-proof" not in lowered


def test_non_windows_has_no_promotion():
    promotion = _promo({DRIVER_GUID: 2}, cfa=2, sku="NonWindows")
    assert promotion["options"] == []
    assert promotion["prerequisites_met"] is False


def test_recovery_states_stay_independent_and_reversible(tmp_path: Path):
    path = tmp_path / "learn" / "recovery.txt"
    missing = load_recovery(path, now=NOW)
    assert (missing.backup_configured, missing.backup_fresh, missing.restore_verified) == ("unknown", "unknown", "unknown")
    assert missing.source == "absent"
    declared = write_recovery_declaration(
        path,
        configured="yes",
        last_backup_at=(NOW - timedelta(days=1)).isoformat(),
        now=NOW,
    )
    assert (declared.backup_configured, declared.backup_fresh, declared.restore_verified) == ("yes", "yes", "unknown")
    stale = write_recovery_declaration(
        path,
        configured="yes",
        last_backup_at=(NOW - timedelta(days=40)).isoformat(),
        last_restore_test_at=(NOW - timedelta(days=3)).isoformat(),
        now=NOW,
    )
    assert (stale.backup_configured, stale.backup_fresh, stale.restore_verified) == ("yes", "no", "yes")
    cleared = clear_recovery_declaration(path, now=NOW)
    assert cleared.source == "absent"
    assert cleared.backup_configured == "unknown"
    assert not path.exists()


def test_bad_recovery_timestamp_is_not_written(tmp_path: Path):
    path = tmp_path / "recovery.txt"
    with pytest.raises(ValueError):
        write_recovery_declaration(path, configured="yes", last_backup_at="2026-09-29")
    assert not path.exists()
    write_recovery_declaration(path, configured="no", now=NOW)
    with pytest.raises(ValueError):
        write_recovery_declaration(path, configured="yes", last_restore_test_at="yesterday")
    kept = load_recovery(path, now=NOW)
    assert kept.backup_configured == "no"
    assert kept.restore_verified == "unknown"


def test_future_restore_stamp_is_not_verified(tmp_path: Path):
    path = tmp_path / "recovery.txt"
    report = write_recovery_declaration(
        path,
        configured="unknown",
        last_restore_test_at=(NOW + timedelta(days=1)).isoformat(),
        now=NOW,
    )
    assert report.restore_verified == "unknown"
    assert report.backup_fresh == "unknown"


def test_direct_apply_refuses_without_the_dual_gate():
    prefs = _Prefs()
    prefs.rules[DRIVER_GUID] = 2
    with pytest.raises(PolicyDenied):
        apply_asr_rule(guid=DRIVER_GUID, action=1, runner=prefs.runner, health_reader=_health, maps_reader=_maps)
    with pytest.raises(PolicyDenied):
        apply_cfa_mode(mode=1, runner=prefs.runner, health_reader=_health, maps_reader=_maps)
    assert prefs.calls == []
    assert prefs.rules[DRIVER_GUID] == 2


def test_gated_standard_block_verifies_live_state_and_undoes(tmp_path: Path):
    prefs = _Prefs()
    prefs.rules[DRIVER_GUID] = 2
    _engine, blocked = _invoke(tmp_path, prefs, "safety.set_asr_rule", {"guid": DRIVER_GUID, "action": 1})
    assert blocked["performed"] is True
    assert prefs.rules[DRIVER_GUID] == 1
    assert any("DVIELLE_ASR_SET" in call for call in prefs.calls)
    undone = _invoke(tmp_path, prefs, "safety.set_asr_rule", {"guid": DRIVER_GUID, "action": 2})[1]
    assert undone["performed"] is True
    assert prefs.rules[DRIVER_GUID] == 2


def test_other_rule_block_does_not_call_set(tmp_path: Path):
    prefs = _Prefs()
    prefs.rules[OFFICE_GUID] = 2
    body = _invoke(tmp_path, prefs, "safety.set_asr_rule", {"guid": OFFICE_GUID, "action": 1})[1]
    assert body["performed"] is False
    assert not any("DVIELLE_ASR_SET" in call for call in prefs.calls)
    assert prefs.rules[OFFICE_GUID] == 2


def test_wmi_block_does_not_call_set(tmp_path: Path):
    prefs = _Prefs()
    prefs.rules[WMI_GUID] = 2
    body = _invoke(tmp_path, prefs, "safety.set_asr_rule", {"guid": WMI_GUID, "action": 1})[1]
    assert body["performed"] is False
    assert prefs.rules[WMI_GUID] == 2
    assert not any("DVIELLE_ASR_SET" in call for call in prefs.calls)


def test_audit_other_rule_from_not_configured(tmp_path: Path):
    prefs = _Prefs()
    body = _invoke(tmp_path, prefs, "safety.set_asr_rule", {"guid": OFFICE_GUID, "action": 2})[1]
    assert body["performed"] is True
    assert prefs.rules[OFFICE_GUID] == 2


def test_cfa_audit_then_block_and_access_denied_does_not_stick(tmp_path: Path):
    prefs = _Prefs()
    audited = _invoke(tmp_path, prefs, "safety.set_cfa_mode", {"mode": 2})[1]
    assert audited["performed"] is True
    assert prefs.cfa == 2
    blocked = _invoke(tmp_path, prefs, "safety.set_cfa_mode", {"mode": 1})[1]
    assert blocked["performed"] is True
    assert prefs.cfa == 1
    assert "modification shield" in blocked["message"].lower()
    assert "restore test" in blocked["message"].lower()
    prefs.cfa = 2
    prefs.deny = True
    denied = _invoke(tmp_path, prefs, "safety.set_cfa_mode", {"mode": 1})[1]
    assert denied["performed"] is False
    assert prefs.cfa == 2


def test_set_ok_without_a_matching_reread_is_not_applied(tmp_path: Path):
    prefs = _Prefs()
    prefs.rules[DRIVER_GUID] = 2
    prefs.stick = False
    body = _invoke(tmp_path, prefs, "safety.set_asr_rule", {"guid": DRIVER_GUID, "action": 1})[1]
    assert body["performed"] is False
    assert prefs.rules[DRIVER_GUID] == 2


def test_decision_is_not_applied_when_persist_fails(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    prefs = _Prefs()
    prefs.rules[DRIVER_GUID] = 2
    engine = ResolutionEngine(AgentStore(tmp_path / "agent.db"), learn_dir=tmp_path / "learn", log_dir=tmp_path / "logs")
    engine.handler_ctx.powershell = prefs.runner
    engine.handler_ctx.defender_health_reader = lambda: _health()
    engine.handler_ctx.maps_reader = lambda: _maps()

    def boom(_decision):
        raise RuntimeError("disk full")

    monkeypatch.setattr(engine.store, "log_decision", boom)
    finding = {
        "id": "finding-1",
        "subject_identity": f"asr:{DRIVER_GUID}",
        "title_simple": "Block the driver rule",
        "evidence_refs": ["live Audit"],
        "signals": {"guid": DRIVER_GUID, "action": 1},
    }
    token = engine.policy.issue(finding["id"], "safety.set_asr_rule", auto=False, subject=finding["subject_identity"])
    with pytest.raises(PolicyDenied):
        engine.handlers.invoke("safety.set_asr_rule", finding, engine.handler_ctx, token)
    assert not any("DVIELLE_ASR_SET" in call for call in prefs.calls)


def test_auto_protect_cannot_issue_asr_or_cfa(tmp_path: Path):
    engine = ResolutionEngine(
        AgentStore(tmp_path / "agent.db"),
        learn_dir=tmp_path / "learn",
        auto_enabled=True,
    )
    with pytest.raises(PolicyDenied):
        engine.policy.issue("f", "safety.set_asr_rule", auto=True, subject=f"asr:{DRIVER_GUID}")
    with pytest.raises(PolicyDenied):
        engine.policy.issue("f", "safety.set_cfa_mode", auto=True, subject="cfa")
    assert ActionKind.SET_ASR_RULE in USER_APPROVED_ONLY
    assert ActionKind.SET_CFA_MODE in USER_APPROVED_ONLY


def test_linux_prevention_query_does_not_launch_powershell(monkeypatch: pytest.MonkeyPatch):
    def forbidden(*_args, **_kwargs):
        raise AssertionError("PowerShell must not run")

    monkeypatch.setattr("agent.modules.prevention.IS_WINDOWS", False)
    monkeypatch.setattr("agent.modules.prevention.run_powershell", forbidden)
    posture = query_prevention_posture()
    assert posture.coverage == "unavailable"
    assert posture.cfa_mode is None


def test_security_monitor_publishes_promotion_without_a_live_process(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    def forbidden(*_args, **_kwargs):
        raise AssertionError("PowerShell must not run")

    monkeypatch.setattr(security, "run_powershell", forbidden)
    monkeypatch.setattr(security, "_query_defender", lambda: (True, True))
    monkeypatch.setattr(security, "_query_firewall", lambda: (True, {"domain": True, "private": True, "public": True}))
    monkeypatch.setattr(security, "_query_defender_health", lambda: _health())
    monkeypatch.setattr(security, "_query_maps", lambda: _maps())
    monkeypatch.setattr(security, "_query_edition_matrix", lambda: build_edition_matrix("Home", edition_id="Core"))
    monkeypatch.setattr(security, "_query_prevention", lambda: parse_prevention(_transcript({DRIVER_GUID: 2}, 2)))
    status = security.SecurityMonitor(AgentStore(tmp_path / "agent.db"), {}).run()
    assert status.prevention["coverage"] == "complete"
    assert status.promotion["cfa"]["block_allowed"] is True
    assert status.recovery["backup_configured"] == "unknown"
    assert status.recovery["restore_verified"] == "unknown"
    assert "does not claim CFA prevents reading or exfiltration" in status.promotion["cfa_copy"]
    assert any(option["id"] == f"asr-block-{DRIVER_GUID}" for option in status.promotion["options"])
    assert status.edition_matrix["features"]["windows_sandbox"] == "UNAVAILABLE"


def test_evidence_strip_names_recovery_and_the_modification_shield():
    stamp = datetime.now(timezone.utc).isoformat()
    promotion_health = _health().to_dict()
    data = {
        "runtime": {"state": "running", "heartbeat_at": stamp},
        "collectors": {
            "heartbeat": {"status": "ok", "interval_seconds": 5, "last_success_at": stamp},
            "security": {"status": "ok", "interval_seconds": 120, "last_success_at": stamp},
        },
        "security": {
            "defender_health": promotion_health,
            "maps": {"result": "pass"},
            "edition_matrix": build_edition_matrix("Home").to_dict(),
            "prevention": {"coverage": "complete", "cfa_mode_name": "Audit"},
            "recovery": {"backup_configured": "yes", "backup_fresh": "yes", "restore_verified": "unknown"},
        },
    }
    line = prevention_evidence_line(data)
    assert "ASR read complete" in line
    assert "CFA Audit" in line
    assert "CFA modification shield" in line
    assert "BackupConfigured yes" in line
    assert "RestoreVerified unknown" in line
    assert "stops reads" not in line.lower()
    assert "Sandbox UNAVAILABLE" in line


def test_p1_sources_do_not_add_exclusions_or_block_maps():
    blob = "\n".join(
        path.read_text(encoding="utf-8")
        for path in (
            ROOT / "agent" / "modules" / "prevention.py",
            ROOT / "agent" / "modules" / "prevention_apply.py",
            ROOT / "agent" / "modules" / "security.py",
        )
    )
    assert "ExclusionPath" not in blob
    assert "AttackSurfaceReductionOnlyExclusions" not in blob
    assert "Add-MpPreference" not in blob
    assert "Set-MpPreference" not in (ROOT / "agent" / "modules" / "security.py").read_text(encoding="utf-8")
    assert "Get-MpPreference" in OBSERVE_PS
    assert "Set-MpPreference" not in OBSERVE_PS
    assert "wdcp.microsoft.com" not in blob

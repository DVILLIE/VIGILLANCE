"""P0 world-class FREE foundations: fixtures only, no live Defender or processes."""

from datetime import datetime, timezone
from pathlib import Path

import pytest

from agent.capability import probe_capabilities
from agent.edition_matrix import build_edition_matrix, classify_sku, interpret_sac
from agent.modules import security
from agent.modules.prevention import parse_prevention
from agent.modules.defender_health import (
    combine_health,
    interpret_maps_output,
    parse_defender_status,
    query_defender_health,
    query_maps,
)
from agent.modules.security import SecurityStatus
from agent.nerve import CollectionIncomplete
from agent.runtime import _collector_callbacks
from agent.store.db import AgentStore
from agent.twin import TwinStore
from agent.utils import IS_WINDOWS
from agent.version import get_version
from dvielle.gui.observations import prevention_evidence_line

ROOT = Path(__file__).resolve().parents[1]

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
MAPS_ELEVATION = (
    "MAPS:RAN\nEXIT:1\n"
    "ValidateMapsConnection failed to establish a connection to MAPS (hr=80070005 httpcode=450)\n"
)
MAPS_BLOCKED = (
    "MAPS:RAN\nEXIT:1\n"
    "ValidateMapsConnection failed to establish a connection to MAPS (hr=80070006 httpcode=451)\n"
)


def _fresh(security_block: dict, *, status: str = "ok", capability: dict | None = None) -> dict:
    stamp = datetime.now(timezone.utc).isoformat()
    return {
        "runtime": {"state": "running", "heartbeat_at": stamp},
        "collectors": {
            "heartbeat": {"status": "ok", "interval_seconds": 5, "last_success_at": stamp},
            "security": {"status": status, "interval_seconds": 120, "last_success_at": stamp},
        },
        "security": security_block,
        "capability": capability or {},
    }


def test_version_is_2_0_0():
    assert get_version() == "2.2.0"


def test_home_matrix_marks_sandbox_and_authoring_unavailable():
    matrix = build_edition_matrix("Home", edition_id="Core")
    assert matrix.features["windows_sandbox"] == "UNAVAILABLE"
    assert matrix.features["app_control_authoring"] == "UNAVAILABLE"
    assert matrix.features["asr"] == "AVAILABLE"
    assert matrix.features["cfa"] == "AVAILABLE"
    assert matrix.features["firewall"] == "AVAILABLE"
    assert matrix.features["smart_app_control"] == "UNKNOWN"
    blob = " ".join(matrix.notes)
    assert "does not claim CFA prevents reading or exfiltration" in blob
    assert "not supported on Windows Home" in blob
    assert "does not enforce" in blob


def test_home_sac_probe_does_not_invent_sandbox():
    matrix = build_edition_matrix(
        "Home",
        smart_app_control="AVAILABLE",
        smart_app_control_mode="enforcement",
    )
    assert matrix.features["windows_sandbox"] == "UNAVAILABLE"
    assert matrix.features["smart_app_control"] == "AVAILABLE"
    assert matrix.smart_app_control_mode == "enforcement"


def test_pro_matrix_supports_sandbox_without_calling_it_running():
    matrix = build_edition_matrix("ProOrHigher", edition_id="Professional")
    assert matrix.features["windows_sandbox"] == "AVAILABLE"
    assert matrix.features["app_control_authoring"] == "AVAILABLE"
    assert any("does not mean the optional feature is installed" in note for note in matrix.notes)


def test_unknown_sku_does_not_claim_sandbox():
    matrix = build_edition_matrix("Unknown")
    assert matrix.features["windows_sandbox"] == "UNKNOWN"
    assert matrix.features["windows_sandbox"] != "AVAILABLE"
    assert matrix.features["app_control_authoring"] == "UNKNOWN"
    assert matrix.features["asr"] == "AVAILABLE"


def test_server_and_non_windows_do_not_claim_sandbox():
    assert build_edition_matrix("Server").features["windows_sandbox"] == "UNAVAILABLE"
    other = build_edition_matrix("NonWindows", smart_app_control="AVAILABLE", smart_app_control_mode="enforcement")
    assert all(state == "UNAVAILABLE" for state in other.features.values())
    assert other.smart_app_control_mode is None


@pytest.mark.parametrize(
    ("edition_id", "caption", "expected"),
    [
        ("Core", None, "Home"),
        ("CoreSingleLanguage", "Windows 11 Pro", "Home"),
        ("Professional", None, "ProOrHigher"),
        ("ProfessionalEducation", None, "ProOrHigher"),
        ("Enterprise", None, "ProOrHigher"),
        ("Education", None, "ProOrHigher"),
        ("ServerStandard", None, "Server"),
        (None, "Windows 11 Home", "Home"),
        (None, "Windows Server 2022 Datacenter", "Server"),
        (None, "Windows 11 Pro", "ProOrHigher"),
        (None, None, "Unknown"),
    ],
)
def test_classify_sku(edition_id, caption, expected):
    assert classify_sku(edition_id, caption, windows=True) == expected


def test_non_windows_classify_ignores_a_home_caption():
    assert classify_sku("Core", "Windows 11 Home", windows=False) == "NonWindows"


@pytest.mark.parametrize(
    ("value", "readable", "mode", "state"),
    [
        (0, True, "off", "LIMITED"),
        (1, True, "enforcement", "AVAILABLE"),
        (2, True, "evaluation", "LIMITED"),
        (7, True, None, "UNKNOWN"),
        (None, False, None, "UNKNOWN"),
    ],
)
def test_sac_probe_values(value, readable, mode, state):
    assert interpret_sac(value, readable=readable, windows=True) == (mode, state)


def test_sac_probe_off_windows_is_unavailable():
    assert interpret_sac(1, readable=True, windows=False) == (None, "UNAVAILABLE")


def test_healthy_status_is_not_all_clear_until_maps_passes():
    health = parse_defender_status(HEALTHY)
    assert health.coverage == "complete"
    assert health.active_mode == "AVAILABLE"
    assert health.realtime == "AVAILABLE"
    assert health.signature_freshness == "AVAILABLE"
    assert health.signature_age_days == 0
    assert health.engine_version == "1.1.25000.5"
    assert health.engine_freshness == "UNKNOWN"
    assert health.all_clear is False
    passed = combine_health(health, interpret_maps_output(MAPS_PASS))
    assert passed.all_clear is True
    assert passed.overall == "AVAILABLE"
    assert passed.engine_freshness == "UNKNOWN"


def test_access_denied_stays_partial_and_not_healthy():
    health = parse_defender_status("STATUS:ACCESS_DENIED\nDETAIL:Access is denied\n" + HEALTHY)
    assert health.coverage == "partial"
    assert health.query_state == "LIMITED"
    assert health.overall == "UNKNOWN"
    assert health.all_clear is False
    assert health.am_running_mode is None
    assert "access denied" in health.coverage_detail
    assert "all clear" not in health.coverage_detail.lower()


def test_missing_fields_and_timeout_are_not_complete():
    partial = parse_defender_status("STATUS:OK\nAMRunningMode:Normal\nAntivirusEnabled:True\n")
    assert partial.coverage == "partial"
    assert partial.all_clear is False
    assert "missing" in partial.coverage_detail
    timed = parse_defender_status(HEALTHY, timed_out=True)
    assert timed.coverage == "partial"
    assert timed.all_clear is False
    assert timed.engine_freshness == "UNKNOWN"


def test_passive_mode_and_stale_signatures_are_not_active_pass():
    text = HEALTHY.replace("AMRunningMode:Normal", "AMRunningMode:Passive")
    text = text.replace("DefenderSignaturesOutOfDate:False", "DefenderSignaturesOutOfDate:True")
    health = combine_health(parse_defender_status(text), interpret_maps_output(MAPS_PASS))
    assert health.active_mode == "LIMITED"
    assert health.signature_freshness == "LIMITED"
    assert health.all_clear is False
    assert health.overall == "LIMITED"


def test_maps_elevation_is_unavailable_and_block_result_does_not_recommend_blocking():
    elevated = interpret_maps_output(MAPS_ELEVATION)
    assert elevated.result == "unavailable"
    assert "not a pass" in elevated.detail
    assert "does not block" in elevated.detail
    blocked = interpret_maps_output(MAPS_BLOCKED)
    assert blocked.result == "fail"
    assert "does not block" in blocked.detail
    assert "New-NetFirewallRule" not in blocked.detail
    assert "ExclusionPath" not in blocked.detail
    missing = interpret_maps_output("MAPS:UNAVAILABLE\nDETAIL:MpCmdRun.exe was not found\n")
    assert missing.result == "unavailable"
    service = interpret_maps_output("ValidateMapsConnection failed (800106BA)\nEXIT:1\n")
    assert service.result == "unavailable"


def test_linux_queries_do_not_launch_powershell(monkeypatch):
    def forbidden(*_args, **_kwargs):
        raise AssertionError("PowerShell must not run for a non-Windows health query")

    monkeypatch.setattr("agent.modules.defender_health.IS_WINDOWS", False)
    monkeypatch.setattr("agent.modules.defender_health.run_powershell", forbidden)
    assert query_defender_health().query_state == "UNAVAILABLE"
    assert query_maps().result == "unavailable"
    assert query_defender_health().all_clear is False


def test_security_access_denial_sets_collection_error(tmp_path, monkeypatch):
    monkeypatch.setattr(security, "_query_defender", lambda: (None, None))
    monkeypatch.setattr(security, "_query_firewall", lambda: (None, {}))
    monkeypatch.setattr(
        security,
        "_query_defender_health",
        lambda: parse_defender_status("STATUS:ACCESS_DENIED\nDETAIL:Access is denied"),
    )
    monkeypatch.setattr(security, "_query_maps", lambda: interpret_maps_output(MAPS_ELEVATION))
    monkeypatch.setattr(security, "_query_edition_matrix", lambda: build_edition_matrix("Home"))
    monkeypatch.setattr(
        security,
        "_query_prevention",
        lambda: parse_prevention("STATUS:ACCESS_DENIED\nDETAIL:Access is denied"),
    )
    monitor = security.SecurityMonitor(AgentStore(tmp_path / "agent.db"), {})
    status = monitor.run()
    assert monitor.collection_error
    assert "access denied" in monitor.collection_error
    assert status.defender_health["coverage"] == "partial"
    assert status.defender_health["all_clear"] is False
    assert status.edition_matrix["features"]["windows_sandbox"] == "UNAVAILABLE"
    assert status.issues == []
    assert "all clear" not in monitor.collection_error.lower()


def test_runtime_publishes_partial_home_matrix(tmp_path, monkeypatch):
    class Monitor:
        def __init__(self, *args, **kwargs):
            self.collection_error = "Defender health collection incomplete: access denied"

        def run(self):
            return SecurityStatus(
                None,
                None,
                None,
                {},
                [],
                defender_health={
                    "coverage": "partial",
                    "all_clear": False,
                    "query_state": "LIMITED",
                    "overall": "UNKNOWN",
                    "am_running_mode": None,
                    "realtime": "UNKNOWN",
                    "signature_age_days": None,
                    "signature_freshness": "UNKNOWN",
                    "engine_freshness": "UNKNOWN",
                },
                maps={"result": "unavailable"},
                edition_matrix=build_edition_matrix("Home").to_dict(),
                firewall_query_state="UNKNOWN",
            )

    monkeypatch.setattr("agent.runtime.SecurityMonitor", Monitor)
    twin = TwinStore()
    callbacks = _collector_callbacks(
        AgentStore(tmp_path / "agent.db"),
        {},
        {},
        tmp_path / "domains.txt",
        tmp_path,
        {"enable_toasts": False},
        twin,
        None,
    )
    with pytest.raises(CollectionIncomplete, match="access denied"):
        callbacks["security"]()
    data = twin.as_dict()
    assert data["security"]["coverage"] == "partial"
    assert data["security"]["defender_health"]["all_clear"] is False
    assert data["security"]["edition_matrix"]["features"]["windows_sandbox"] == "UNAVAILABLE"
    assert data["capability"]["defender"] == "LIMITED"


def test_evidence_strip_partial_home_is_not_an_all_clear():
    health = parse_defender_status("STATUS:ACCESS_DENIED\nDETAIL:Access is denied").to_dict()
    data = _fresh(
        {
            "defender_health": health,
            "maps": interpret_maps_output(MAPS_ELEVATION).to_dict(),
            "edition_matrix": build_edition_matrix("Home").to_dict(),
        },
        status="partial",
    )
    line = prevention_evidence_line(data)
    assert "Sandbox UNAVAILABLE" in line
    assert "AppControl UNAVAILABLE" in line
    assert "ASR AVAILABLE" in line
    assert "Defender collection partial" in line
    assert "MAPS unavailable" in line
    assert "engine freshness UNKNOWN" in line
    assert "coverage incomplete" in line
    assert "all clear" not in line.lower()
    assert "ACTIVE" not in line


def test_evidence_strip_can_show_a_qualified_pass_without_hiding_engine_uncertainty():
    health = combine_health(parse_defender_status(HEALTHY), interpret_maps_output(MAPS_PASS)).to_dict()
    matrix = build_edition_matrix("ProOrHigher", smart_app_control="LIMITED", smart_app_control_mode="evaluation")
    data = _fresh(
        {
            "defender_enabled": True,
            "defender_health": health,
            "maps": {"result": "pass"},
            "edition_matrix": matrix.to_dict(),
        },
        status="ok",
    )
    line = prevention_evidence_line(data)
    assert "coverage incomplete" not in line
    assert "engine freshness UNKNOWN" in line
    assert "MAPS pass" in line
    assert "Sandbox AVAILABLE" in line
    assert "SAC mode evaluation" in line
    assert "all clear" not in line.lower()


def test_stale_evidence_is_not_current():
    data = _fresh({}, status="ok")
    data["runtime"]["state"] = "stopped"
    text = prevention_evidence_line(data)
    assert text.startswith("Prevention evidence stale")
    assert "Sandbox AVAILABLE" not in text


def test_idle_probe_does_not_erase_a_defender_query_state():
    report = probe_capabilities(deep=False)
    report.defender = "UNKNOWN"
    report.firewall = "UNKNOWN"
    twin = TwinStore()
    twin.set_capability(report)
    twin.patch(capability={"defender": "LIMITED", "firewall": "AVAILABLE"})
    twin.set_capability(report)
    data = twin.as_dict()
    assert data["capability"]["defender"] == "LIMITED"
    assert data["capability"]["firewall"] == "AVAILABLE"
    assert "windows_sandbox" in data["capability"]["feature_matrix"]


def test_non_windows_probe_matrix_has_no_sandbox():
    if IS_WINDOWS:
        return
    report = probe_capabilities(deep=False)
    assert report.edition_sku == "NonWindows"
    assert report.feature_matrix["windows_sandbox"] == "UNAVAILABLE"
    assert report.defender == "UNAVAILABLE"


def test_console_evidence_strip_is_wired():
    text = (ROOT / "dvielle" / "gui" / "app.py").read_text(encoding="utf-8")
    assert "prevention_evidence_line" in text
    assert "evidence_lbl" in text
    assert 'set_state("ACTIVE"' in text


def test_p0_sources_do_not_mutate_defender_or_add_exclusions():
    blob = "\n".join(
        path.read_text(encoding="utf-8")
        for path in (
            ROOT / "agent" / "modules" / "defender_health.py",
            ROOT / "agent" / "edition_matrix.py",
            ROOT / "agent" / "modules" / "security.py",
        )
    )
    assert "ExclusionPath" not in blob
    assert "Add-MpPreference" not in blob
    assert "Set-MpPreference" not in blob
    assert "New-NetFirewallRule" not in blob
    assert "Remove-MpPreference" not in blob

"""Control repair regressions using explicit fixtures, never host remediation.

These establish serialization, state comparisons, and refusal contracts. They
do not certify actual Defender changes, firewall enforcement, or a live guest.
"""

from __future__ import annotations

import json
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

from agent.engine.handlers import HandlerContext, open_unfamiliar as sandbox_handler
from agent.modules import prevention_apply as prevention
from agent.modules.defender_health import interpret_maps_output, parse_defender_status
from agent.modules.firewall_apply import (
    _matches, _remote_ok, apply_scope, apply_script, apply_verified, parse_verify, remove_script, rule_names,
)
from agent.modules.firewall_assist import OBSERVE_PS, parse_firewall_observe
from agent.modules.prevention import DRIVER_GUID, LSASS_GUID
from agent.modules.sandbox import default_sandbox_launch, open_unfamiliar, system_sandbox_exe
from agent.policy.dual import _mutate_depth

OTHER_GUID = "d4f940ab-401b-4efc-aadc-ad5f3c50688a"
UNKNOWN_GUID = "11111111-2222-3333-4444-555555555555"
HEALTHY = """STATUS:OK
AMRunningMode:Normal
AntivirusEnabled:True
RealTimeProtectionEnabled:True
AntivirusSignatureAge:0
AntivirusSignatureVersion:1.413.1.0
AntivirusSignatureLastUpdated:2026-09-29
AMEngineVersion:1.1.25000.5
AMProductVersion:4.18.25000.7
DefenderSignaturesOutOfDate:False
AMServiceEnabled:True
"""


@pytest.fixture
def mutate_scope():
    token = _mutate_depth.set(1)
    try:
        yield
    finally:
        _mutate_depth.reset(token)


class PreferenceFixture:
    """Set replaces arrays; Add changes one entry. No Windows cmdlet executes."""

    def __init__(self, rules: dict[str, int], journal: Path) -> None:
        self.rules = dict(rules)
        self.journal = journal
        self.commands: list[str] = []
        self.collateral = False

    def __call__(self, script, timeout=25):
        if "DVIELLE_ASR_SET" in script or "DVIELLE_ASR_REMOVE" in script:
            assert self.journal.exists(), "Recovery information must predate mutation"
            self.commands.append(script)
            if "Set-MpPreference -AttackSurfaceReductionRules_Ids" in script:
                ids = re.search(r"-AttackSurfaceReductionRules_Ids @\(([^)]*)\)", script)
                actions = re.search(r"-AttackSurfaceReductionRules_Actions @\(([^)]*)\)", script)
                assert ids and actions
                self.rules = dict(zip(re.findall(r"'([^']+)'", ids.group(1)),
                                      (int(value) for value in actions.group(1).split(","))))
            elif "Add-MpPreference -AttackSurfaceReductionRules_Ids" in script:
                row = re.search(r"Add-MpPreference -AttackSurfaceReductionRules_Ids '([^']+)' -AttackSurfaceReductionRules_Actions (\d+)", script)
                assert row
                self.rules[row.group(1)] = int(row.group(2))
            else:
                row = re.search(r"Remove-MpPreference -AttackSurfaceReductionRules_Ids '([^']+)'", script)
                assert row
                self.rules.pop(row.group(1), None)
            if self.collateral:
                self.rules.pop(OTHER_GUID, None)
            return "SET:OK\n", False
        rows = ["OBSERVE:ASR_CFA", "STATUS:OK", f"COUNT:{len(self.rules)}:{len(self.rules)}", "CFA:0"]
        rows.extend(f"RULE:{guid}={action}" for guid, action in self.rules.items())
        return "\n".join(rows), False


def _asr(fixture: PreferenceFixture, action: int):
    return prevention.apply_asr_rule(
        guid=DRIVER_GUID, action=action, runner=fixture,
        health_reader=lambda: parse_defender_status(HEALTHY),
        maps_reader=lambda: interpret_maps_output("MAPS:RAN\nEXIT:0\nValidateMapsConnection completed\n"),
        undo_path=fixture.journal, sku="Home",
    )


def test_asr_set_and_verified_undo_preserve_catalog_and_unknown_rules(tmp_path, mutate_scope):
    original = {DRIVER_GUID: 2, OTHER_GUID: 2, UNKNOWN_GUID: 1}
    fixture = PreferenceFixture(original, tmp_path / "undo.txt")
    applied = _asr(fixture, 1)
    assert applied["performed"] is True
    assert fixture.rules == {**original, DRIVER_GUID: 1}
    assert "ASR preferences changed before apply" in fixture.commands[0]
    records = prevention._read_undo(fixture.journal)
    assert json.loads(records["asr_snapshot"]) == original
    assert "asr_pending" not in records
    undone = _asr(fixture, 2)
    assert undone["performed"] is True
    assert fixture.rules == original


def test_absent_asr_rule_is_added_without_replacing_array(tmp_path, mutate_scope):
    fixture = PreferenceFixture({OTHER_GUID: 2, UNKNOWN_GUID: 1}, tmp_path / "undo.txt")
    result = _asr(fixture, 2)
    assert result["performed"] is True
    assert "Add-MpPreference -AttackSurfaceReductionRules_Ids" in fixture.commands[0]
    assert "Set-MpPreference -AttackSurfaceReductionRules_Ids" not in fixture.commands[0]
    assert fixture.rules[OTHER_GUID] == 2 and fixture.rules[UNKNOWN_GUID] == 1
    undo = _asr(fixture, 5)
    assert undo["performed"] is True
    assert DRIVER_GUID not in fixture.rules
    assert fixture.rules == {OTHER_GUID: 2, UNKNOWN_GUID: 1}


def test_asr_does_not_certify_collateral_rule_loss(tmp_path, mutate_scope):
    original = {DRIVER_GUID: 2, OTHER_GUID: 2}
    fixture = PreferenceFixture(original, tmp_path / "undo.txt")
    fixture.collateral = True
    result = _asr(fixture, 1)
    assert result["performed"] is False
    assert result["recovery_pending"] is True
    pending = json.loads(prevention._read_undo(fixture.journal)["asr_pending"])
    assert pending["before"] == original
    fixture.collateral = False
    command_count = len(fixture.commands)
    retry = _asr(fixture, 2)
    assert retry["performed"] is False and retry["recovery_pending"] is True
    assert len(fixture.commands) == command_count
    assert json.loads(prevention._read_undo(fixture.journal)["asr_pending"]) == pending


def test_asr_refuses_if_recovery_journal_cannot_be_written(tmp_path, mutate_scope, monkeypatch):
    fixture = PreferenceFixture({DRIVER_GUID: 2}, tmp_path / "undo.txt")

    def fail(*args):
        raise OSError("unit fixture denied write")

    monkeypatch.setattr(prevention, "_write_undo", fail)
    result = _asr(fixture, 1)
    assert result["performed"] is False
    assert fixture.commands == []


@pytest.mark.parametrize("content", ["", "unstructured", "asr_pending|not-json", "cfa_pending|{}", "cfa|bad", "cfa|2\ncfa|1"])
def test_corrupt_recovery_journal_blocks_prevention_changes(tmp_path, mutate_scope, content):
    fixture = PreferenceFixture({DRIVER_GUID: 2}, tmp_path / "undo.txt")
    fixture.journal.write_text(content, encoding="utf-8")
    result = _asr(fixture, 1)
    assert result["performed"] is False
    assert "corrupt" in result["message"]
    assert fixture.commands == []
    assert fixture.journal.read_text(encoding="utf-8") == content


def test_unreadable_existing_journal_is_not_treated_as_empty(tmp_path, mutate_scope, monkeypatch):
    fixture = PreferenceFixture({DRIVER_GUID: 2}, tmp_path / "undo.txt")
    fixture.journal.write_text("# DVielle prevention undo\n", encoding="utf-8")
    real_read = Path.read_text

    def read(path, *args, **kwargs):
        if path == fixture.journal:
            raise PermissionError("unit fixture access denied")
        return real_read(path, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", read)
    result = _asr(fixture, 1)
    assert result["performed"] is False and fixture.commands == []


def test_nested_prevention_change_is_refused_before_a_second_lock(tmp_path, mutate_scope):
    fixture = PreferenceFixture({DRIVER_GUID: 2}, tmp_path / "undo.txt")
    nested = []

    def runner(script, timeout=25):
        if "DVIELLE_ASR_SET" in script:
            nested.append(prevention.apply_cfa_mode(mode=2, undo_path=fixture.journal))
        return fixture(script, timeout)

    result = prevention.apply_asr_rule(
        guid=DRIVER_GUID, action=1, runner=runner, undo_path=fixture.journal, sku="Home",
        health_reader=lambda: parse_defender_status(HEALTHY),
        maps_reader=lambda: interpret_maps_output("MAPS:RAN\nEXIT:0\n"),
    )
    assert result["performed"] is True
    assert len(nested) == 1 and nested[0]["performed"] is False
    assert "Nested" in nested[0]["message"]


def test_different_asr_rules_share_one_serialized_recovery_lifecycle(tmp_path):
    fixture = PreferenceFixture({DRIVER_GUID: 2, LSASS_GUID: 2}, tmp_path / "undo.txt")
    barrier = threading.Barrier(2)

    def runner(script, timeout=25):
        if "DVIELLE_ASR_SET" in script:
            time.sleep(0.05)  # Widen a potential read-modify-write race in this unit fixture.
        return fixture(script, timeout)

    def change(guid):
        barrier.wait(timeout=5)
        token = _mutate_depth.set(1)
        try:
            return prevention.apply_asr_rule(
                guid=guid, action=1, runner=runner, undo_path=fixture.journal, sku="Home",
                health_reader=lambda: parse_defender_status(HEALTHY),
                maps_reader=lambda: interpret_maps_output("MAPS:RAN\nEXIT:0\n"),
            )
        finally:
            _mutate_depth.reset(token)

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(change, [DRIVER_GUID, LSASS_GUID]))
    assert all(result["performed"] for result in results)
    assert fixture.rules == {DRIVER_GUID: 1, LSASS_GUID: 1}
    records = prevention._read_undo(fixture.journal)
    assert records[f"asr:{DRIVER_GUID}"] == "2" and records[f"asr:{LSASS_GUID}"] == "2"


def test_cfa_writer_compares_full_prewrite_state():
    script = prevention._cfa_set_script(2, 0, {DRIVER_GUID: 2})
    assert "Get-MpPreference -ErrorAction Stop" in script
    assert "CFA mode changed before apply" in script
    assert "ASR preferences changed before CFA apply" in script
    assert script.index("CFA mode changed before apply") < script.index("Set-MpPreference -EnableControlledFolderAccess")


def _request(remotes=None):
    return {"program": r"C:\Apps\App.exe", "profile": "Public",
            "address_families": ["IPv4", "IPv6"], "remote_addresses": remotes or []}


def _verified(request, *, owner="DVielle invocation unit-fixture", remote_override=None):
    lines = []
    for name, family in rule_names(request["program"], request["profile"], request["address_families"], request["remote_addresses"]):
        remotes = [value for value in request["remote_addresses"] if (":" in value) == (family == "IPv6")]
        remote = remote_override or ",".join(remotes) or ("0.0.0.0/0" if family == "IPv4" else "::/0")
        lines.append(f"VERIFY:{name}|True|Outbound|Block|Public|derived|{request['program']}|{remote}|DVielle|{owner}")
    return "\n".join(lines + ["STATUS:OK"])


def test_firewall_uses_supported_arrays_and_per_family_networks():
    request = _request(["203.0.113.10/32", "203.0.113.20/32", "2001:db8::1/128"])
    script = apply_script(request, ownership_token="unit-fixture")
    assert "AddressFamily =" not in script and ".AddressFamily" not in script
    assert "RemoteAddress = @($item.Remote)" in script
    assert "Remote = @('203.0.113.10/32','203.0.113.20/32')" in script
    assert "Remote = @('2001:db8::1/128')" in script
    assert "-PolicyStore ActiveStore" in script
    assert _matches(parse_verify(_verified(request)), request)


def test_specific_ipv4_remotes_do_not_create_ipv6_wide_block():
    request = _request(["203.0.113.10/32"])
    assert [family for _, family in rule_names(request["program"], request["profile"], request["address_families"], request["remote_addresses"])] == ["IPv4"]
    assert "::/0" not in apply_script(request)


@pytest.mark.parametrize("observed", ["11.2.3.40", "1.2.3.4,8.8.8.8", "1.2.3.0/24", "Any", ""])
def test_firewall_filter_rejects_substring_extra_or_broader_addresses(observed):
    assert not _remote_ok(["1.2.3.4/32"], observed)


def test_firewall_normalizes_exact_equivalent_ranges():
    assert _remote_ok(["192.0.2.0/24"], "192.0.2.0-192.0.2.255")
    assert _remote_ok(["2001:db8::1/128"], "2001:0db8:0:0:0:0:0:1")


def test_firewall_rollback_requires_ownership_and_observed_removal():
    request = _request()
    commands = []

    def runner(script):
        commands.append(script)
        if "DVIELLE_FW_APPLY" in script:
            return "STATUS:FAILED", False
        names = [name for name, _ in rule_names(request["program"], request["profile"], request["address_families"], [])]
        return "\n".join([f"REMOVE:UNTOUCHED:{names[0]}", f"REMOVE:STILL:{names[1]}", "STATUS:OK"]), False

    with apply_scope():
        result = apply_verified(request, runner)
    assert result["performed"] is False and result["state_unknown"] is True
    assert result["rollback_verified"] is False
    assert "may remain" in result["message"]
    assert "[string]$rule.Description -eq $tag" in commands[1]
    assert "[string]$rule.Group -eq 'DVielle'" in commands[1]
    assert "REMOVE:UNTOUCHED:" in commands[1]
    assert "[string]$rule.Description -eq $tag" in remove_script(["DVielle-restrict-abc-v4"])


def test_firewall_observation_uses_filters_not_invented_family_property():
    assert ".AddressFamily" not in OBSERVE_PS
    text = "\n".join(["OBSERVE:FIREWALL", "MPSSVC:Running", "PROFILE:Domain:True", "PROFILE:Private:True",
                       "PROFILE:Public:True", "COUNT:1", "RULE:DVielle-restrict-test-v4|True|Outbound|Block|Any|IPv4|C:\\App.exe|Any", "STATUS:OK"])
    posture = parse_firewall_observe(text)
    assert posture.rules[0].address_family == "Both"
    assert not any(row.get("why", "").startswith("An existing") for row in posture.proposals)


def test_sandbox_refuses_arbitrary_matching_basename(tmp_path, mutate_scope):
    calls = []
    result = open_unfamiliar(
        sku="ProOrHigher", feature_installed=True, host_folder=r"C:\Unfamiliar",
        sandbox_exe=r"C:\Users\Public\WindowsSandbox.exe", folder_exists=lambda path: True,
        launch=lambda args: calls.append(args) or 0, wsb_dir=tmp_path,
    )
    assert result["performed"] is False and calls == []
    assert default_sandbox_launch([r"C:\Users\Public\WindowsSandbox.exe", "anything.wsb"]) == 127


def test_sandbox_handler_ignores_forged_guest_network_claim(tmp_path, mutate_scope):
    ctx = HandlerContext(lookup=lambda pid: None, close=lambda pid, name: (False, "unused"),
                         sandbox_launch=lambda args: 0, sandbox_folder_exists=lambda path: True,
                         sandbox_wsb_dir=tmp_path)
    finding = {"signals": {"sku": "ProOrHigher", "feature_installed": True,
                           "host_folder": r"C:\Unfamiliar", "network_probe": "disabled"}}
    first = sandbox_handler(finding, ctx)
    second = sandbox_handler(finding, ctx)
    assert first["network_verification"] == "UNKNOWN" and first["isolation"] == "LIMITED"
    assert first["wsb"] != second["wsb"]
    root = ET.fromstring(Path(first["wsb"]).read_text(encoding="utf-8"))
    for setting in ("Networking", "ClipboardRedirection", "AudioInput", "VideoInput", "PrinterRedirection", "VGpu"):
        assert root.findtext(setting) == "Disable"
    assert first["command"][0] == system_sandbox_exe()

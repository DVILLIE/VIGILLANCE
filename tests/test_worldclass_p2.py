"""P2: firewall assistant, privileged helper contract, published CPU contract."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from agent.cpu_contract import (
    PUBLISHED_ANALYSIS_CPU_RATE,
    published_contract,
    try_assign_current_process,
)
from agent.edition_matrix import build_edition_matrix
from agent.engine.handlers import HandlerContext
from agent.engine.loop import ResolutionEngine
from agent.engine.models import PolicyDenied
from agent.engine.net_block import block_app_network
from agent.modules.firewall_apply import apply_script, apply_verified, remove_script
from agent.modules.firewall_assist import LEAK_WARNING, OBSERVE_PS, parse_firewall_observe, query_firewall_assist
from agent.modules.prevention import CFA_MODIFICATION_COPY
from agent.privilege.broker import discover_endpoint, submit_restrict_network
from agent.privilege.contract import validate_restrict_params
from agent.privilege.helper import LoopbackHelper, dispatch
from agent.store.db import AgentStore
from agent.utils import IS_WINDOWS
from agent.version import get_version

ROOT = Path(__file__).resolve().parents[1]
P2_SOURCES = (
    ROOT / "agent" / "modules" / "firewall_assist.py",
    ROOT / "agent" / "modules" / "firewall_apply.py",
    ROOT / "agent" / "privilege" / "contract.py",
    ROOT / "agent" / "privilege" / "broker.py",
    ROOT / "agent" / "privilege" / "helper.py",
    ROOT / "agent" / "cpu_contract.py",
    ROOT / "agent" / "engine" / "net_block.py",
)


def _comment(script: str, key: str) -> str:
    prefix = f"# {key}:"
    for line in script.splitlines():
        if line.startswith(prefix):
            return line[len(prefix) :]
    return ""


class _Rules:
    def __init__(self, *, fail: str | None = None) -> None:
        self.fail = fail
        self.calls: list[str] = []
        self.live: dict[str, str] = {}

    def __call__(self, script: str) -> tuple[str, bool]:
        self.calls.append(script)
        if "Stop-Service" in script or "Set-Service" in script:
            raise AssertionError("firewall script tried to change a service")
        names = re.findall(r"DVielle-restrict-[0-9a-f]{12}-v[46]", script)
        if "DVIELLE_FW_REMOVE" in script:
            for name in names:
                self.live.pop(name, None)
            lines = [f"REMOVE:GONE:{name}" for name in dict.fromkeys(names)]
            lines.append("STATUS:OK")
            return "\n".join(lines), False
        if "DVIELLE_FW_APPLY" not in script:
            return "STATUS:FAILED\n", False
        program = _comment(script, "PROGRAM")
        profile = _comment(script, "PROFILE")
        remote = _comment(script, "REMOTE") or "Any"
        lines = []
        for family, name in re.findall(
            r"# FAMILY:(IPv[46]):(DVielle-restrict-[0-9a-f]{12}-v[46])", script
        ):
            if self.fail == family:
                lines.append(f"VERIFY:MISSING:{name}")
                continue
            self.live[name] = family
            lines.append(
                f"VERIFY:{name}|True|Outbound|Block|{profile}|{family}|{program}|{remote}"
            )
        lines.append("STATUS:OK")
        return "\n".join(lines), False


def _program(tmp_path: Path) -> str:
    path = tmp_path / "My App.exe"
    path.write_bytes(b"MZ")
    return str(path)


def _observe(rules: str = "", *, mpssvc: str = "Running", vpn: str = "", count: int | None = None) -> str:
    rule_lines = [line for line in rules.splitlines() if line.strip()]
    counted = len(rule_lines) if count is None else count
    vpn_line = f"VPN:{vpn}\n" if vpn else ""
    body = "".join(line + "\n" for line in rule_lines)
    return (
        "OBSERVE:FIREWALL\n"
        f"MPSSVC:{mpssvc}\n"
        "PROFILE:Domain:True\n"
        "PROFILE:Private:True\n"
        "PROFILE:Public:True\n"
        f"COUNT:{counted}\n"
        f"{body}"
        f"{vpn_line}"
        "STATUS:OK\n"
    )


def test_version_is_2_0_0():
    assert get_version() == "2.0.0"


def test_home_firewall_stays_available_and_sandbox_stays_unavailable():
    home = build_edition_matrix("Home")
    assert home.features["firewall"] == "AVAILABLE"
    assert home.features["windows_sandbox"] == "UNAVAILABLE"
    assert "reading or exfiltration" in CFA_MODIFICATION_COPY


def test_observe_warns_on_vpn_and_single_stack_without_changing_rules():
    posture = parse_firewall_observe(
        _observe(
            "RULE:DVielle-restrict-abc123abc123-v4|True|Outbound|Block|Any|IPv4|C:\\Apps\\App.exe|Any",
            vpn="Tailscale",
        )
    )
    assert posture.coverage == "complete"
    assert posture.mpssvc == "Running"
    assert posture.vpn_adapters == ["Tailscale"]
    assert posture.to_dict()["leakproof"] is False
    blob = " ".join(posture.warnings).lower()
    assert "not a leakproof" in blob
    assert "tailscale" in blob
    assert "does not stop or start" in blob
    assert any(item["signals"]["address_families"] == ["IPv6"] for item in posture.proposals)
    assert "Stop-Service" not in OBSERVE_PS
    assert "New-NetFirewallRule" not in OBSERVE_PS
    assert "Set-NetFirewallProfile" not in OBSERVE_PS


def test_stopped_firewall_service_proposes_nothing_and_is_not_started():
    posture = parse_firewall_observe(_observe(mpssvc="Stopped"))
    assert posture.coverage == "complete"
    assert posture.proposals == []
    assert "will not start it" in " ".join(posture.warnings).lower()
    assert "Stop-Service" not in OBSERVE_PS


def test_incomplete_firewall_read_proposes_nothing():
    mismatch = parse_firewall_observe(_observe(count=2))
    assert mismatch.coverage == "partial"
    assert mismatch.proposals == []
    denied = parse_firewall_observe("OBSERVE:FIREWALL\nSTATUS:ACCESS_DENIED\nDETAIL:Access is denied\n")
    assert denied.coverage == "partial"
    assert denied.rules == []


def test_linux_firewall_query_does_not_launch_powershell(monkeypatch: pytest.MonkeyPatch):
    def forbidden(*_args, **_kwargs):
        raise AssertionError("PowerShell must not run for a non-Windows firewall query")

    monkeypatch.setattr("agent.modules.firewall_assist.IS_WINDOWS", False)
    monkeypatch.setattr("agent.modules.firewall_assist.run_powershell", forbidden)
    posture = query_firewall_assist()
    assert posture.coverage == "unavailable"
    assert posture.proposals == []


def test_helper_refuses_undefined_operations_without_a_firewall_call():
    calls: list[str] = []

    def runner(script: str) -> tuple[str, bool]:
        calls.append(script)
        return "STATUS:OK\n", False

    for op in (
        "stop_mpssvc",
        "stop_service",
        "exclusion_path",
        "github_update",
        "set_asr_rule",
        "close_process",
        "block_ip",
        "sandbox",
        "",
    ):
        body = dispatch(
            {"v": 1, "op": op, "token": "ab" * 16, "params": {}},
            runner=runner,
            expected_token="ab" * 16,
        )
        assert body["code"] == "undefined_op"
        assert body["performed"] is False
    assert calls == []
    junk = dispatch(["restrict_network"], runner=runner, expected_token="ab" * 16)
    assert junk["code"] == "bad_params"
    assert calls == []


def test_helper_refuses_a_bad_token_and_unchecked_parameters(tmp_path: Path):
    calls: list[str] = []
    program = _program(tmp_path)

    def runner(script: str) -> tuple[str, bool]:
        calls.append(script)
        return "STATUS:OK\n", False

    token = "cd" * 16
    refused = dispatch(
        {
            "v": 1,
            "op": "restrict_network",
            "token": "00" * 16,
            "params": {"program": program, "profile": "Public"},
        },
        runner=runner,
        expected_token=token,
    )
    assert refused["code"] == "refused"
    extra = dispatch(
        {
            "v": 1,
            "op": "restrict_network",
            "token": token,
            "params": {"program": program, "profile": "Public", "service": "MpsSvc"},
        },
        runner=runner,
        expected_token=token,
    )
    assert extra["code"] == "bad_params"
    wide = validate_restrict_params(
        {"program": program, "profile": "Public", "remote_addresses": ["0.0.0.0/0"]}
    )
    assert wide[0] is None
    wrong_family = validate_restrict_params(
        {
            "program": program,
            "profile": "Public",
            "address_families": ["IPv4"],
            "remote_addresses": ["2001:db8::1"],
        }
    )
    assert wrong_family[0] is None
    assert calls == []


def test_direct_apply_refuses_outside_the_helper(tmp_path: Path):
    calls: list[str] = []
    program = _program(tmp_path)
    checked, error = validate_restrict_params({"program": program, "profile": "Public"})
    assert error == ""
    assert checked is not None
    body = apply_verified(checked, lambda script: calls.append(script) or ("", False))
    assert body["performed"] is False
    assert "privileged helper" in body["message"].lower()
    assert calls == []
    script = apply_script(checked)
    assert "New-NetFirewallRule" in script
    assert "Get-NetFirewallRule" in script
    assert "Stop-Service" not in script
    assert "MpsSvc" not in script
    assert "Stop-Service" not in remove_script(["DVielle-restrict-abc-v4"])


def test_verified_rule_is_kept_and_a_partial_read_is_rolled_back(tmp_path: Path):
    program = _program(tmp_path)
    rules = _Rules()
    helper = LoopbackHelper(rules)
    try:
        checked, error = validate_restrict_params(
            {
                "program": program,
                "profile": "Public",
                "address_families": ["IPv4", "IPv6"],
                "remote_addresses": ["203.0.113.10"],
            }
        )
        assert error == "" and checked is not None
        from agent.policy.dual import _mutate_depth

        token = _mutate_depth.set(1)
        try:
            body = submit_restrict_network(checked, endpoint=helper.endpoint())
        finally:
            _mutate_depth.reset(token)
        assert body["performed"] is True
        assert "does not prove" in body["message"].lower()
        assert "not a leakproof" in body["message"].lower()
        assert len(rules.live) == 2
        assert any("DVIELLE_FW_REMOVE" in script for script in rules.calls) is False

        rules.fail = "IPv6"
        token = _mutate_depth.set(1)
        try:
            failed = submit_restrict_network(
                {
                    "program": program,
                    "profile": "Any",
                    "address_families": ["IPv4", "IPv6"],
                },
                endpoint=helper.endpoint(),
            )
        finally:
            _mutate_depth.reset(token)
        assert failed["performed"] is False
        assert "not stopped" in failed["message"].lower() or "not kept" in failed["message"].lower()
        assert any("DVIELLE_FW_REMOVE" in script for script in rules.calls)
    finally:
        helper.close()


def test_one_address_family_is_warned(tmp_path: Path):
    program = _program(tmp_path)
    rules = _Rules()
    helper = LoopbackHelper(rules)
    try:
        from agent.policy.dual import _mutate_depth

        token = _mutate_depth.set(1)
        try:
            body = submit_restrict_network(
                {"program": program, "profile": "Private", "address_families": ["IPv4"]},
                endpoint=helper.endpoint(),
            )
        finally:
            _mutate_depth.reset(token)
        assert body["performed"] is True
        assert "does not cover every address family" in body["message"]
        assert LEAK_WARNING.split(".")[0] in body["message"]
        assert len(rules.live) == 1
    finally:
        helper.close()


def test_dual_gate_restrict_uses_the_helper_and_auto_protect_cannot(tmp_path: Path):
    program = _program(tmp_path)
    rules = _Rules()
    helper = LoopbackHelper(rules)
    engine = ResolutionEngine(
        AgentStore(tmp_path / "agent.db"),
        learn_dir=tmp_path / "learn",
        log_dir=tmp_path / "logs",
        handler_ctx=HandlerContext(
            lookup=lambda _pid: None,
            close=lambda _pid, _name: (False, "unused"),
            helper_endpoint=helper.endpoint(),
        ),
    )
    try:
        with pytest.raises(PolicyDenied):
            engine.policy.issue("f", "safety.restrict_network", auto=True, subject=program)
        finding = {
            "id": "finding-fw",
            "subject_identity": program,
            "title_simple": "Block this app on Public",
            "evidence_refs": ["firewall proposal"],
            "signals": {
                "program": program,
                "name": "My App.exe",
                "profile": "Public",
                "address_families": ["IPv4", "IPv6"],
            },
        }
        with pytest.raises(PolicyDenied, match="options required"):
            engine.handlers.invoke("safety.restrict_network", finding, engine.handler_ctx, None)
        assert rules.calls == []
        issued = engine.policy.issue(finding["id"], "safety.restrict_network", auto=False, subject=program)
        body = engine.handlers.invoke("safety.restrict_network", finding, engine.handler_ctx, issued)
        assert body["performed"] is True
        assert "not a leakproof" in body["message"].lower()
        assert len(rules.live) == 2
    finally:
        helper.close()


def test_block_without_helper_or_cortex_does_not_invent_a_rule(tmp_path: Path):
    program = _program(tmp_path)
    ok, message = block_app_network("My App.exe", program)
    assert ok is False
    assert "not stopped" in message.lower()
    quoted, text = block_app_network("Chatty.exe", "/tmp/bad'path", runner=lambda *_a: (True, "added"))
    assert quoted is False
    assert "not stopped" in text.lower()
    refused = block_app_network("svchost.exe", program)
    assert refused[0] is False
    assert "not stopped" in refused[1].lower()


def test_non_loopback_endpoint_is_ignored(tmp_path: Path):
    path = tmp_path / "helper_endpoint.json"
    path.write_text('{"host":"8.8.8.8","port":9,"token":"' + ("ab" * 16) + '"}', encoding="utf-8")
    assert discover_endpoint(tmp_path) is None
    program = _program(tmp_path)
    from agent.policy.dual import _mutate_depth

    token = _mutate_depth.set(1)
    try:
        body = submit_restrict_network(
            {"program": program, "profile": "Public"},
            endpoint={"host": "10.1.1.1", "port": 9, "token": "ab" * 16},
        )
    finally:
        _mutate_depth.reset(token)
    assert body["code"] == "helper_unavailable"
    assert body["performed"] is False


def test_cpu_contract_is_measured_and_does_not_kill_user_apps():
    body = published_contract({"budget": {"max_cpu_percent": 1, "max_rss_mb": 150, "analysis_cpu_percent": 20}})
    assert body["scheduling_mode"] == "measured"
    assert body["analysis_cpu_percent"] == 20
    assert body["analysis_cpu_rate"] == PUBLISHED_ANALYSIS_CPU_RATE == 2000
    assert body["terminates_other_processes"] is False
    assert body["job_cap_applied"] is False
    assert "dynamic fair share" in " ".join(body["assumptions"]).lower()
    zero = published_contract({"budget": {"analysis_cpu_percent": 0}})
    assert zero["analysis_cpu_rate"] == 2000
    hundred = published_contract({"budget": {"analysis_cpu_percent": 100}})
    assert hundred["analysis_cpu_percent"] == 20
    capped = published_contract(None, job={"applied": True, "reason": "helper cap"})
    assert capped["scheduling_mode"] == "job_hard_cap"
    assert capped["terminates_other_processes"] is False
    if not IS_WINDOWS:
        assigned = try_assign_current_process()
        assert assigned["applied"] is False
        assert "measured scheduling" in assigned["reason"].lower()
    source = (ROOT / "agent" / "cpu_contract.py").read_text(encoding="utf-8")
    assert "SetInformationJobObject" in source
    assert "TerminateProcess" not in source
    assert "taskkill" not in source.lower()
    assert "close_pids" not in source


def test_p2_sources_do_not_open_forbidden_paths():
    blob = "\n".join(path.read_text(encoding="utf-8") for path in P2_SOURCES)
    assert "ExclusionPath" not in blob
    assert "Add-MpPreference" not in blob
    assert "api.github.com" not in blob
    assert "wdcp.microsoft.com" not in blob
    assert "Stop-Service" not in OBSERVE_PS
    install = (ROOT / "installer" / "install-dvielle.ps1").read_text(encoding="utf-8")
    assert "[string]$RunLevel = 'Limited'" in install
    assert "TASK_RUNLEVEL_HIGHEST" not in blob


def test_runtime_publishes_the_measured_contract(tmp_path, monkeypatch):
    from agent import runtime

    class _FakeCaps:
        tier = "T1"
        is_admin = False
        overall_vision = "LIMITED"
        gaps: list = []
        ram_total_gb = 16.0
        cpu_count = 4
        battery_present = False
        os_caption = "Linux"
        os_build = "test"
        edition_hint = "Home"
        notes: list = []

        def to_dict(self) -> dict:
            return {"tier": self.tier}

    cfgdir = tmp_path / "config"
    cfgdir.mkdir()
    (cfgdir / "config.yaml").write_text(
        "agent:\n"
        f"  data_dir: {(tmp_path / 'data').as_posix()}\n"
        "modes: {monitor_only: true, enable_toasts: false}\n"
        "modules: {}\n"
        "nerve: {heartbeat_seconds: 5, pulse_seconds: 60, idle_deep_seconds: 900}\n"
        "budget: {max_cpu_percent: 1.0, max_rss_mb: 150, analysis_cpu_percent: 20}\n"
        "logging: {level: INFO}\n",
        encoding="utf-8",
    )
    (cfgdir / "whitelists.yaml").write_text("{}\n", encoding="utf-8")
    (cfgdir / "telemetry-domains.txt").write_text("", encoding="utf-8")
    monkeypatch.setattr(runtime, "probe_capabilities", lambda deep=False: _FakeCaps())
    monkeypatch.setattr(runtime, "set_process_priority", lambda *_a, **_k: None)
    rt = runtime.build_runtime(config_dir=cfgdir)
    try:
        rt.prime()
        contract = rt.twin.as_dict()["self_budget"]["cpu_contract"]
        assert contract["scheduling_mode"] == "measured"
        assert contract["analysis_cpu_rate"] == 2000
        assert contract["job_cap_applied"] is False
        assert contract["terminates_other_processes"] is False
    finally:
        rt.close(timeout=1)

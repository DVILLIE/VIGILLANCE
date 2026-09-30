"""P5: activity experiences, passkey guidance, and the claims page."""

from __future__ import annotations

from pathlib import Path

import pytest

from agent.engine.loop import ResolutionEngine
from agent.engine.models import Observation, PolicyDenied
from agent.engine.policy import PolicyGate
from agent.experiences import (
    PUBLISHED_AUTO,
    experience_allows_auto,
    resolve_experience,
)
from agent.modules.passkeys import account_guidance, review_marks
from agent.modules.sandbox import observe_sandbox
from agent.policy.actions import USER_APPROVED_ONLY, ActionKind
from agent.runtime import load_runtime_config
from agent.store.db import AgentStore
from agent.version import get_version
from dvielle.gui.observations import prevention_evidence_line

ROOT = Path(__file__).resolve().parents[1]
P5_SOURCES = (
    ROOT / "agent" / "experiences.py",
    ROOT / "agent" / "modules" / "passkeys.py",
)


def _obs(severity: str, *, kind: str = "protection_off", action_class: str = "ask_user") -> Observation:
    return Observation(
        pillar="safety",
        kind=kind,
        subject_identity=f"subject:{severity}",
        title_simple="A measured note",
        why_it_matters="The test recorded this severity.",
        if_ignored="Nothing on the computer changes.",
        evidence_refs=["fixture"],
        severity=severity,
        confidence="high",
        recommended_action="Look at it.",
        resolution_steps=["Look."],
        reversible="yes",
        identity_ok=True,
        expected=False,
        suspicious_mismatch=False,
        action_class=action_class,
        signals={},
    )


def test_version_is_2_3_0() -> None:
    assert get_version() == "2.3.2"


def test_shipped_config_is_everyday_and_locks_are_false() -> None:
    config, _, _ = load_runtime_config(ROOT / "config")
    contract = resolve_experience(config, sku="Home")
    assert contract["name"] == "everyday"
    assert contract["denylist_actions"] is False
    assert contract["close_process_auto"] is False
    assert contract["dual_gate"] == "unchanged"
    assert contract["mutates"] is False
    assert contract["proposals"] == []
    assert contract["sandbox"] is None
    assert contract["auto_handlers"] == list(PUBLISHED_AUTO)
    assert contract["observation"] == {"asr": "observe", "cfa": "observe", "firewall": "observe", "mutate": False}


def test_everyday_cannot_enable_denylist_actions() -> None:
    contract = resolve_experience(
        {
            "experiences": {
                "active": "everyday",
                "everyday": {
                    "denylist_actions": True,
                    "close_process_auto": True,
                    "handlers": ["safety.delete_documents", "safety.mass_kill", "safety.smart_close"],
                },
            }
        }
    )
    assert contract["denylist_actions"] is False
    assert contract["close_process_auto"] is False
    assert contract["auto_handlers"] == list(PUBLISHED_AUTO)
    refused = {item["requested"] for item in contract["refused"]}
    assert True in refused
    assert "safety.delete_documents" in refused
    assert "safety.smart_close" in refused
    assert experience_allows_auto(contract, "safety.delete_documents")[0] is False
    assert experience_allows_auto(contract, "safety.mass_kill")[0] is False
    gate = PolicyGate(auto_enabled=True, experience=contract)
    with pytest.raises(PolicyDenied, match="denylist"):
        gate.issue("f1", "safety.delete_documents", auto=True, subject="docs")
    with pytest.raises(PolicyDenied, match="CLOSE_PROCESS stays user-approved"):
        gate.issue("f1", "safety.smart_close", auto=True, subject="app.exe")


def test_everyday_quiet_floor_holds_medium_and_sensitive_surfaces_it(tmp_path: Path) -> None:
    everyday = resolve_experience({"experiences": {"active": "everyday"}})
    sensitive = resolve_experience({"experiences": {"active": "sensitive"}})
    medium = _obs("medium")
    low = _obs("low")
    quiet = ResolutionEngine(
        AgentStore(tmp_path / "quiet.db"),
        learn_dir=tmp_path / "learn-q",
        log_dir=tmp_path / "logs-q",
        experience=everyday,
    )
    held = quiet.evaluate(medium)
    assert held["disposition"] == "held"
    assert held["mutated"] is False
    loud = ResolutionEngine(
        AgentStore(tmp_path / "loud.db"),
        learn_dir=tmp_path / "learn-s",
        log_dir=tmp_path / "logs-s",
        experience=sensitive,
    )
    surfaced = loud.evaluate(medium)
    assert surfaced["disposition"] == "ticket"
    assert surfaced["mutated"] is False
    low_ticket = loud.evaluate(low)
    assert low_ticket["disposition"] == "ticket"
    guess = loud.evaluate(
        Observation(
            pillar="safety",
            kind="protection_off",
            subject_identity="subject:guess",
            title_simple="Unsure",
            why_it_matters="Confidence is low.",
            if_ignored="Nothing changes.",
            evidence_refs=["fixture"],
            severity="critical",
            confidence="low",
            recommended_action="Wait.",
            resolution_steps=["Wait."],
            reversible="yes",
            identity_ok=True,
            expected=False,
            suspicious_mismatch=False,
        )
    )
    assert guess["disposition"] == "held"


def test_sensitive_cannot_auto_mutate_close_process(tmp_path: Path) -> None:
    contract = resolve_experience(
        {
            "experiences": {
                "active": "sensitive",
                "sensitive": {"close_process_auto": True, "open_unfamiliar_auto": True},
            }
        }
    )
    assert contract["close_process_auto"] is False
    assert contract["open_unfamiliar_auto"] is False
    assert contract["close_process"] == "user_approved"
    assert contract["open_unfamiliar"] == "user_approved"
    assert contract["auto_protect_min_severity"] == "critical"
    assert any(item["key"] == "experiences.sensitive.close_process_auto" for item in contract["refused"])
    assert ActionKind.CLOSE_PROCESS in USER_APPROVED_ONLY
    assert experience_allows_auto(contract, "safety.smart_close", severity="critical") == (
        False,
        "CLOSE_PROCESS stays user-approved",
    )
    assert experience_allows_auto(contract, "safety.open_unfamiliar", severity="critical")[0] is False
    engine = ResolutionEngine(
        AgentStore(tmp_path / "agent.db"),
        learn_dir=tmp_path / "learn",
        log_dir=tmp_path / "logs",
        auto_enabled=True,
        experience=contract,
    )
    with pytest.raises(PolicyDenied, match="CLOSE_PROCESS stays user-approved"):
        engine.policy.issue("f-close", "safety.smart_close", auto=True, subject="app.exe")
    called = {"ran": False}

    def mutator() -> dict:
        called["ran"] = True
        return {"performed": True, "message": "closed"}

    from agent.engine.models import AuthToken

    token = AuthToken("f-close", "safety.smart_close", "nonce", auto=True, subject="app.exe")
    engine.policy._issued.add((token.finding_id, token.handler, token.nonce))
    finding = {
        "id": "f-close",
        "subject_identity": "app.exe",
        "title_simple": "Close",
        "evidence_refs": ["fixture"],
    }
    with pytest.raises(PolicyDenied, match="CLOSE_PROCESS stays user-approved"):
        engine.dual.perform(
            handler_name="safety.smart_close",
            finding=finding,
            token=token,
            mutator=mutator,
        )
    assert called["ran"] is False


def test_sensitive_gate_refuses_auto_temp_delete_below_critical(tmp_path: Path) -> None:
    """The mutate gate itself enforces the critical floor, not only the evaluate pre-check."""
    contract = resolve_experience({"experiences": {"active": "sensitive"}})
    engine = ResolutionEngine(
        AgentStore(tmp_path / "agent.db"),
        learn_dir=tmp_path / "learn",
        log_dir=tmp_path / "logs",
        auto_enabled=True,
        experience=contract,
    )
    with pytest.raises(PolicyDenied, match="auto-protect eligibility is tighter"):
        engine.policy.issue(
            "f-temp",
            "storage.free_safe_temp",
            auto=True,
            subject="temp:safe",
            severity="high",
        )
    with pytest.raises(PolicyDenied, match="auto-protect eligibility is tighter"):
        engine.policy.issue("f-temp", "storage.free_safe_temp", auto=True, subject="temp:safe")

    from agent.engine.models import AuthToken

    token = AuthToken("f-temp", "storage.free_safe_temp", "nonce", auto=True, subject="temp:safe")
    engine.policy._issued.add((token.finding_id, token.handler, token.nonce))
    called = {"ran": False}

    def mutator() -> dict:
        called["ran"] = True
        return {"performed": True, "message": "deleted"}

    with pytest.raises(PolicyDenied, match="auto-protect eligibility is tighter"):
        engine.dual.perform(
            handler_name="storage.free_safe_temp",
            finding={
                "id": "f-temp",
                "subject_identity": "temp:safe",
                "severity": "high",
                "title_simple": "Temp",
                "evidence_refs": ["fixture"],
            },
            token=token,
            mutator=mutator,
        )
    assert called["ran"] is False
    issued = engine.policy.issue(
        "f-temp-ok",
        "storage.free_safe_temp",
        auto=True,
        subject="temp:safe",
        severity="critical",
    )
    assert issued.auto is True


def test_sensitive_auto_protect_is_tighter_than_high(tmp_path: Path) -> None:
    contract = resolve_experience({"experiences": {"active": "sensitive"}})
    assert experience_allows_auto(contract, "safety.turn_protection_on", severity="high")[0] is False
    assert experience_allows_auto(contract, "safety.turn_protection_on", severity="critical")[0] is True
    engine = ResolutionEngine(
        AgentStore(tmp_path / "agent.db"),
        learn_dir=tmp_path / "learn",
        log_dir=tmp_path / "logs",
        auto_enabled=True,
        experience=contract,
    )
    high = _obs("high", kind="protection_off", action_class="auto_protect_eligible")
    high.signals["component"] = "defender"
    result = engine.evaluate(high)
    assert result["disposition"] == "ticket"
    assert result["mutated"] is False


def test_sensitive_proposes_cfa_audit_and_firewall_without_applying() -> None:
    promotion = {
        "cfa": {
            "audit_allowed": True,
            "allowed_modes": [2],
            "observed_name": "Disabled",
        }
    }
    firewall = {
        "proposals": [
            {
                "handler": "safety.restrict_network",
                "title_simple": "Block one chosen app on the Public profile",
            }
        ]
    }
    contract = resolve_experience(
        {"experiences": {"active": "sensitive"}},
        promotion=promotion,
        firewall=firewall,
    )
    assert [item["id"] for item in contract["proposals"][:2]] == ["cfa_audit", "firewall_restrict"]
    assert all(item["applied"] is False for item in contract["proposals"])
    assert all(item["requires_dual_gate"] is True for item in contract["proposals"])
    assert all(item["authorization"] == "user_approved" for item in contract["proposals"])
    assert contract["proposals"][0]["available"] is True
    assert "modification shield" in contract["proposals"][0]["what"]
    everyday = resolve_experience(
        {"experiences": {"active": "everyday"}},
        promotion=promotion,
        firewall=firewall,
    )
    assert everyday["proposals"] == []
    assert everyday["observation"]["mutate"] is False


def test_open_unfamiliar_home_is_checklist_only_and_pro_does_not_launch() -> None:
    home = resolve_experience({"experiences": {"active": "open_unfamiliar"}}, sku="Home")
    assert home["sandbox"]["launched"] is False
    assert home["sandbox"]["performed"] is False
    assert home["sandbox"]["checklist_only"] is True
    assert home["sandbox"]["home_checklist_only"] is True
    assert home["sandbox"]["handler"] is None
    checklist = " ".join(home["sandbox"]["checklist"])
    assert "Smart App Control" in checklist
    assert "Attack surface reduction" in checklist
    assert "Controlled folder access" in checklist
    assert "Windows Firewall" in checklist
    assert "Windows Home" in home["sandbox"]["message"]
    forged = resolve_experience(
        {"experiences": {"active": "open_unfamiliar"}},
        sku="Home",
        sandbox={"offer": "READY", "checklist": ["forged"], "message": "ready"},
    )
    assert forged["sandbox"]["offer"] == "UNAVAILABLE"
    assert forged["sandbox"]["launched"] is False
    assert "forged" not in forged["sandbox"]["checklist"]
    ready = observe_sandbox("ProOrHigher", feature_installed=True)
    pro = resolve_experience(
        {"experiences": {"active": "open_unfamiliar", "open_unfamiliar": {"launch": True}}},
        sku="ProOrHigher",
        feature_installed=True,
        sandbox=ready,
    )
    assert pro["sandbox"]["offer"] == "READY"
    assert pro["sandbox"]["checklist_only"] is False
    assert pro["sandbox"]["handler"] == "safety.open_unfamiliar"
    assert pro["sandbox"]["authorization"] == "user_approved"
    assert pro["sandbox"]["launched"] is False
    assert any(item["key"] == "experiences.open_unfamiliar.launch" for item in pro["refused"])
    assert experience_allows_auto(pro, "safety.open_unfamiliar")[0] is False


def test_passkey_guidance_has_no_badge_and_does_not_change_accounts() -> None:
    guide = account_guidance()
    assert guide["phishing_impossible"] is False
    assert guide["badge"] is None
    assert guide["browser_automation"] is False
    assert guide["accounts_changed"] is False
    assert "relying party" in guide["scope"].lower()
    assert "lookalike" in guide["scope"].lower()
    limits = " ".join(guide["limits"]).lower()
    assert "session" in limits
    assert "recovery" in limits
    reviewed = review_marks({item["id"]: True for item in guide["checklist"]})
    assert reviewed["reviewed_count"] == len(guide["checklist"])
    assert reviewed["phishing_impossible"] is False
    assert reviewed["badge"] is None
    assert reviewed["accounts_changed"] is False
    assert reviewed["browser_automation"] is False
    partial = review_marks({"rp_passkey": "yes"})
    assert partial["reviewed_count"] == 0


def test_evidence_line_names_experience_and_passkeys_without_a_badge() -> None:
    from datetime import datetime, timezone

    now = datetime.now(timezone.utc).isoformat()
    data = {
        "runtime": {"state": "running", "heartbeat_at": now},
        "collectors": {"security": {"status": "ok", "interval_seconds": 120, "last_success_at": now}},
        "security": {
            "experience": resolve_experience({"experiences": {"active": "everyday"}}),
            "passkeys": account_guidance(),
        },
    }
    line = prevention_evidence_line(data)
    assert "experience everyday" in line
    assert "denylist off" in line
    assert "CLOSE_PROCESS user-approved" in line
    assert "passkeys RP-scoped" in line
    assert "no phishing-impossible badge" in line
    assert "no account automation" in line


def test_p5_sources_do_not_add_forbidden_mutators() -> None:
    text = "\n".join(path.read_text(encoding="utf-8") for path in P5_SOURCES)
    lowered = text.lower()
    for banned in (
        "exclusionpath",
        "add-mppreference",
        "set-mppreference",
        "new-netfirewallrule",
        "api.github.com",
        "selenium",
        "playwright",
        "webbrowser",
        "windowssandbox.exe",
    ):
        assert banned not in lowered
    assert "def open_unfamiliar" not in text
    claims = (ROOT / "docs" / "CLAIMS.md").read_text(encoding="utf-8")
    assert "UNCHECKED" in claims
    assert "verify_runtime" in claims
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "docs/CLAIMS.md" in readme

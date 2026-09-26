"""Footprint tickets resolve only after a choice, and they do not invent a search."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agent.engine.footprint import collect_footprint_facts, observation_from_footprint
from agent.engine.handlers import HandlerContext
from agent.engine.loop import ResolutionEngine
from agent.engine.models import PolicyDenied
from agent.engine.service import ingest_monitors
from agent.store.db import AgentStore

NOW = "2026-09-26T18:00:00+00:00"
EMAIL = "drill-user@example.com"


def _engine(tmp_path: Path, **kwargs) -> ResolutionEngine:
    return ResolutionEngine(
        AgentStore(tmp_path / "agent.db"),
        learn_dir=tmp_path / "learn",
        log_dir=tmp_path / "logs",
        now=lambda: NOW,
        auto_enabled=kwargs.pop("auto_enabled", False),
        handler_ctx=kwargs.pop(
            "handler_ctx",
            HandlerContext(lookup=lambda _pid: None, close=lambda _pid, _name: (False, "unused")),
        ),
        **kwargs,
    )


def test_remote_hits_require_a_synthetic_fixture_and_refuse_other_people() -> None:
    assert observation_from_footprint({"kind": "breach_hit", "label": "mailbox", "target": "self"}) is None
    assert observation_from_footprint({"kind": "breach_hit", "label": "mailbox", "target": "other"}) is None
    assert observation_from_footprint({"kind": "broker_listing", "label": "someone-else", "target": "neighbor"}) is None
    drill = observation_from_footprint(
        {"kind": "breach_hit", "label": "mailbox", "target": "self", "synthetic": True}
    )
    assert drill is not None
    text = drill.title_simple + drill.why_it_matters + " ".join(drill.evidence_refs)
    assert "fixture" in text.lower() or "drill" in text.lower()
    assert EMAIL not in text
    assert "another person" in drill.why_it_matters.lower() or "someone else" in drill.why_it_matters.lower()


def test_options_before_act_and_honesty(tmp_path: Path) -> None:
    calls: list[str] = []
    ctx = HandlerContext(
        lookup=lambda _pid: None,
        close=lambda _pid, _name: (False, "unused"),
        breach_email=EMAIL,
        breach_check=lambda email: calls.append(email) or ["SyntheticDrill"],
    )
    engine = _engine(tmp_path, auto_enabled=True, handler_ctx=ctx)
    obs = observation_from_footprint({"kind": "local_residue", "label": "this-pc", "target": "self"})
    assert obs is not None
    obs.action_class = "auto_protect_eligible"
    opened = engine.evaluate(obs)
    assert opened["disposition"] == "ticket"
    assert opened["mutated"] is False
    assert calls == []
    labels = [item["label"] for item in opened["finding"]["options"]]
    for required in (
        "Start local lockdown steps",
        "Check breach (opt-in email)",
        "Open DIY opt-out",
        "Start / open partner removal or monitoring",
        "Mark resolved",
        "Still monitoring",
        "Not now",
        "Show me why",
    ):
        assert required in labels
    with pytest.raises(PolicyDenied, match="options required"):
        engine.mutate(opened["finding"]["id"], "footprint.breach_check")
    assert calls == []
    lockdown = engine.select(opened["finding"]["id"], "lockdown")
    assert lockdown["resolution_status"] == "in_progress"
    assert "did not sign you out" in lockdown["last_result"]
    assert calls == []


def test_breach_check_says_email_leaves_and_does_not_store_it(tmp_path: Path) -> None:
    calls: list[str] = []
    ctx = HandlerContext(
        lookup=lambda _pid: None,
        close=lambda _pid, _name: (False, "unused"),
        breach_check=lambda email: calls.append(email) or ["SyntheticDrill"],
    )
    engine = _engine(tmp_path, handler_ctx=ctx)
    obs = observation_from_footprint(
        {"kind": "breach_hit", "label": "mailbox", "target": "self", "synthetic": True}
    )
    opened = engine.evaluate(obs)
    held = engine.select(opened["finding"]["id"], "breach_check")
    assert calls == []
    assert "did not send" in held["last_result"].lower()
    assert held["resolution_status"] == "found"
    ctx.breach_email = EMAIL
    checked = engine.select(opened["finding"]["id"], "breach_check")
    assert calls == [EMAIL]
    assert "off this device" in checked["last_result"]
    assert "does not erase" in checked["last_result"].lower()
    assert EMAIL not in checked["last_result"]
    assert checked["resolution_status"] == "in_progress"
    stored = json.dumps(engine.store.get_finding(opened["finding"]["id"]))
    progress = (tmp_path / "learn" / "baseline_footprint.txt").read_text(encoding="utf-8")
    assert EMAIL not in stored
    assert "@" not in progress


def test_partner_playbook_and_resolved_do_not_claim_erasure(tmp_path: Path) -> None:
    engine = _engine(tmp_path)
    obs = observation_from_footprint(
        {"kind": "broker_listing", "label": "people-search", "target": "self", "synthetic": True}
    )
    opened = engine.evaluate(obs)
    partner = engine.select(opened["finding"]["id"], "partner")
    assert partner["resolution_status"] == "monitoring"
    for name in ("DeleteMe", "Incogni", "Aura", "LifeLock", "REMOVE"):
        assert name in partner["last_result"]
    assert "did not enroll" in partner["last_result"].lower()
    assert "erase" in partner["last_result"].lower()
    resolved = engine.select(opened["finding"]["id"], "mark_resolved")
    assert resolved["resolution_status"] == "resolved"
    assert "does not erase every copy" in resolved["last_result"]
    progress = (tmp_path / "learn" / "baseline_footprint.txt").read_text(encoding="utf-8")
    assert "resolved" in progress
    assert "@" not in progress


def test_tracked_item_is_not_reopened_without_a_fresh_fixture(tmp_path: Path) -> None:
    store = AgentStore(tmp_path / "agent.db")
    fact = {"kind": "public_search", "label": "own-page", "target": "self", "synthetic": True}
    first = ingest_monitors(store, footprint_facts=[fact])
    assert len(first) == 1
    assert first[0]["disposition"] == "ticket"
    engine = ResolutionEngine(
        store,
        learn_dir=tmp_path / "learn",
        log_dir=tmp_path / "logs",
        now=lambda: NOW,
        auto_enabled=False,
        handler_ctx=HandlerContext(lookup=lambda _pid: None, close=lambda _pid, _name: (False, "unused")),
    )
    engine.select(first[0]["finding"]["id"], "still_monitoring")
    again = ingest_monitors(store, footprint_facts=[fact])
    assert again == []
    fresh = ingest_monitors(store, footprint_facts=[{**fact, "fresh": True}])
    assert len(fresh) == 1
    assert fresh[0]["disposition"] == "ticket"
    assert collect_footprint_facts() == []

"""Finding 65: L2 recommendations are persisted to a durable ledger and issued
on the normal path by representative modules (security, attacks, ram). No mutation.
"""

from __future__ import annotations

import pytest

from agent.modules import ram, security
from agent.modules.prevention import parse_prevention
from agent.policy import (
    ActionKind,
    Authorization,
    LEVEL_OBSERVE,
    LEVEL_RECOMMEND,
    PolicyCortex,
    PolicyGate,
)
from agent.store.db import AgentStore


@pytest.fixture()
def store(tmp_path):
    return AgentStore(tmp_path / "agent.db")


def _issue(cortex, *, level=LEVEL_RECOMMEND, initiator="test"):
    return cortex.issue(
        action=ActionKind.RECOMMEND,
        action_level=level,
        confidence=0.8,
        evidence_summary=["evidence line"],
        authorization=Authorization.AUTOMATIC_POLICY,
        target="t",
        initiator=initiator,
        reversible=False,
    )


# ---- persistence gating ---------------------------------------------------

def test_cortex_persists_l2(store):
    cortex = PolicyCortex(store=store)
    assert _issue(cortex) is not None
    rows = [dict(r) for r in store.recent_decisions()]
    assert len(rows) == 1
    assert rows[0]["initiator"] == "test"
    assert rows[0]["action_level"] == LEVEL_RECOMMEND


def test_cortex_without_store_does_not_crash():
    assert _issue(PolicyCortex()) is not None  # no store -> no persistence, no error


def test_cortex_does_not_persist_below_l2(store):
    cortex = PolicyCortex(store=store)
    cortex.issue(
        action=ActionKind.AUDIT,
        action_level=LEVEL_OBSERVE,
        confidence=0.0,
        evidence_summary=[],
        authorization=Authorization.AUTOMATIC_POLICY,
        target="t",
        initiator="observer",
    )
    assert store.recent_decisions() == []


def test_gate_wires_store_into_cortex(store):
    gate = PolicyGate.create(store)
    _issue(gate.cortex)
    assert len(store.recent_decisions()) == 1


# ---- modules issue on the NORMAL path -------------------------------------

def test_security_recommends_on_defender_off_and_dedups(store, monkeypatch):
    from agent.edition_matrix import build_edition_matrix
    from agent.modules.defender_health import interpret_maps_output, parse_defender_status

    healthy = """STATUS:OK
AMRunningMode:Normal
AntivirusEnabled:False
RealTimeProtectionEnabled:False
AntivirusSignatureAge:1
AntivirusSignatureLastUpdated:2026-09-28
AntivirusSignatureVersion:1.2.3.4
AMEngineVersion:1.1.25000.1
AMProductVersion:4.18.25000.1
DefenderSignaturesOutOfDate:False
"""
    monkeypatch.setattr(security, "_query_defender", lambda: (False, False))
    monkeypatch.setattr(security, "_query_firewall", lambda: (True, {"domain": True, "private": True, "public": True}))
    monkeypatch.setattr(security, "_query_defender_health", lambda: parse_defender_status(healthy))
    monkeypatch.setattr(security, "_query_maps", lambda: interpret_maps_output("MAPS:RAN\nEXIT:0\nconnected\n"))
    monkeypatch.setattr(security, "_query_edition_matrix", lambda: build_edition_matrix("Home"))
    monkeypatch.setattr(
        security,
        "_query_prevention",
        lambda: parse_prevention("STATUS:ACCESS_DENIED\nDETAIL:Access is denied"),
    )
    monkeypatch.setattr(security, "_last_security_sig", None)
    cortex = PolicyCortex(store=store)

    security.SecurityMonitor(store, {}, cortex=cortex).run()
    sec = [dict(r) for r in store.recent_decisions() if dict(r)["initiator"] == "security"]
    assert len(sec) == 1
    assert sec[0]["target"] == "windows_security_posture"

    # Same posture next pulse -> no new recommendation (transition dedup).
    security.SecurityMonitor(store, {}, cortex=cortex).run()
    sec = [r for r in store.recent_decisions() if dict(r)["initiator"] == "security"]
    assert len(sec) == 1


def test_ram_recommends_on_pressure_transition(store, tmp_path, monkeypatch):
    class _VM:
        percent = 95.0
        available = 200 * 1024 * 1024
        total = 16 * 1024 ** 3

    class _Snap:
        commit_percent = 92.0  # >= 85 -> memory_under_pressure True
        source = "test"
        total_phys_bytes = 16 * 1024 ** 3
        avail_phys_bytes = 200 * 1024 * 1024

    monkeypatch.setattr(ram.psutil, "virtual_memory", lambda: _VM())
    monkeypatch.setattr(ram, "sample_memory", lambda: _Snap())
    monkeypatch.setattr(ram, "_ram_pressure_active", False)
    cortex = PolicyCortex(store=store)

    ram.RamMonitor(store, {}, tmp_path, cortex=cortex).run()
    r = [dict(x) for x in store.recent_decisions() if dict(x)["initiator"] == "ram"]
    assert len(r) == 1
    assert r[0]["target"] == "memory_pressure"

    # Still pressured next pulse -> no duplicate (once per episode).
    ram.RamMonitor(store, {}, tmp_path, cortex=cortex).run()
    r = [x for x in store.recent_decisions() if dict(x)["initiator"] == "ram"]
    assert len(r) == 1


def test_ram_no_recommend_when_healthy(store, tmp_path, monkeypatch):
    class _VM:
        percent = 40.0
        available = 8 * 1024 ** 3
        total = 16 * 1024 ** 3

    class _Snap:
        commit_percent = 30.0  # healthy: low commit
        source = "test"
        total_phys_bytes = 16 * 1024 ** 3
        avail_phys_bytes = 8 * 1024 ** 3  # ample available -> not pressure

    monkeypatch.setattr(ram.psutil, "virtual_memory", lambda: _VM())
    monkeypatch.setattr(ram, "sample_memory", lambda: _Snap())
    monkeypatch.setattr(ram, "_ram_pressure_active", False)
    cortex = PolicyCortex(store=store)

    ram.RamMonitor(store, {}, tmp_path, cortex=cortex).run()
    assert [x for x in store.recent_decisions() if dict(x)["initiator"] == "ram"] == []

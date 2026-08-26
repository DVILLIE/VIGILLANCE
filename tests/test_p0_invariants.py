"""P0 invariant tests — negative security / safety gates."""

from __future__ import annotations

from pathlib import Path

import pytest

from agent.modules.ram import AUTOMATIC_TRIM_ENABLED, RamMonitor, _trim_working_sets
from agent.net_identity import host_matches_domain, looks_like_ipv4_or_ipv6, normalize_hostname
from agent.policy import ActionExecutor, PolicyCortex
from agent.policy.cortex import LEVEL_OBSERVE, LEVEL_REVERSIBLE
from agent.store.db import AgentStore


@pytest.fixture
def store(tmp_path: Path) -> AgentStore:
    return AgentStore(tmp_path / "p0.db")


def test_fake_trim_never_succeeds() -> None:
    assert AUTOMATIC_TRIM_ENABLED is False
    assert _trim_working_sets() is False


def test_ram_monitor_ignores_enable_trim(store: AgentStore, tmp_path: Path) -> None:
    status = RamMonitor(store, {"thresholds": {"ram_critical_percent": 0.01}}, tmp_path).run(
        enable_trim=True
    )
    assert status.trimmed is False


def test_hostname_boundary_matching() -> None:
    assert host_matches_domain("api.example.com", "example.com")
    assert host_matches_domain("example.com", "example.com")
    assert not host_matches_domain("badexample.com", "example.com")
    assert not host_matches_domain("example.com.evil", "example.com")
    assert normalize_hostname("Example.COM.") == "example.com"
    assert normalize_hostname("203.0.113.1") is None
    assert looks_like_ipv4_or_ipv6("203.0.113.1")
    assert not looks_like_ipv4_or_ipv6("WIN81")


def test_executor_rejects_missing_decision(store: AgentStore) -> None:
    ex = ActionExecutor(store)
    ok, msg = ex.execute(None, lambda: (True, "should_not_run"))
    assert ok is False
    assert "REJECTED" in msg


def test_executor_rejects_incomplete_level3(store: AgentStore) -> None:
    cortex = PolicyCortex()
    # Missing rollback on reversible L3
    d = cortex.issue(
        action="RESTRICT",
        action_level=LEVEL_REVERSIBLE,
        confidence=0.9,
        evidence_summary=["e1"],
        policy="privacy",
        target="svc",
        initiator="test",
        reversible=True,
        rollback_plan=None,
    )
    assert d is None


def test_executor_accepts_valid_decision(store: AgentStore) -> None:
    cortex = PolicyCortex()
    d = cortex.issue(
        action="RESTRICT",
        action_level=LEVEL_REVERSIBLE,
        confidence=0.91,
        evidence_summary=["Delivery Optimization competing with AI"],
        policy="workload_protect",
        target="dosvc",
        initiator="test",
        reversible=True,
        rollback_plan="restore_service_start_type",
    )
    assert d is not None
    ex = ActionExecutor(store)
    called = {"n": 0}

    def mut() -> tuple[bool, str]:
        called["n"] += 1
        return True, "ok"

    ok, msg = ex.execute(d, mut, before_state="running")
    assert ok is True
    assert called["n"] == 1
    # Replay rejected
    ok2, msg2 = ex.execute(d, mut)
    assert ok2 is False
    assert "already used" in msg2


def test_observe_level_does_not_mutate(store: AgentStore) -> None:
    cortex = PolicyCortex()
    d = cortex.issue(
        action="OBSERVE",
        action_level=LEVEL_OBSERVE,
        confidence=1.0,
        evidence_summary=[],
        policy="none",
        target="n/a",
        initiator="test",
    )
    ex = ActionExecutor(store)
    ok, msg = ex.execute(d, lambda: (True, "nope"))
    assert ok is False


def test_cursor_advances_only_via_store(store: AgentStore) -> None:
    assert store.get_cursor("security_event_record_id") == 0
    store.set_cursor("security_event_record_id", 42)
    assert store.get_cursor("security_event_record_id") == 42


def test_4776_workstation_is_not_ip() -> None:
    assert not looks_like_ipv4_or_ipv6("WIN81")
    assert not looks_like_ipv4_or_ipv6("CLIENT-1")

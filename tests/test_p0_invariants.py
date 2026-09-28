"""P0 invariant tests — negative security / safety gates."""

from __future__ import annotations

from pathlib import Path
import sqlite3

import pytest

from agent.modules.ram import AUTOMATIC_TRIM_ENABLED, RamMonitor, _trim_working_sets
from agent.net_identity import host_matches_domain, looks_like_ipv4_or_ipv6, normalize_hostname
from agent.policy import (
    ActionExecutor,
    ActionKind,
    ActionRequest,
    Authorization,
    PolicyCortex,
)
from agent.policy.cortex import LEVEL_OBSERVE, LEVEL_RECOMMEND, LEVEL_REVERSIBLE, LEVEL_ADMIN
from agent.store.db import AgentStore


@pytest.fixture
def store(tmp_path: Path) -> AgentStore:
    return AgentStore(tmp_path / "p0.db")


def _restrict_decision(
    cortex: PolicyCortex,
    *,
    level: int = LEVEL_REVERSIBLE,
    confidence: float = 0.91,
    authorization: Authorization = Authorization.AUTOMATIC_POLICY,
    rollback_plan: str | None = "restore_service_start_type",
    action: ActionKind = ActionKind.RESTRICT_NETWORK,
) -> object:
    return cortex.issue(
        action=action,
        action_level=level,
        confidence=confidence,
        evidence_summary=["Delivery Optimization competing with AI"],
        authorization=authorization,
        policy_ref="workload_protect",
        target="dosvc",
        initiator="test",
        reversible=True,
        rollback_plan=rollback_plan,
    )


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
    ok, msg = ex.execute(None)
    assert ok is False
    assert "REJECTED" in msg


def test_executor_rejects_incomplete_level3(store: AgentStore) -> None:
    cortex = PolicyCortex()
    d = _restrict_decision(cortex, rollback_plan=None)
    assert d is None


def test_level2_recommend_cannot_mutate(store: AgentStore) -> None:
    """P0.0: Level 2 reaches recommend only — never the mutation path."""
    cortex = PolicyCortex()
    d = cortex.issue(
        action=ActionKind.RECOMMEND,
        action_level=LEVEL_RECOMMEND,
        confidence=0.99,
        evidence_summary=["candidate telemetry process"],
        authorization=Authorization.AUTOMATIC_POLICY,
        policy_ref="privacy_observe",
        target="DiagTrack",
        initiator="test",
        reversible=False,
    )
    assert d is not None
    called = {"n": 0}

    def boom(_req: ActionRequest) -> tuple[bool, str]:
        called["n"] += 1
        return True, "should_not_run"

    ex = ActionExecutor(store)
    # Even if someone wrongly registers a handler for a mutating kind, L2 decision must not run.
    ex.register(ActionKind.RESTRICT_NETWORK, boom)
    ok, msg = ex.execute(d)
    assert ok is False
    assert "L2=recommend only" in msg or "Level <3" in msg
    assert called["n"] == 0


def test_level2_mutating_kind_refused_at_issue() -> None:
    cortex = PolicyCortex()
    d = cortex.issue(
        action=ActionKind.RESTRICT_NETWORK,
        action_level=LEVEL_RECOMMEND,
        confidence=0.99,
        evidence_summary=["e"],
        authorization=Authorization.AUTOMATIC_POLICY,
        target="x",
        initiator="test",
        rollback_plan="undo",
    )
    assert d is None


def test_automatic_policy_cannot_authorize_admin(store: AgentStore) -> None:
    cortex = PolicyCortex()
    d = cortex.issue(
        action=ActionKind.BLOCK_IP,
        action_level=LEVEL_ADMIN,
        confidence=0.95,
        evidence_summary=["bruteforce"],
        authorization=Authorization.AUTOMATIC_POLICY,
        policy_ref="attacks",
        target="203.0.113.50",
        initiator="test",
        reversible=True,
        rollback_plan="unblock_ip",
    )
    assert d is None


def test_policy_string_is_not_authorization() -> None:
    cortex = PolicyCortex()
    d = cortex.issue(
        action=ActionKind.RESTRICT_NETWORK,
        action_level=LEVEL_REVERSIBLE,
        confidence=0.91,
        evidence_summary=["e"],
        authorization="auto_allowed",  # type: ignore[arg-type]
        target="dosvc",
        initiator="test",
        rollback_plan="undo",
    )
    assert d is None


def test_low_confidence_l3_refused() -> None:
    cortex = PolicyCortex()
    d = _restrict_decision(cortex, confidence=0.50)
    assert d is None


def test_executor_accepts_valid_decision_via_registry(store: AgentStore) -> None:
    cortex = PolicyCortex(store=store)
    d = _restrict_decision(cortex)
    assert d is not None
    ex = ActionExecutor(store)
    called: dict[str, object] = {"n": 0, "target": None}

    def mut(req: ActionRequest) -> tuple[bool, str]:
        called["n"] = int(called["n"]) + 1  # type: ignore[arg-type]
        called["target"] = req.target
        assert req.action is ActionKind.RESTRICT_NETWORK
        assert req.decision_id == d.decision_id  # type: ignore[union-attr]
        return True, "ok"

    ex.register(ActionKind.RESTRICT_NETWORK, mut)
    ok, msg = ex.execute(d, before_state="running")  # type: ignore[arg-type]
    assert ok is True
    assert called["n"] == 1
    assert called["target"] == "dosvc"
    # Replay rejected (persistent claim)
    ok2, msg2 = ex.execute(d)  # type: ignore[arg-type]
    assert ok2 is False
    assert "already used" in msg2


def test_executor_rejects_without_registered_handler(store: AgentStore) -> None:
    cortex = PolicyCortex(store=store)
    d = _restrict_decision(cortex)
    assert d is not None
    ex = ActionExecutor(store)
    ok, msg = ex.execute(d)  # type: ignore[arg-type]
    assert ok is False
    assert "no registered handler" in msg


def test_executor_rejects_arbitrary_action_string() -> None:
    cortex = PolicyCortex()
    d = cortex.issue(
        action="DELETE_SYSTEM32",
        action_level=LEVEL_REVERSIBLE,
        confidence=0.99,
        evidence_summary=["e"],
        authorization=Authorization.USER_APPROVED,
        target="C:\\",
        initiator="test",
        rollback_plan="impossible",
    )
    assert d is None


def test_replay_survives_new_executor_instance(store: AgentStore) -> None:
    cortex = PolicyCortex(store=store)
    d = _restrict_decision(cortex)
    assert d is not None

    def mut(_req: ActionRequest) -> tuple[bool, str]:
        return True, "ok"

    ex1 = ActionExecutor(store)
    ex1.register(ActionKind.RESTRICT_NETWORK, mut)
    assert ex1.execute(d)[0] is True  # type: ignore[arg-type]

    ex2 = ActionExecutor(store)
    ex2.register(ActionKind.RESTRICT_NETWORK, mut)
    ok, msg = ex2.execute(d)  # type: ignore[arg-type]
    assert ok is False
    assert "already used" in msg


def test_observe_level_does_not_mutate(store: AgentStore) -> None:
    cortex = PolicyCortex()
    d = cortex.issue(
        action=ActionKind.AUDIT,
        action_level=LEVEL_OBSERVE,
        confidence=1.0,
        evidence_summary=[],
        authorization=Authorization.AUTOMATIC_POLICY,
        target="n/a",
        initiator="test",
    )
    assert d is not None
    called = {"n": 0}

    def boom(_req: ActionRequest) -> tuple[bool, str]:
        called["n"] += 1
        return True, "nope"

    ex = ActionExecutor(store)
    ex.register(ActionKind.RESTRICT_NETWORK, boom)
    ok, _msg = ex.execute(d)
    assert ok is False
    assert called["n"] == 0


def test_cannot_register_non_mutating_handler(store: AgentStore) -> None:
    ex = ActionExecutor(store)
    with pytest.raises(ValueError):
        ex.register(ActionKind.RECOMMEND, lambda _r: (True, "nope"))


def test_user_approved_block_ip_issues(store: AgentStore) -> None:
    cortex = PolicyCortex(store=store)
    d = cortex.issue(
        action=ActionKind.BLOCK_IP,
        action_level=LEVEL_ADMIN,
        confidence=0.95,
        evidence_summary=["repeated 4625 from external IP"],
        authorization=Authorization.USER_APPROVED,
        policy_ref="attacks_block",
        target="203.0.113.50",
        initiator="test",
        reversible=True,
        rollback_plan="unblock_ip",
    )
    assert d is not None
    seen: list[str] = []

    def block(req: ActionRequest) -> tuple[bool, str]:
        seen.append(req.target)
        return True, "blocked"

    ex = ActionExecutor(store)
    ex.register(ActionKind.BLOCK_IP, block)
    ok, _ = ex.execute(d)
    assert ok is True
    assert seen == ["203.0.113.50"]


def test_handler_cannot_run_without_saved_decision(store: AgentStore, monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(_decision: dict) -> None:
        raise sqlite3.OperationalError("readonly")

    monkeypatch.setattr(store, "log_decision", boom)
    issued = _restrict_decision(PolicyCortex(store=store))
    assert issued is None
    called = {"n": 0}

    def mut(_req: ActionRequest) -> tuple[bool, str]:
        called["n"] += 1
        return True, "should_not_run"

    from agent.policy.cortex import Decision

    forged = Decision(
        decision_id="never-saved",
        finding_id=None,
        action=ActionKind.RESTRICT_NETWORK.value,
        action_level=LEVEL_REVERSIBLE,
        confidence=0.95,
        evidence_summary=["evidence"],
        authorization=Authorization.AUTOMATIC_POLICY.value,
        policy_ref="test",
        target="dosvc",
        reversible=True,
        rollback_plan="undo",
        initiator="test",
    )
    ex = ActionExecutor(store)
    ex.register(ActionKind.RESTRICT_NETWORK, mut)
    ok, msg = ex.execute(forged)
    assert ok is False
    assert called["n"] == 0
    assert "durable decision record missing" in msg


def test_cursor_advances_only_via_store(store: AgentStore) -> None:
    assert store.get_cursor("security_event_record_id") == 0
    store.set_cursor("security_event_record_id", 42)
    assert store.get_cursor("security_event_record_id") == 42


def test_4776_workstation_is_not_ip() -> None:
    assert not looks_like_ipv4_or_ipv6("WIN81")
    assert not looks_like_ipv4_or_ipv6("CLIENT-1")

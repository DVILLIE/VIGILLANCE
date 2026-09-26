"""One mutate path: keep-on token and Cortex, or nothing changes."""

from __future__ import annotations

from pathlib import Path

import pytest

from agent.engine.handlers import HandlerContext, smart_close
from agent.engine.loop import ResolutionEngine
from agent.engine.models import PolicyDenied
from agent.engine.observations import from_disk_status, from_speed_sample
from agent.modules.disk import DiskStatus
from agent.policy import ActionKind, Authorization, PolicyGate
from agent.policy.actions import USER_APPROVED_ONLY
from agent.policy.levels import LEVEL_REVERSIBLE
from agent.store.db import AgentStore


NOW = "2026-09-26T12:00:00+00:00"


def _engine(tmp_path: Path, **kwargs) -> ResolutionEngine:
    return ResolutionEngine(
        AgentStore(tmp_path / "agent.db"),
        learn_dir=tmp_path / "learn",
        log_dir=tmp_path / "logs",
        now=lambda: NOW,
        **kwargs,
    )


def test_direct_smart_close_refuses_without_cortex() -> None:
    called = {"n": 0}

    def close(pid: int, name: str):
        called["n"] += 1
        return True, "closed"

    with pytest.raises(PolicyDenied, match="Cortex"):
        smart_close(
            {"signals": {"pid": 5, "name": "notepad.exe", "path": ""}},
            HandlerContext(lookup=lambda _pid: ("notepad.exe", ""), close=close),
        )
    assert called["n"] == 0


def test_selected_close_records_cortex_and_calls_closer_once(tmp_path: Path) -> None:
    calls: list[tuple[int, str]] = []

    def close(pid: int, name: str):
        calls.append((pid, name))
        return True, "closed notepad.exe"

    engine = _engine(
        tmp_path,
        handler_ctx=HandlerContext(lookup=lambda _pid: ("notepad.exe", ""), close=close),
    )
    obs = from_speed_sample(name="notepad.exe", pid=4242, cpu_percent=80, memory_mb=200)
    assert obs is not None
    opened = engine.evaluate(obs)
    finding = engine.select(opened["finding"]["id"], "pause_close")
    assert calls == [(4242, "notepad.exe")]
    assert finding["resolution_status"] == "resolved"
    with engine.store._conn() as conn:
        audits = conn.execute("SELECT COUNT(*) AS n FROM action_audit").fetchone()["n"]
        claimed = conn.execute("SELECT COUNT(*) AS n FROM action_decisions").fetchone()["n"]
    assert audits >= 1
    assert claimed == 1


def test_user_gate_close_without_keep_on_does_not_run(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*_args, **_kwargs):
        raise AssertionError("close_pids must not run without a keep-on grant")

    monkeypatch.setattr("agent.modules.resource_advisor.close_pids", boom)
    store = AgentStore(tmp_path / "agent.db")
    gate = PolicyGate.create(store, user_actions=True)
    decision = gate.cortex.issue(
        action=ActionKind.CLOSE_PROCESS,
        action_level=LEVEL_REVERSIBLE,
        confidence=1.0,
        evidence_summary=["user confirmed"],
        authorization=Authorization.USER_APPROVED,
        target="notepad.exe",
        initiator="test",
        reversible=False,
        details={"pids": [4242], "names": ["notepad.exe"], "force": False, "keep_on_granted": True},
    )
    assert decision is not None
    ok, message = gate.executor.execute(decision)
    assert ok is False
    assert "options required" in message


def test_auto_protect_temp_still_requires_both_gates(tmp_path: Path) -> None:
    root = tmp_path / "temp"
    root.mkdir()
    cache = root / "old-cache.tmp"
    cache.write_bytes(b"abcdef")
    engine = _engine(
        tmp_path,
        auto_enabled=True,
        handler_ctx=HandlerContext(
            lookup=lambda _pid: None,
            close=lambda _pid, _name: (False, "unused"),
            temp_roots=[root],
        ),
    )
    obs = from_disk_status(DiskStatus(mount="C:", percent_used=96, free_gb=0.2, total_gb=10, low_space=True))
    result = engine.evaluate(obs)
    assert result["disposition"] == "auto_protect"
    assert result["mutated"] is True
    assert not cache.exists()


def test_close_process_stays_user_approved_only() -> None:
    assert ActionKind.CLOSE_PROCESS in USER_APPROVED_ONLY
    assert ActionKind.BLOCK_IP not in USER_APPROVED_ONLY


def test_attacks_copy_does_not_claim_live_blocks() -> None:
    text = Path("dvielle/gui/attacks_window.py").read_text(encoding="utf-8")
    assert "Blocked IPs (active now)" not in text
    assert "no gated writer" in text

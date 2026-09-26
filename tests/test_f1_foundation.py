"""F1 foundation: version, evidence, nerve, twin, memory pressure counters."""

from __future__ import annotations

import time
from pathlib import Path

from agent.evidence import Decision, Finding, Observation, why_card
from agent.nerve import Cadence, CollectorSpec, NervePlane
from agent.twin import TwinStore
from agent.version import get_version
from agent.win_memory import sample_memory


def test_version_semver_shape() -> None:
    v = get_version()
    parts = v.split(".")
    assert len(parts) >= 2
    assert all(p.isdigit() for p in parts[:2])


def test_observation_finding_decision_why() -> None:
    obs = Observation.make("memory", {"commit_percent": 82.0}, cadence="heartbeat")
    finding = Finding(
        id="f1",
        ts=obs.ts,
        finding="memory_pressure",
        entity="system",
        risk=70,
        confidence=0.9,
        impact="MEDIUM",
        workload="AI_DEVELOPMENT",
        evidence_ids=[obs.id],
        reason="Commit high under AI workload",
    )
    decision = Decision(
        id="d1",
        ts=obs.ts,
        finding_id=finding.id,
        recommended_action="RECOMMEND",
        action_level=2,
        confidence=0.9,
        reversible=True,
        rollback_token="tok",
        reason=finding.reason,
        evidence_summary=["Commit pressure elevated"],
    )
    card = why_card(decision, finding)
    assert card["decision"] == "RECOMMEND"
    assert card["rollback"] == "Available"
    assert card["confidence"] == 0.9


def test_nerve_per_collector_cadence() -> None:
    ran: list[str] = []
    nerve = NervePlane()
    nerve.register(
        CollectorSpec(
            name="hb",
            cadence=Cadence.HEARTBEAT,
            interval_seconds=0.05,
            run=lambda: ran.append("hb"),
        )
    )
    nerve.register(
        CollectorSpec(
            name="pulse",
            cadence=Cadence.PULSE,
            interval_seconds=10.0,
            run=lambda: ran.append("pulse"),
            defer_under_maximum_workload=True,
        )
    )
    nerve.workload_maximum = True
    time.sleep(0.06)
    due_names = [c.name for c in nerve.due()]
    assert "hb" in due_names
    assert "pulse" not in due_names
    nerve.run_due()
    assert "hb" in ran
    assert "pulse" not in ran


def test_twin_memory_update(tmp_path: Path) -> None:
    twin = TwinStore(tmp_path / "twin.jsonl")
    snap = twin.update_memory(sample_memory())
    assert snap.total_phys_bytes > 0
    assert snap.avail_phys_bytes >= 0
    data = twin.snapshot()
    assert "memory" in data
    assert data["memory"]["source"] in (
        "GetPerformanceInfo+MEMORYSTATUSEX",
        "MEMORYSTATUSEX",
        "psutil",
        "partial",
    )
    assert (tmp_path / "twin.jsonl").exists()

"""C1: gated Smart Close — USER_APPROVED CLOSE_PROCESS, PID-scoped, protected-safe.

These lock the safety contract the GUI relies on:
- the autonomous gate can never close a process (empty registry, no auth path);
- CLOSE_PROCESS is refused unless authorization is USER_APPROVED;
- close_pids targets an explicit PID set, refuses protected targets, and never
  terminates a protected child;
- graceful first: with force=False and no graceful exit, nothing is terminated.
"""

from __future__ import annotations

import os
import time

import psutil
import pytest

from agent.modules import resource_advisor as ra
from agent.policy import (
    ActionKind,
    Authorization,
    Decision,
    LEVEL_ADMIN,
    LEVEL_RECOMMEND,
    LEVEL_REVERSIBLE,
    PolicyGate,
)
from agent.store.db import AgentStore


@pytest.fixture()
def store(tmp_path):
    return AgentStore(tmp_path / "agent.db")


# ---- gate wiring ---------------------------------------------------------

def test_autonomous_gate_has_empty_registry(store):
    gate = PolicyGate.create(store)
    assert gate.executor.registry.registered() == frozenset()


def test_user_gate_registers_only_close_process(store):
    gate = PolicyGate.create(store, user_actions=True)
    assert gate.executor.registry.registered() == frozenset({ActionKind.CLOSE_PROCESS})


# ---- authorization gating (USER_APPROVED only) ---------------------------

@pytest.mark.parametrize("auth", [Authorization.AUTOMATIC_POLICY, Authorization.EMERGENCY_POLICY])
def test_issue_close_process_refused_without_user_approval(store, auth):
    gate = PolicyGate.create(store, user_actions=True)
    decision = gate.cortex.issue(
        action=ActionKind.CLOSE_PROCESS,
        action_level=LEVEL_REVERSIBLE,
        confidence=1.0,
        evidence_summary=["x"],
        authorization=auth,
        target="t",
        initiator="test",
        reversible=False,
    )
    assert decision is None


def test_issue_close_process_allowed_with_user_approval(store):
    gate = PolicyGate.create(store, user_actions=True)
    decision = gate.cortex.issue(
        action=ActionKind.CLOSE_PROCESS,
        action_level=LEVEL_REVERSIBLE,
        confidence=1.0,
        evidence_summary=["user confirmed"],
        authorization=Authorization.USER_APPROVED,
        target="t",
        initiator="test",
        reversible=False,
        details={"pids": [999999999], "names": ["ghost.exe"], "force": False},
    )
    assert decision is not None
    assert decision.action == ActionKind.CLOSE_PROCESS.value


def test_execute_rejects_hand_built_automatic_close(store):
    """Defense in depth: even a forged AUTOMATIC_POLICY Decision is rejected at execute."""
    gate = PolicyGate.create(store, user_actions=True)
    forged = Decision(
        decision_id="forged-1",
        finding_id=None,
        action=ActionKind.CLOSE_PROCESS.value,
        action_level=LEVEL_REVERSIBLE,
        confidence=1.0,
        evidence_summary=["x"],
        authorization=Authorization.AUTOMATIC_POLICY.value,
        policy_ref="",
        target="t",
        reversible=False,
        rollback_plan=None,
        initiator="test",
        details={"pids": [999999999]},
    )
    ok, msg = gate.executor.execute(forged)
    assert ok is False
    assert "USER_APPROVED" in msg


def test_user_approved_decision_cannot_execute_on_autonomous_gate(store):
    """A valid USER_APPROVED close cannot run where no handler is registered."""
    user_gate = PolicyGate.create(store, user_actions=True)
    auto_gate = PolicyGate.create(store)
    decision = user_gate.cortex.issue(
        action=ActionKind.CLOSE_PROCESS,
        action_level=LEVEL_REVERSIBLE,
        confidence=1.0,
        evidence_summary=["user confirmed"],
        authorization=Authorization.USER_APPROVED,
        target="t",
        initiator="test",
        reversible=False,
        details={"pids": [999999999]},
    )
    ok, msg = auto_gate.executor.execute(decision)
    assert ok is False
    assert "no registered handler" in msg


def test_execute_writes_evidence_ledger(store):
    gate = PolicyGate.create(store, user_actions=True)
    decision = gate.cortex.issue(
        action=ActionKind.CLOSE_PROCESS,
        action_level=LEVEL_REVERSIBLE,
        confidence=1.0,
        evidence_summary=["user confirmed"],
        authorization=Authorization.USER_APPROVED,
        target="t",
        initiator="mission_console_user",
        reversible=False,
        details={"pids": [999999999], "names": ["ghost.exe"], "force": False},
    )
    gate.executor.execute(decision)
    with store._conn() as conn:
        decs = conn.execute("SELECT COUNT(*) FROM action_decisions").fetchone()[0]
        aud = conn.execute("SELECT COUNT(*) FROM action_audit").fetchone()[0]
    assert decs == 1
    assert aud >= 1


# ---- close_pids primitive ------------------------------------------------

def test_close_pids_empty_is_rejected():
    ok, msg = ra.close_pids([])
    assert ok is False
    assert "No target" in msg


def test_close_pids_ghost_pid_is_noop():
    ok, msg = ra.close_pids([999999999])
    assert ok is True
    assert "closed" in msg.lower()


def test_close_pids_refuses_protected_target():
    """This interpreter (python.exe) is SYSTEM_PROTECTED — must never be closed."""
    assert "python.exe" in ra.SYSTEM_PROTECTED
    for force in (False, True):
        ok, msg = ra.close_pids([os.getpid()], ["python.exe"], force=force)
        assert ok is False
        assert "protected" in msg.lower()
    # And we are obviously still running.
    assert psutil.pid_exists(os.getpid())


class _FakeProc:
    def __init__(self, pid, name, children=None, parents=None, created=100.0):
        self.pid = pid
        self._name = name
        self._children = children or []
        self._parents = parents or []
        self.created = created
        self._alive = True
        self.terminated = False

    def name(self):
        return self._name

    def children(self, recursive=False):
        return list(self._children)

    def parents(self):
        return list(self._parents)

    def create_time(self):
        return self.created

    def exe(self):
        return "C:\\Apps\\" + self._name

    def is_running(self):
        return self._alive

    def status(self):
        return "running"

    def terminate(self):
        self.terminated = True
        self._alive = False


def test_close_pids_skips_protected_children(monkeypatch):
    """A protected process hanging under a target must not be terminated."""
    parent = _FakeProc(1000, "myapp.exe")
    prot_child = _FakeProc(1001, "svchost.exe")  # SYSTEM_PROTECTED
    ok_child = _FakeProc(1002, "myapp_helper.exe")
    parent._children = [prot_child, ok_child]
    registry = {1000: parent, 1001: prot_child, 1002: ok_child}

    def fake_process(pid):
        if pid in registry:
            return registry[pid]
        raise psutil.NoSuchProcess(pid)

    monkeypatch.setattr(ra.psutil, "Process", fake_process)
    monkeypatch.setattr(ra.psutil, "wait_procs", lambda procs, timeout=0: ([], []))
    monkeypatch.setattr(ra, "_post_wm_close", lambda pids, validate=None: False)
    monkeypatch.setattr(ra, "get_foreground_process", lambda: (9000, "foreground.exe"))

    ok, msg = ra.close_pids([1000], ["myapp.exe"], force=True,
                            identities=[ra._identity(parent)], observed_at=time.time())
    assert ok is True
    assert parent.terminated is True
    assert ok_child.terminated is True
    assert prot_child.terminated is False  # protected child was skipped
    assert "protected" in msg.lower()


def test_close_pids_graceful_no_force_does_not_terminate(monkeypatch):
    """force=False + no graceful exit => report, but never TerminateProcess."""
    proc = _FakeProc(2000, "editor.exe")
    monkeypatch.setattr(
        ra.psutil, "Process", lambda pid: proc if pid == 2000 else (_ for _ in ()).throw(psutil.NoSuchProcess(pid))
    )
    monkeypatch.setattr(ra.psutil, "wait_procs", lambda procs, timeout=0: ([], []))
    monkeypatch.setattr(ra, "_post_wm_close", lambda pids, validate=None: False)
    monkeypatch.setattr(ra, "get_foreground_process", lambda: (9000, "foreground.exe"))

    ok, msg = ra.close_pids([2000], ["editor.exe"], force=False,
                            identities=[ra._identity(proc)], observed_at=time.time())
    assert ok is False
    assert proc.terminated is False  # nothing killed without an explicit force confirm
    assert "force close" in msg.lower()


def _wire_processes(monkeypatch, registry):
    def resolve(pid):
        if pid not in registry:
            raise psutil.NoSuchProcess(pid)
        return registry[pid]
    monkeypatch.setattr(ra.psutil, "Process", resolve)
    monkeypatch.setattr(ra.psutil, "wait_procs", lambda *args, **kwargs: ([], []))
    monkeypatch.setattr(ra, "get_foreground_process", lambda: (9000, "foreground.exe"))
    monkeypatch.setattr(ra, "_post_wm_close", lambda *args: False)


@pytest.mark.parametrize("identity,stamp", [(None, 0), (None, None), ("old", "now"), ("valid", 0)])
def test_close_rejects_missing_changed_or_expired_identity(monkeypatch, identity, stamp):
    proc = _FakeProc(3000, "editor.exe", created=200.0)
    _wire_processes(monkeypatch, {proc.pid: proc})
    expected = ra._identity(proc)
    if identity == "old":
        expected["create_time"] = 100.0
    ok, reason = ra.close_pids([proc.pid], force=True,
        identities=[expected] if identity else None,
        observed_at=time.time() if stamp == "now" else stamp)
    assert not ok
    assert not proc.terminated
    assert "identity" in reason or "expired" in reason


def test_close_protects_differently_named_descendant_of_never_close(monkeypatch):
    protected = _FakeProc(4000, "important.exe")
    child = _FakeProc(4001, "helper.exe", parents=[protected])
    _wire_processes(monkeypatch, {4000: protected, 4001: child})
    ok, reason = ra.close_pids([child.pid], force=True, identities=[ra._identity(child)],
        observed_at=time.time(), never_close=frozenset({"important.exe"}))
    assert not ok and "protected" in reason
    assert not child.terminated


def test_force_revalidates_pid_after_graceful_attempt(monkeypatch):
    original = _FakeProc(5000, "worker.exe", created=100.0)
    replacement = _FakeProc(5000, "worker.exe", created=200.0)
    registry = {5000: original}
    _wire_processes(monkeypatch, registry)
    def graceful(*args):
        registry[5000] = replacement
        return False
    monkeypatch.setattr(ra, "_post_wm_close", graceful)
    ok, _ = ra.close_pids([5000], force=True, identities=[ra._identity(original)], observed_at=time.time())
    assert not ok
    assert not original.terminated and not replacement.terminated


def test_force_rechecks_foreground_family_after_graceful_attempt(monkeypatch):
    target = _FakeProc(6000, "whatsapp.host.exe")
    _wire_processes(monkeypatch, {6000: target})
    def graceful(*args):
        monkeypatch.setattr(ra, "get_foreground_process", lambda: (6001, "whatsapp.exe"))
        return False
    monkeypatch.setattr(ra, "_post_wm_close", graceful)
    ok, _ = ra.close_pids([6000], force=True, identities=[ra._identity(target)], observed_at=time.time())
    assert not ok
    assert not target.terminated

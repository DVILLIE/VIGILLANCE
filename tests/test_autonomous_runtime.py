"""Regression tests for ownership, failure isolation and measured deferral.

All providers are local fixtures; no real Windows security settings are changed.
"""
from datetime import datetime, timedelta, timezone
from pathlib import Path
import json
import subprocess
import sys
import threading
import time

import pytest

from agent.nerve import Cadence, CollectorSpec, CollectionIncomplete, NervePlane
from agent.ownership import RuntimeAlreadyRunning, RuntimeLease, atomic_json, read_json
from agent.twin import TwinStore
from agent.workload import WorkloadTracker


def test_slow_provider_does_not_block_heartbeat_or_duplicate_itself():
    release, entered = threading.Event(), threading.Event()
    samples, starts = [], []

    def slow():
        starts.append(1)
        entered.set()
        release.wait(2)

    plane = NervePlane(max_workers=2)
    hb = CollectorSpec('heartbeat', Cadence.HEARTBEAT, .01, run=lambda: samples.append(1))
    plane.register(hb)
    plane.register(CollectorSpec('slow', Cadence.PULSE, .01, run=slow, background=True))
    try:
        plane.run_due()
        assert entered.wait(1)
        hb.last_run_monotonic = 0
        plane.run_due()
        assert len(samples) == 2
        assert len(starts) == 1
        assert not plane.close(timeout=.01)
    finally:
        release.set()
        assert plane.close(timeout=2)


def test_optional_work_cannot_occupy_reserved_security_worker():
    release, entered = threading.Event(), threading.Event()
    plane = NervePlane(max_workers=2)
    def slow():
        entered.set()
        release.wait(2)
    plane.register(CollectorSpec('optional1', Cadence.PULSE, .01, run=slow, background=True))
    plane.register(CollectorSpec('optional2', Cadence.PULSE, .01, run=slow, background=True))
    try:
        assert plane.run_due() == ['optional1']
        assert entered.wait(1)
        critical = threading.Event()
        plane.register(CollectorSpec('security', Cadence.PULSE, .01, run=critical.set,
                                    background=True, critical=True))
        plane.run_due()
        assert critical.wait(1)
    finally:
        release.set()
        assert plane.close(2)


def test_workload_and_budget_defer_optional_not_core():
    plane = NervePlane(workload_maximum=True, idle=False)
    plane.register(CollectorSpec('security', Cadence.PULSE, 10, run=lambda: None, critical=True))
    plane.register(CollectorSpec('network', Cadence.PULSE, 10, run=lambda: None,
                                defer_under_maximum_workload=True))
    plane.register(CollectorSpec('deep', Cadence.IDLE_DEEP, 60, run=lambda: None))
    assert [c.name for c in plane.due()] == ['security']
    plane.workload_maximum, plane.idle, plane.budget_exceeded = False, True, True
    assert [c.name for c in plane.due()] == ['security']
    plane.budget_exceeded = False
    assert len(plane.due()) == 3


def test_valid_partial_collection_keeps_catchup_cadence_and_reports_gap():
    def partial():
        raise CollectionIncomplete('More source records remain')
    plane = NervePlane()
    spec = CollectorSpec('attacks', Cadence.PULSE, 30, run=partial, critical=True, failures=3)
    plane.register(spec)
    plane.run_due()
    assert spec.status == 'partial' and spec.failures == 0
    assert spec.error == 'More source records remain'
    assert plane.due(spec.last_run_monotonic + 30) == [spec]


def test_failed_provider_backoff_and_recovery():
    calls = []
    def provider():
        calls.append(1)
        if len(calls) == 1:
            raise OSError('provider unavailable')
    plane = NervePlane()
    c = CollectorSpec('provider', Cadence.PULSE, 10, run=provider)
    plane.register(c)
    plane.run_due()
    assert c.status == 'error' and c.failures == 1
    assert plane.due(now=c.last_run_monotonic + 11) == []
    c.last_run_monotonic -= 21
    plane.run_due()
    assert c.status == 'ok' and c.failures == 0 and c.error is None


@pytest.mark.parametrize('interval', [0, -1, float('nan'), float('inf')])
def test_invalid_cadence_rejected(interval):
    with pytest.raises(ValueError):
        NervePlane().register(CollectorSpec('bad', Cadence.PULSE, interval))


def test_workload_requires_sustained_cpu_and_recovers():
    tracker = WorkloadTracker({})
    def sample(cpu):
        return tracker.update(cpu, False, foreground=(None, None), inactive=200)
    assert not sample(None).idle
    assert not sample(90).maximum
    assert not sample(90).maximum
    assert sample(90).maximum
    assert sample(10).maximum
    assert sample(10).maximum
    state = sample(10)
    assert not state.maximum and state.idle
    assert tracker.update(10, True, foreground=(None, None), inactive=200).maximum


def test_owner_lock_blocks_another_process_and_releases_after_exit(tmp_path):
    code = ('import sys; from pathlib import Path; from agent.ownership import RuntimeLease; '
            'lease=RuntimeLease(Path(sys.argv[1])); lease.acquire(); '
            'print("owned",flush=True); sys.stdin.readline()')
    child = subprocess.Popen([sys.executable, '-c', code, str(tmp_path)],
                             stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
    lease = RuntimeLease(tmp_path)
    try:
        assert child.stdout.readline().strip() == 'owned'
        with pytest.raises(RuntimeAlreadyRunning):
            lease.acquire()
    finally:
        child.communicate('\n', timeout=5)
    lease.acquire()
    lease.release()


def test_stale_or_wrong_shutdown_token_cannot_stop_new_owner(tmp_path):
    with RuntimeLease(tmp_path) as lease:
        path = tmp_path / 'shutdown.json'
        atomic_json(path, {'owner_token': 'wrong', 'requested_at': datetime.now(timezone.utc).isoformat()})
        assert not lease.stop_requested()
        atomic_json(path, {'owner_token': lease.token, 'requested_at': (datetime.now(timezone.utc) - timedelta(minutes=10)).isoformat()})
        assert not lease.stop_requested()
        atomic_json(path, {'owner_token': lease.token, 'requested_at': datetime.now(timezone.utc).isoformat()})
        assert lease.stop_requested()


def test_published_twin_is_readable_and_history_bounded(tmp_path):
    path = tmp_path / 'twin.json'
    history = tmp_path / 'twin.jsonl'
    owner = TwinStore(history, latest_path=path, max_snapshot_bytes=1024)
    reader = TwinStore()
    owner.patch(runtime={'state': 'running', 'owner_token': 'one'}, memory={'source': 'test'})
    owner.publish()
    assert reader.read_published(path)
    assert reader.as_dict()['runtime']['owner_token'] == 'one'
    for _ in range(10):
        owner.snapshot()
    assert history.stat().st_size < 2048
    assert history.with_suffix('.jsonl.1').exists()
    path.write_text('{partial', encoding='utf-8')
    assert not reader.read_published(path)
    assert read_json(path) is None


def test_unknown_and_disabled_sections_not_fabricated_by_twin(tmp_path):
    twin = TwinStore(latest_path=tmp_path / 'twin.json')
    twin.patch(runtime={'state': 'starting'}, security={'defender_enabled': None})
    twin.collector_status('security', status='error', error='AccessDenied')
    twin.publish()
    data = json.loads((tmp_path / 'twin.json').read_text())
    assert data['security']['defender_enabled'] is None
    assert data['collectors']['security']['status'] == 'error'


def test_atomic_snapshot_retries_transient_windows_reader_contention(tmp_path, monkeypatch):
    from agent import ownership
    original = ownership.os.replace
    calls = []
    def contended(source, destination):
        calls.append(1)
        if len(calls) < 3:
            raise PermissionError('reader still closing')
        original(source, destination)
    monkeypatch.setattr(ownership.os, 'replace', contended)
    monkeypatch.setattr(ownership.time, 'sleep', lambda _: None)
    path = tmp_path / 'twin.json'
    atomic_json(path, {'runtime': {'state': 'running'}})
    assert len(calls) == 3
    assert read_json(path)['runtime']['state'] == 'running'

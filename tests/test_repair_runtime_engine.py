"""Regression fixtures for ownership/failure semantics, not protection efficacy tests."""
from __future__ import annotations

import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace

import pytest

from agent.engine.loop import ResolutionEngine, _append_log
from agent.engine.footprint import FootprintProgress
from agent.engine.models import PolicyDenied
from agent.engine.observations import from_disk_status, from_speed_sample
from agent.engine.service import ingest_monitors, startup_executable
from agent.learn.memory import KeepOnMemory, SafetyBaseline
from agent.local_files import file_lock
from agent.modules.disk import DiskStatus
from agent.modules.egress_watch import _attach_hosts
from agent.runtime import _collector_callbacks, _ingest_keep_on
from agent.store.db import AgentStore
from agent.twin import TwinStore


def engine_at(path):
    return ResolutionEngine(AgentStore(path / 'agent.db'), auto_enabled=False)


def observation():
    return from_speed_sample(name='FixtureApp.exe', pid=42, cpu_percent=80, memory_mb=500)


def test_parallel_observers_create_one_active_finding(tmp_path):
    engines = [engine_at(tmp_path) for _ in range(8)]
    barrier = threading.Barrier(len(engines))

    def evaluate(engine):
        barrier.wait(timeout=10)
        return engine.evaluate(observation())['finding']['id']

    with ThreadPoolExecutor(max_workers=8) as pool:
        ids = list(pool.map(evaluate, engines))
    assert len(set(ids)) == 1
    assert len(engines[0].store.list_open_findings()) == 1


def test_claim_is_atomic_and_stale_save_cannot_release_it(tmp_path):
    engine = engine_at(tmp_path)
    original = engine.evaluate(observation())['finding']
    stores = [AgentStore(tmp_path / 'agent.db') for _ in range(8)]
    with ThreadPoolExecutor(max_workers=8) as pool:
        claimed = list(pool.map(lambda store: store.claim_finding(original['id'], engine.now()), stores))
    assert sum(item is not None for item in claimed) == 1
    original['last_result'] = 'stale'
    stores[0].save_finding(original)
    assert stores[0].get_finding(original['id'])['resolution_status'] == 'in_progress'
    assert stores[0].get_finding(original['id'])['last_result'] != 'stale'


def test_stale_owner_cannot_overwrite_a_new_claim_or_its_result(tmp_path):
    engine = engine_at(tmp_path)
    finding = engine.evaluate(observation())['finding']
    first = engine.store.claim_finding(finding['id'], engine.now())
    first.update(action_claimed=False, resolution_status='found')
    assert engine.store.save_finding(first, action_owner=True)
    second = engine.store.claim_finding(finding['id'], engine.now())
    assert second['action_claim_token'] != first['action_claim_token']
    assert not engine.store.save_finding(first, action_owner=True)
    second.update(action_claimed=False, resolution_status='resolved')
    assert engine.store.save_finding(second, action_owner=True)
    assert not engine.store.save_finding(first, action_owner=True)
    assert engine.store.get_finding(finding['id'])['resolution_status'] == 'resolved'


def test_local_logging_failure_cannot_steal_later_dispatch(tmp_path, monkeypatch):
    first, second, third = engine_at(tmp_path), engine_at(tmp_path), engine_at(tmp_path)
    finding = first.evaluate(observation())['finding']
    learn = next(item['id'] for item in finding['options'] if item['effect'] == 'learn')
    action = next(item['id'] for item in finding['options'] if item.get('handler') == 'speed.pause_process')
    local_released, fail_log, dispatched, finish = [threading.Event() for _ in range(4)]

    def failed_work_log(*_args):
        local_released.set()
        assert fail_log.wait(timeout=10)
        raise OSError('fixture log unavailable after local choice completed')

    def adapter(*_args):
        dispatched.set()
        assert finish.wait(timeout=10)
        return {'performed': True, 'message': 'fixture dispatch completed'}

    monkeypatch.setattr(first.store, 'log_work', failed_work_log)
    monkeypatch.setattr(second.handlers, 'invoke', adapter)
    with ThreadPoolExecutor(max_workers=2) as pool:
        local_future = pool.submit(first.select, finding['id'], learn)
        assert local_released.wait(timeout=10)
        action_future = pool.submit(second.select, finding['id'], action)
        assert dispatched.wait(timeout=10)
        try:
            fail_log.set()
            with pytest.raises(OSError):
                local_future.result(timeout=10)
            with pytest.raises(PolicyDenied):
                third.select(finding['id'], action)
            assert third.store.get_finding(finding['id'])['action_claimed'] is True
        finally:
            finish.set()
        assert action_future.result(timeout=10)['resolution_status'] == 'resolved'


def test_competing_choices_only_dispatch_once(tmp_path, monkeypatch):
    first, second = engine_at(tmp_path), engine_at(tmp_path)
    finding = first.evaluate(observation())['finding']
    choice = next(item['id'] for item in finding['options'] if item.get('handler') == 'speed.pause_process')
    entered, release = threading.Event(), threading.Event()
    calls = []

    def adapter(*_args):
        calls.append('dispatch')
        entered.set()
        assert release.wait(timeout=10)
        return {'performed': True, 'message': 'fixture dispatch completed'}

    monkeypatch.setattr(first.handlers, 'invoke', adapter)
    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(first.select, finding['id'], choice)
        assert entered.wait(timeout=10)
        try:
            with pytest.raises(PolicyDenied):
                second.select(finding['id'], choice)
            refreshed = second.evaluate(observation())['finding']
            assert refreshed['id'] == finding['id']
            assert refreshed['resolution_status'] == 'in_progress'
        finally:
            release.set()
        assert future.result(timeout=10)['resolution_status'] == 'resolved'
    assert calls == ['dispatch']


def test_dispatch_exception_remains_reserved_for_recovery(tmp_path, monkeypatch):
    engine = engine_at(tmp_path)
    finding = engine.evaluate(observation())['finding']
    choice = next(item['id'] for item in finding['options'] if item.get('handler') == 'speed.pause_process')

    def uncertain(*_args):
        raise RuntimeError('fixture failure after dispatch')

    monkeypatch.setattr(engine.handlers, 'invoke', uncertain)
    with pytest.raises(RuntimeError):
        engine.select(finding['id'], choice)
    assert engine.store.get_finding(finding['id'])['recovery_required'] is True
    with pytest.raises(PolicyDenied):
        engine.select(finding['id'], choice)


def test_returned_unknown_outcome_is_reserved(tmp_path, monkeypatch):
    engine = engine_at(tmp_path)
    finding = engine.evaluate(observation())['finding']
    choice = next(item['id'] for item in finding['options'] if item.get('handler') == 'speed.pause_process')
    monkeypatch.setattr(engine.handlers, 'invoke', lambda *_args: {
        'performed': False, 'message': 'Fixture recovery required', 'state_unknown': True})
    result = engine.select(finding['id'], choice)
    assert result['resolution_status'] == 'in_progress'
    with pytest.raises(PolicyDenied):
        engine.select(finding['id'], choice)


def test_completed_checklist_progress_can_accept_next_choice(tmp_path, monkeypatch):
    engine = engine_at(tmp_path)
    finding = engine.evaluate(observation())['finding']
    choice = next(item['id'] for item in finding['options'] if item.get('handler') == 'speed.pause_process')
    monkeypatch.setattr(engine.handlers, 'invoke', lambda *_args: {
        'performed': False, 'message': 'Fixture checklist started', 'status': 'in_progress'})
    started = engine.select(finding['id'], choice)
    assert started['resolution_status'] == 'in_progress'
    assert started['action_claimed'] is False
    assert started['recovery_required'] is False
    why = next(item['id'] for item in started['options'] if item['effect'] == 'show_why')
    viewed = engine.select(finding['id'], why)
    assert viewed['action_claimed'] is False
    assert viewed['resolution_status'] == 'in_progress'


def test_legacy_duplicate_tickets_cannot_dispatch_concurrently(tmp_path):
    engine = engine_at(tmp_path)
    first = engine.evaluate(observation())['finding']
    duplicate = {**first, 'id': 'fixture-legacy-duplicate'}
    engine.store.save_finding(duplicate)
    assert engine.store.claim_finding(first['id'], engine.now()) is not None
    assert engine.store.claim_finding(duplicate['id'], engine.now()) is None


def test_legacy_unclassified_duplicate_blocks_new_ticket(tmp_path):
    engine = engine_at(tmp_path)
    original = engine.evaluate(observation())['finding']
    legacy = {key: value for key, value in original.items() if key not in {'action_claimed', 'recovery_required'}}
    legacy.update(id='legacy-unclassified', resolution_status='in_progress')
    engine.store.save_finding(legacy)
    assert engine.store.claim_finding(original['id'], engine.now()) is None
    assert engine.evaluate(observation())['finding']['id'] == 'legacy-unclassified'


def test_legacy_in_progress_action_requires_review(tmp_path):
    engine = engine_at(tmp_path)
    finding = engine.evaluate(observation())['finding']
    legacy = {key: value for key, value in finding.items() if key not in {'action_claimed', 'recovery_required'}}
    legacy['resolution_status'] = 'in_progress'
    engine.store.save_finding(legacy)
    assert engine.store.claim_finding(finding['id'], engine.now()) is None
    saved = engine.store.get_finding(finding['id'])
    assert saved['recovery_required'] is True
    engine.store.save_finding(finding)
    assert engine.store.get_finding(finding['id'])['recovery_required'] is True
    why = next(item['id'] for item in saved['options'] if item['effect'] == 'show_why')
    assert engine.select(finding['id'], why)['recovery_required'] is True


def test_token_refusal_before_dispatch_releases_claim(tmp_path, monkeypatch):
    engine = engine_at(tmp_path)
    finding = engine.evaluate(observation())['finding']
    choice = next(item['id'] for item in finding['options'] if item.get('handler') == 'speed.pause_process')

    def denied(*_args, **_kwargs):
        raise PolicyDenied('fixture token refused before dispatch')

    monkeypatch.setattr(engine.policy, 'issue', denied)
    with pytest.raises(PolicyDenied):
        engine.select(finding['id'], choice)
    saved = engine.store.get_finding(finding['id'])
    assert saved['action_claimed'] is False
    assert saved['recovery_required'] is False
    assert saved['resolution_status'] == 'found'


def test_auto_failure_wrapped_as_denial_does_not_retry(tmp_path, monkeypatch):
    engine = ResolutionEngine(AgentStore(tmp_path / 'agent.db'), auto_enabled=True)
    calls = []

    def uncertain(*_args):
        calls.append('dispatch')
        raise PolicyDenied('fixture executor wrapped a failed mutator')

    monkeypatch.setattr(engine.handlers, 'invoke', uncertain)
    obs = from_disk_status(DiskStatus(mount='C:', percent_used=96, free_gb=.2, total_gb=10, low_space=True))
    result = engine.evaluate(obs)
    assert result['disposition'] == 'error'
    assert result['mutated'] is None
    assert result['finding']['resolution_status'] == 'in_progress'
    assert engine.evaluate(obs)['finding']['resolution_status'] == 'in_progress'
    assert calls == ['dispatch']


def test_auto_rechecks_eligibility_of_the_claimed_snapshot(tmp_path, monkeypatch):
    engine = ResolutionEngine(AgentStore(tmp_path / 'agent.db'), auto_enabled=True)
    issue = engine.policy.issue
    calls = []

    def changed_before_claim(finding_id, handler, **kwargs):
        token = issue(finding_id, handler, **kwargs)
        changed = engine.store.get_finding(finding_id)
        changed['action_class'] = 'ask_user'
        changed['updated_at'] = engine.now()
        engine.store.stage_finding(changed)
        return token

    monkeypatch.setattr(engine.policy, 'issue', changed_before_claim)
    monkeypatch.setattr(engine.handlers, 'invoke', lambda *_args: calls.append('dispatch') or {
        'performed': True, 'message': 'fixture dispatch'})
    obs = from_disk_status(DiskStatus(mount='C:', percent_used=96, free_gb=.2, total_gb=10, low_space=True))
    result = engine.evaluate(obs)
    assert result['mutated'] is False
    assert result['finding']['action_class'] == 'ask_user'
    assert calls == []
    assert engine.store.get_finding(result['finding']['id'])['action_claimed'] is False


def test_refresh_updates_decision_fields(tmp_path):
    engine = engine_at(tmp_path)
    obs = observation()
    original = engine.evaluate(obs)['finding']
    obs.severity, obs.confidence, obs.why_it_matters = 'high', 'medium', 'Updated evidence'
    updated = engine.evaluate(obs)['finding']
    assert updated['id'] == original['id']
    assert (updated['severity'], updated['confidence'], updated['why_it_matters']) == ('high', 'medium', 'Updated evidence')


def test_keep_on_updates_merge_across_real_processes(tmp_path):
    worker = tmp_path / 'worker.py'
    worker.write_text(
        "import sys\nfrom pathlib import Path\nfrom agent.learn.memory import KeepOnMemory\n"
        "memory=KeepOnMemory(Path(sys.argv[1]))\n"
        "for i in range(8): memory.set('speed', sys.argv[2]+str(i), 'allow', '2026-10-09T00:00:00+00:00')\n",
        encoding='utf-8',
    )
    # -c imports from the current checkout rather than the worker's temp folder.
    processes = [subprocess.Popen([sys.executable, '-B', '-c', worker.read_text(encoding='utf-8'),
                                    str(tmp_path / 'learn'), prefix], stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, text=True)
                 for prefix in ('one', 'two')]
    for proc in processes:
        _out, err = proc.communicate(timeout=30)
        assert proc.returncode == 0, err
    memory = KeepOnMemory(tmp_path / 'learn')
    assert len(memory.records) == 16
    stale = KeepOnMemory(tmp_path / 'learn')
    memory.set('speed', 'new', 'deny', '2026-10-09T00:00:00+00:00')
    assert stale.get('speed', 'new').decision == 'deny'


def test_first_baseline_cannot_be_overwritten_by_stale_instance(tmp_path):
    first, stale = SafetyBaseline(tmp_path / 'baseline'), SafetyBaseline(tmp_path / 'baseline')
    first.seed([('startup:a', 'C:\\a.exe')], 'now')
    stale.seed([('startup:b', 'C:\\b.exe')], 'later')
    assert stale.items == {'startup:a': 'C:\\a.exe'}


def test_footprint_updates_merge_and_readers_refresh(tmp_path):
    first, stale = FootprintProgress(tmp_path / 'progress'), FootprintProgress(tmp_path / 'progress')
    first.record('self:first', 'resolved', 'now')
    stale.record('self:second', 'monitoring', 'later')
    assert stale.get('self:first') == 'resolved'
    assert first.get('self:second') == 'monitoring'


def test_mirror_failure_preserves_saved_decision_and_finishes_card(tmp_path, monkeypatch):
    import agent.learn.memory as module

    real_atomic = module._atomic

    def fail_mirror(path, text):
        if path.name == 'speed_allow.txt':
            raise OSError('fixture mirror unavailable')
        real_atomic(path, text)

    monkeypatch.setattr(module, '_atomic', fail_mirror)
    engine = engine_at(tmp_path)
    finding = engine.evaluate(observation())['finding']
    option = next(item['id'] for item in finding['options'] if item['effect'] == 'learn')
    result = engine.select(finding['id'], option)
    assert result['resolution_status'] != 'in_progress'
    assert engine.memory.get('speed', observation().subject_identity) is not None
    assert engine.memory.mirror_errors == ['speed_allow.txt']
    assert 'decision was saved' in result['last_result']


def test_file_lock_timeout_includes_thread_contention(tmp_path):
    entered, release = threading.Event(), threading.Event()

    def holder():
        with file_lock(tmp_path / 'lock'):
            entered.set()
            assert release.wait(timeout=10)

    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(holder)
        assert entered.wait(timeout=10)
        try:
            with pytest.raises(TimeoutError):
                with file_lock(tmp_path / 'lock', timeout=.03):
                    pytest.fail('Acquired an occupied lock')
        finally:
            release.set()
        future.result(timeout=10)


def test_engine_logs_are_bounded_and_rotate(tmp_path):
    for _ in range(75):
        _append_log(tmp_path, 'activity', 'x' * 65536)
    files = list(tmp_path.glob('activity.txt*'))
    assert {p.name for p in files} == {'activity.txt', 'activity.txt.1', 'activity.txt.2'}
    assert all(p.stat().st_size <= 1024 * 1024 for p in files)


def test_resolver_uses_actual_wrapper_contract(monkeypatch):
    monkeypatch.setattr('agent.net_resolve.lookup', lambda ip: 'fixture.example' if ip == '1.1.1.1' else None)
    rows = [{'remote_ip': '1.1.1.1'}, {'remote_ip': '1.1.1.1'}, {'remote_ip': '8.8.8.8'}]
    _attach_hosts(rows)
    assert [row['host'] for row in rows] == ['fixture.example', 'fixture.example', '']


def test_failed_live_source_does_not_cancel_other_findings(tmp_path, monkeypatch):
    def failed():
        raise OSError('fixture source unavailable')

    monkeypatch.setattr('agent.modules.egress_watch.collect_egress_facts', failed)
    monkeypatch.setattr('agent.modules.camera_guard.collect_camera_holders', lambda: [])
    monkeypatch.setattr('agent.engine.service.collect_startup_items', lambda: [])
    security = SimpleNamespace(defender_enabled=False, realtime_protection=True, firewall_enabled=True)
    disk = DiskStatus(mount='C:', percent_used=96, free_gb=.2, total_gb=10, low_space=True)
    rows = ingest_monitors(AgentStore(tmp_path / 'agent.db'), security=security,
                           disks=[object(), disk], collect_live=True)
    assert any(row.get('source') == 'egress' and row['disposition'] == 'error' for row in rows)
    assert {row['finding']['pillar'] for row in rows if row.get('finding')} == {'safety', 'storage'}


def test_stale_sample_is_not_forwarded_and_health_is_partial(tmp_path, monkeypatch):
    captured = {}

    def ingest(_store, **kwargs):
        captured.update(kwargs)
        return []

    monkeypatch.setattr('agent.engine.service.ingest_monitors', ingest)
    observed = {'_expected_sources': {'security', 'advice'},
                '_max_ages': {'security': 10, 'advice': 10},
                '_samples': {'security': (object(), time.monotonic() - 30, True),
                             'advice': (['fresh fixture'], time.monotonic(), True)}}
    twin = TwinStore()
    problems = _ingest_keep_on(AgentStore(tmp_path / 'agent.db'), observed, twin=twin)
    assert captured['security'] is None
    assert captured['advice'] == ['fresh fixture']
    assert problems[0]['source'] == 'security'
    assert twin.as_dict()['runtime']['keep_on']['status'] == 'partial'


def test_incomplete_sample_is_not_forwarded(tmp_path, monkeypatch):
    captured = {}
    monkeypatch.setattr('agent.engine.service.ingest_monitors', lambda _store, **kwargs: captured.update(kwargs) or [])
    observed = {'_expected_sources': {'security'},
                '_samples': {'security': (object(), time.monotonic(), False)}}
    problems = _ingest_keep_on(AgentStore(tmp_path / 'agent.db'), observed)
    assert captured['security'] is None
    assert problems[0]['error'] == 'Source coverage is incomplete'


def test_failed_refresh_invalidates_prior_success(tmp_path, monkeypatch):
    class Provider:
        calls = 0

        def run(self, **_kwargs):
            self.calls += 1
            if self.calls > 1:
                raise OSError('fixture refresh failed')
            return []

    provider = Provider()
    monkeypatch.setattr('agent.runtime.ResourceAdvisor', lambda *_args, **_kwargs: provider)
    observed = {}
    callbacks = _collector_callbacks(AgentStore(tmp_path / 'agent.db'), {}, {}, tmp_path / 'telemetry',
                                     tmp_path, {'enable_toasts': False}, None, None, observed)
    callbacks['resource_advisor']()
    assert 'advice' in observed['_samples']
    with pytest.raises(OSError):
        callbacks['resource_advisor']()
    assert 'advice' not in observed['_samples']


def test_finding_preserves_sample_receipt_time(tmp_path):
    stamp = '2026-10-09T00:00:00+00:00'
    security = SimpleNamespace(defender_enabled=False, realtime_protection=True, firewall_enabled=True)
    rows = ingest_monitors(AgentStore(tmp_path / 'agent.db'), security=security, sample_times={'security': stamp})
    assert rows[0]['finding']['signals']['sample_received_at'] == stamp
    assert f'Sample received: {stamp}' in rows[0]['finding']['evidence_refs']


def test_startup_quoted_path_preserves_spaces():
    assert startup_executable('  "C:\\Program Files\\Fixture App\\fixture.exe" --tray') == r'C:\Program Files\Fixture App\fixture.exe'
    assert startup_executable('') == ''

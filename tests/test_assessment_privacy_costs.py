"""Real SQLite and process observations; fixture rows are retention contracts."""
import json
import subprocess
import sys
import time
from datetime import datetime, timedelta, timezone

import psutil
import pytest

from agent.assessment import AssessmentEngine, AssessmentScope
from agent.assessment.history import HistoryPrivacy, validate_policy
from agent.assessment.resources import ProcessTreeSampler
from agent.local_files import file_lock


def seed(engine, run_id, age, state='completed'):
    stamp = (datetime.now(timezone.utc) - timedelta(days=age)).isoformat()
    report = {'id': run_id, 'started': stamp, 'finished': stamp, 'state': state,
              'scope': {}, 'findings': [], 'observations': {}, 'coverage': [], 'mutations': []}
    engine._save(report, insert=True)
    engine._save(report)


def test_retention_default_off_and_manual_preview_is_nonmutating(tmp_path):
    engine = AssessmentEngine(tmp_path)
    seed(engine, 'old', 90)
    privacy = HistoryPrivacy(engine)
    assert privacy.policy() == {'enabled': False, 'days': 30, 'max_runs': 100}
    assert privacy.preview()['ids'] == ['old']
    assert engine.report('old')['id'] == 'old'
    with file_lock(tmp_path / 'assessment.lock'):
        assert privacy.maintain_locked(preserve_run_id='current')['deleted'] == 0
    assert engine.report('old')['id'] == 'old'


def test_policy_persistence_preview_and_delete_preserve_running(tmp_path):
    engine = AssessmentEngine(tmp_path)
    for run_id, age in [('old', 90), ('recent1', 2), ('recent2', 1), ('recent3', 0)]:
        seed(engine, run_id, age)
    seed(engine, 'running', 150, 'running')
    privacy = HistoryPrivacy(engine)
    privacy.set_policy({'enabled': True, 'days': 30, 'max_runs': 2})
    reopened = HistoryPrivacy(AssessmentEngine(tmp_path))
    selected = reopened.preview()['ids']
    assert selected == ['old', 'recent1']
    result = reopened.delete(selected)
    assert result['deleted'] == 2 and result['secure_erasure_claimed'] is False
    assert {r['id'] for r in engine.history()} == {'recent2', 'recent3', 'running'}


def test_stale_preview_and_running_selection_are_atomic_refusals(tmp_path):
    engine = AssessmentEngine(tmp_path)
    seed(engine, 'old', 90)
    seed(engine, 'running', 100, 'running')
    privacy = HistoryPrivacy(engine)
    for selection in [['old', 'missing'], ['old', 'running']]:
        with pytest.raises(ValueError):
            privacy.delete(selection)
        assert engine.report('old')['id'] == 'old'


def test_assessment_lock_blocks_deletion_and_settings(tmp_path):
    engine = AssessmentEngine(tmp_path)
    seed(engine, 'old', 90)
    privacy = HistoryPrivacy(engine)
    with file_lock(tmp_path / 'assessment.lock'):
        with pytest.raises(TimeoutError):
            privacy.delete(['old'])
        with pytest.raises(TimeoutError):
            privacy.set_policy({'enabled': True, 'days': 30, 'max_runs': 100})
    assert engine.report('old')['id'] == 'old'


@pytest.mark.parametrize('policy', [None, {}, {'enabled': 1, 'days': 30, 'max_runs': 100},
    {'enabled': True, 'days': False, 'max_runs': 100}, {'enabled': True, 'days': -1, 'max_runs': 100},
    {'enabled': True, 'days': 30, 'max_runs': 0}, {'enabled': True, 'days': 30, 'max_runs': 100, 'path': 'outside'}])
def test_closed_policy_schema(policy):
    with pytest.raises(ValueError):
        validate_policy(policy)


def test_automatic_cleanup_preserves_current_run_after_clock_shift(tmp_path):
    engine = AssessmentEngine(tmp_path)
    seed(engine, 'current', 100)
    seed(engine, 'older', 101)
    privacy = HistoryPrivacy(engine)
    privacy.set_policy({'enabled': True, 'days': 30, 'max_runs': 1})
    with file_lock(tmp_path / 'assessment.lock'):
        assert privacy.maintain_locked(preserve_run_id='current')['deleted'] == 1
    assert engine.report('current')['id'] == 'current'


def test_delete_batch_bounded(tmp_path):
    engine = AssessmentEngine(tmp_path)
    for index in range(205):
        seed(engine, f'old-{index}', 90)
    privacy = HistoryPrivacy(engine)
    selected = privacy.preview()['ids']
    assert len(selected) == 200
    assert privacy.delete(selected)['deleted'] == 200
    assert len(engine.history()) == 5


def test_completed_run_records_real_resources_and_retains_itself(tmp_path, monkeypatch):
    engine = AssessmentEngine(tmp_path)
    seed(engine, 'old', 90)
    HistoryPrivacy(engine).set_policy({'enabled': True, 'days': 30, 'max_runs': 1})
    # Observation-body fixture keeps this retention test independent of host
    # Windows queries. The resource sampler still reads the actual process.
    monkeypatch.setattr(engine, '_local', lambda scope, stop, report: engine._checkpoint(scope, stop, report))
    report = engine.run(AssessmentScope())
    assert report['observations']['assessment_resources']['sampled_peak_rss_sum_bytes'] > 0
    assert report['history_maintenance']['deleted'] == 1
    assert [r['id'] for r in engine.history()] == [report['id']]
    assert engine.report(report['id']) == report


def test_actual_process_tree_samples_owned_child():
    child = subprocess.Popen([sys.executable, '-u', '-c',
        "import sys,time; print('ready',flush=True); sys.stdin.readline()"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
    try:
        assert child.stdout.readline().strip() == 'ready'
        sampler = ProcessTreeSampler()
        first = sampler.sample()
        time.sleep(0.04)
        second = sampler.sample()
        assert first['process_count'] >= 2
        assert first['cpu_core_percent'] is None
        assert second['rss_sum_bytes'] > 0
        assert second['elapsed_seconds'] > 0
        assert sampler.report()['sampled_peak_rss_sum_bytes'] > 0
        assert all('pid' not in s for s in sampler.report()['samples'])
    finally:
        child.communicate('\n', timeout=5)


def test_unreadable_process_is_unknown_not_zero(monkeypatch):
    def denied(*args):
        raise psutil.AccessDenied(1)
    monkeypatch.setattr(psutil, 'Process', denied)
    sampler = ProcessTreeSampler(1)
    sampler.sample()
    report = sampler.sample()
    assert report['coverage'] == 'unavailable'
    assert report['rss_sum_bytes'] is None
    assert report['cpu_core_percent'] is None
    assert report['cpu_machine_percent'] is None
    assert sampler.report()['sampled_peak_rss_sum_bytes'] is None


def test_partial_database_delete_is_rolled_back(tmp_path):
    engine = AssessmentEngine(tmp_path)
    seed(engine, 'first', 90)
    seed(engine, 'second', 91)
    with engine._conn() as conn:
        conn.execute("CREATE TRIGGER retain_second BEFORE DELETE ON runs WHEN OLD.id='second' BEGIN SELECT RAISE(IGNORE); END")
    with pytest.raises(ValueError):
        HistoryPrivacy(engine).delete(['first', 'second'])
    assert {r['id'] for r in engine.history()} == {'first', 'second'}


def test_actual_sampler_bounds_detail_and_preserves_lifetime_peak():
    sampler = ProcessTreeSampler(max_samples=2)
    observations = [sampler.sample() for _ in range(5)]
    report = sampler.report()
    assert len(report['samples']) == 2
    assert report['total_samples'] == 5
    assert report['discarded_sample_details'] == 3
    assert report['sampled_peak_rss_sum_bytes'] == max(s['rss_sum_bytes'] for s in observations)


@pytest.mark.parametrize('capacity', [True, 1, 10001, 2.0])
def test_sampler_refuses_unbounded_or_ambiguous_capacity(capacity):
    with pytest.raises(ValueError):
        ProcessTreeSampler(max_samples=capacity)

"""Actual current-process observation and explicitly labeled race fixtures."""
import os
import pytest
from agent.assessment.process_identity import observe_process


def test_actual_current_process_identity():
    observed = observe_process(os.getpid())
    assert observed['state'] == 'observed'
    assert observed['pid'] == os.getpid()
    assert observed['created_epoch_seconds'] > 0
    assert observed['name']
    assert observed['executable_image']['path'] == __import__('psutil').Process().exe()
    assert 'permission to act' in observed['meaning']


@pytest.mark.parametrize('pid', [None, False, -1, 0, '1'])
def test_missing_owner_is_not_invented(pid):
    assert observe_process(pid)['state'] == 'unavailable'


def test_reused_pid_fixture_does_not_preserve_identity(monkeypatch):
    import agent.assessment.process_identity as module
    class ProcessFixture:
        def __init__(self, created):
            self.created = created
        def create_time(self):
            return self.created
        def name(self):
            return 'fixture'
        def exe(self):
            return 'fixture.exe'
    identities = iter([ProcessFixture(1), ProcessFixture(2)])
    monkeypatch.setattr(module.psutil, 'Process', lambda pid: next(identities))
    assert observe_process(1)['state'] == 'identity_changed'

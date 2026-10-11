"""Actual read-only observation and service-error classification contracts."""
import os

import pytest

from agent.privilege.readiness import inspect_readiness


def test_actual_readiness_is_not_an_activation_or_enforcement_claim():
    report = inspect_readiness()
    assert report['mutations'] == []
    assert report['state'] in {'activation_held', 'prerequisites_observed_not_certified', 'unsupported_platform'}
    assert report['observed_at']
    if os.name == 'nt':
        assert report['holds']
        assert report['service']['state'] in {'running', 'not_running', 'not_installed', 'unavailable'}


@pytest.mark.skipif(os.name != 'nt', reason='Windows service API contract')
@pytest.mark.parametrize('windows_error,expected', [(1060, 'not_installed'), (5, 'unavailable')])
def test_service_absence_is_distinct_from_access_failure(monkeypatch, windows_error, expected):
    import pywintypes
    import win32service
    def refuse(*args):
        raise pywintypes.error(windows_error, 'OpenService', 'contract fixture')
    monkeypatch.setattr(win32service, 'OpenService', refuse)
    report = inspect_readiness()
    assert report['service']['state'] == expected
    assert report['service']['windows_error'] == windows_error
    assert report['state'] == 'activation_held'


@pytest.mark.skipif(os.name != 'nt', reason='Windows private configuration contract')
@pytest.mark.parametrize('native', [False, True])
def test_private_configuration_denial_does_not_claim_invalid_configuration(monkeypatch, native):
    import pywintypes
    from agent.privilege import service_host
    def refuse():
        if native:
            raise pywintypes.error(5, 'GetNamedSecurityInfo', 'private configuration contract fixture')
        raise PermissionError('private configuration contract fixture')
    monkeypatch.setattr(service_host, 'installed_configuration', refuse)
    report = inspect_readiness()
    assert report['installation_state']['state'] == 'not_observed_access_denied'
    assert report['release_identity']['state'] == 'not_observed_access_denied'
    assert report['state'] == 'activation_held'
    assert report['mutations'] == []

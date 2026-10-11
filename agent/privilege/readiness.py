"""Read-only installed-service readiness. No installation or elevation."""
from __future__ import annotations

import os
import platform
import sys
from datetime import datetime, timezone
from pathlib import Path

from agent.privilege.helper import _is_elevated
from agent.privilege.protected_paths import assert_protected_path

SERVICE_NAME = 'DViellePrivilegedHelper'


def inspect_readiness() -> dict:
    report = {'observed_at': datetime.now(timezone.utc).isoformat(),
              'platform': {'system': platform.system(), 'version': platform.version()},
              'elevated_session': _is_elevated(), 'mutations': [], 'holds': [],
              'claims': 'Read-only prerequisite observations; not a release or packet-containment certification.'}
    if os.name != 'nt':
        report.update(state='unsupported_platform', service={'state': 'not_applicable'})
        return report
    checks = {}
    supported_runtime = sys.version_info[:2] == (3, 14) and sys.version_info[:3] >= (3, 14, 8)
    report['runtime'] = {'python_version': platform.python_version(),
                         'privileged_helper_version_supported': supported_runtime}
    if not supported_runtime:
        report['holds'].append('Privileged helper requires validated Python 3.14.8 or newer in the 3.14 series.')
    for label, path in [('interpreter', Path(sys.executable)),
                        ('source_package', Path(__file__).resolve().parents[2])]:
        try:
            assert_protected_path(path)
            checks[label] = {'state': 'protected_acl_observed'}
        except Exception as exc:
            checks[label] = {'state': 'not_accepted', 'error_type': type(exc).__name__}
            report['holds'].append(label + ': protected ownership and writer checks did not pass.')
    report['code_path_checks'] = checks
    try:
        import pywintypes
        import win32service
    except ImportError:
        report.update(state='activation_held', service={'state': 'unavailable', 'error_type': 'ImportError'})
        report['holds'].append('Windows service observation support is unavailable.')
        return report
    manager = service = None
    try:
        manager = win32service.OpenSCManager(None, None, win32service.SC_MANAGER_CONNECT)
        service = win32service.OpenService(manager, SERVICE_NAME,
            win32service.SERVICE_QUERY_STATUS | win32service.SERVICE_QUERY_CONFIG)
        status = win32service.QueryServiceStatusEx(service)
        config = win32service.QueryServiceConfig(service)
        running = status['CurrentState'] == win32service.SERVICE_RUNNING
        system = config[7].lower() in {'localsystem', 'nt authority\\system'}
        report['service'] = {'state': 'running' if running else 'not_running',
                             'system_account_configured': system,
                             'peer_authentication': 'not_measured', 'policy_enforcement': 'not_measured'}
        if not running or not system:
            report['holds'].append('Registered helper is not running under the required configured account.')
    except pywintypes.error as exc:
        report['service'] = {'state': 'not_installed' if exc.winerror == 1060 else 'unavailable',
                             'windows_error': exc.winerror, 'policy_enforcement': 'not_measured'}
        report['holds'].append('Protected helper installation/running state is not established.')
    finally:
        if service is not None:
            win32service.CloseServiceHandle(service)
        if manager is not None:
            win32service.CloseServiceHandle(manager)
    try:
        from agent.privilege.service_host import installed_configuration
        directory, sid = installed_configuration()
        report['installation_state'] = {'state': 'protected_configuration_observed',
                                        'user_binding': 'configured_sid_not_exported'}
        from agent.privilege.release_identity import verify_installed_identity
        try:
            report['release_identity'] = verify_installed_identity(directory)
        except Exception as exc:
            report['release_identity'] = {'state': 'not_accepted', 'error_type': type(exc).__name__}
            report['holds'].append('Approved runtime identity is missing or does not match the installed inputs.')
    except Exception as exc:
        if isinstance(exc, PermissionError) or getattr(exc, 'winerror', None) == 5:
            report['installation_state'] = {
                'state': 'not_observed_access_denied',
                'user_binding': 'not_observed',
                'explanation': 'Private helper configuration is inaccessible to this observer; this does not establish invalid configuration.'}
            report['release_identity'] = {'state': 'not_observed_access_denied'}
            report['holds'].append('Private configuration and approved runtime identity require independent authenticated verification.')
        else:
            report['installation_state'] = {'state': 'not_accepted', 'error_type': type(exc).__name__}
            report['holds'].append('Protected installation-user configuration is not accepted.')
    report['state'] = 'activation_held' if report['holds'] else 'prerequisites_observed_not_certified'
    report['holds'].append('Positive native peer authentication, trusted release identity and live enforcement acceptance remain required.')
    return report

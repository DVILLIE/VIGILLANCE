"""Incomplete native results must remain unavailable rather than safe/disabled."""
import sys
from agent.modules import security
from agent.utils import run_hardened


def test_nonzero_native_exit_does_not_return_success_output():
    out, timed_out = run_hardened([sys.executable, '-c', 'print("partial"); raise SystemExit(7)'], timeout=5)
    assert out is None and not timed_out


def test_invalid_defender_boolean_remains_unknown(monkeypatch):
    monkeypatch.setattr(security, 'IS_WINDOWS', True)
    monkeypatch.setattr(security, 'run_powershell', lambda *a, **k: ('AM:\nRT:True', False))
    assert security._query_defender() == (None, True)


def test_partial_firewall_profiles_do_not_claim_all_on(monkeypatch):
    monkeypatch.setattr(security, 'IS_WINDOWS', True)
    monkeypatch.setattr(security, 'run_powershell', lambda *a, **k: ('Domain:True\nPrivate:True', False))
    enabled, _ = security._query_firewall()
    assert enabled is None


def test_complete_firewall_profiles_report_off(monkeypatch):
    monkeypatch.setattr(security, 'IS_WINDOWS', True)
    monkeypatch.setattr(security, 'run_powershell', lambda *a, **k: ('Domain:True\nPrivate:True\nPublic:False', False))
    enabled, profiles = security._query_firewall()
    assert enabled is False and len(profiles) == 3


def test_partial_firewall_still_reports_known_disabled_profile(monkeypatch):
    monkeypatch.setattr(security, 'IS_WINDOWS', True)
    monkeypatch.setattr(security, 'run_powershell', lambda *a, **k: ('Public:False', False))
    assert security._query_firewall()[0] is False

"""CapabilityReport smoke (no Admin required)."""

from agent.capability import CapState, probe_capabilities
from agent.utils import IS_WINDOWS

_VALID: set[CapState] = {"AVAILABLE", "LIMITED", "UNKNOWN", "UNAVAILABLE"}


def test_probe_capabilities_smoke() -> None:
    report = probe_capabilities(deep=False)
    assert report.tier.startswith("T")
    assert report.ram_total_gb > 0
    assert report.cpu_count >= 1
    assert report.process_visibility in _VALID
    assert report.overall_vision in _VALID
    # Unprobed Windows sensors stay UNKNOWN. Off Windows they do not exist.
    if IS_WINDOWS:
        assert report.defender == "UNKNOWN"
        assert report.firewall == "UNKNOWN"
    else:
        assert report.defender == "UNAVAILABLE"
        assert report.firewall == "UNAVAILABLE"
    d = report.to_dict()
    assert "gaps" in d
    assert d["overall_vision"] != "full"


def test_shallow_capability_never_uses_platform_wmi(monkeypatch):
    import agent.capability as capability
    def forbidden(*args, **kwargs):
        raise AssertionError('Shallow startup must not call WMI-backed platform detection')
    for name in ('platform', 'version', 'uname'):
        monkeypatch.setattr(capability.platform, name, forbidden)
    monkeypatch.setattr(capability, 'run_powershell', forbidden)
    report = capability.probe_capabilities(deep=False)
    assert report.wmi == 'UNKNOWN'
    assert 'wmi_cim_unavailable' not in report.gaps

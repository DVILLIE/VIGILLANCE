"""CapabilityReport smoke (no Admin required)."""

from agent.capability import CapState, probe_capabilities

_VALID: set[CapState] = {"AVAILABLE", "LIMITED", "UNKNOWN", "UNAVAILABLE"}


def test_probe_capabilities_smoke() -> None:
    report = probe_capabilities(deep=False)
    assert report.tier.startswith("T")
    assert report.ram_total_gb > 0
    assert report.cpu_count >= 1
    assert report.process_visibility in _VALID
    assert report.overall_vision in _VALID
    # Unprobed deep sensors must not pretend AVAILABLE
    assert report.defender == "UNKNOWN"
    assert report.firewall == "UNKNOWN"
    d = report.to_dict()
    assert "gaps" in d
    assert d["overall_vision"] != "full"

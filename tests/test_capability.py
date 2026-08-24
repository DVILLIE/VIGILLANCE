"""CapabilityReport smoke (no Admin required)."""

from agent.capability import probe_capabilities


def test_probe_capabilities_smoke() -> None:
    report = probe_capabilities(deep=False)
    assert report.tier.startswith("T")
    assert report.ram_total_gb > 0
    assert report.cpu_count >= 1
    assert report.process_visibility in ("full", "partial", "unknown")
    d = report.to_dict()
    assert "gaps" in d

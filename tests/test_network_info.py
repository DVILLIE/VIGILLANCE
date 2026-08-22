"""Tests for network info collection."""

from agent.modules.network_info import NetworkSnapshot, _is_vpn_interface, collect_network_snapshot


def test_vpn_interface_detection() -> None:
    assert _is_vpn_interface("NordLynx")
    assert _is_vpn_interface("OpenVPN TAP-Windows")
    assert not _is_vpn_interface("Ethernet")
    assert _is_vpn_interface("WireGuard Tunnel")


def test_collect_network_snapshot() -> None:
    snap = collect_network_snapshot()
    assert isinstance(snap, NetworkSnapshot)
    assert snap.hostname
    assert isinstance(snap.local_ips, list)
    assert isinstance(snap.dns_servers, list)

"""Tests for smart remote classification (LAN / CDN / unknown)."""

from agent.modules.connections import classify_remote


def test_router_is_gateway() -> None:
    kind, text, threat = classify_remote("192.168.1.1", None, "192.168.1.1", ["192.168.1.50"])
    assert kind == "router"
    assert threat is False
    assert "router" in text.lower() or "gateway" in text.lower()


def test_lan_phone_or_extender() -> None:
    kind, text, threat = classify_remote("192.168.1.42", None, "192.168.1.1", ["192.168.1.50"])
    assert kind == "lan_device"
    assert threat is False
    assert "phone" in text.lower() or "extender" in text.lower()


def test_cloudflare_cdn_not_attack() -> None:
    # 104.16.2.34 from user's Attacks Console screenshot
    kind, text, threat = classify_remote("104.16.2.34", "something.cloudflare.com", "192.168.1.1", ["192.168.1.50"])
    assert kind == "cdn_cloud"
    assert threat is False
    assert "cloudflare" in text.lower()


def test_unknown_public_is_review() -> None:
    kind, text, threat = classify_remote("93.184.216.34", None, "192.168.1.1", ["192.168.1.50"])
    assert kind == "unknown_internet"
    assert threat is True
    assert "not a typical home router" in text.lower()

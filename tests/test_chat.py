"""Tests for chat assistant."""

from agent.chat.assistant import ChatAssistant
from agent.chat.local_explainer import local_answer
from agent.chat.personas import KT, JARVIS
from agent.chat.web_lookup import needs_web_search


def test_local_ram_jarvis() -> None:
    stats = {"ram_percent": 92, "ram_available_gb": 1.2}
    ans = local_answer("how is my ram", stats, JARVIS)
    assert ans is not None
    assert "92" in ans


def test_local_ram_kt_british() -> None:
    stats = {"ram_percent": 50, "ram_available_gb": 8.0}
    ans = local_answer("memory status", stats, KT)
    assert ans is not None
    assert "50" in ans


def test_web_only_for_non_stats() -> None:
    assert needs_web_search("what is the weather in London today?")
    assert not needs_web_search("how is my vpn")


def test_assistant_local_stats() -> None:
    bot = ChatAssistant(enabled=True)
    stats = {
        "agent_started": True,
        "agent_cycles": 3,
        "cpu_percent": 40,
        "ram_percent": 70,
        "ram_available_gb": 4.5,
        "disk_percent_used": 60,
        "disk_free_gb": 120,
        "hostname": "TEST",
        "local_ips": ["192.168.1.1"],
        "public_ip": "1.2.3.4",
        "vpn_active": False,
        "vpn_name": None,
        "vpn_ip": None,
        "dns_servers": ["8.8.8.8"],
        "gateway": "192.168.1.1",
    }
    resp = bot.ask("explain my cpu", persona_id="jarvis", stats_override=stats)
    assert resp.used_local
    assert "40" in resp.text

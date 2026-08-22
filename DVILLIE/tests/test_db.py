"""Tests for AgentStore."""

from pathlib import Path

import pytest

from agent.store.db import AgentStore


@pytest.fixture
def store(tmp_path: Path) -> AgentStore:
    return AgentStore(tmp_path / "test.db")


def test_log_event(store: AgentStore) -> None:
    store.log_event("test", "INFO", "hello", {"k": "v"})
    with store._conn() as conn:
        row = conn.execute("SELECT * FROM events").fetchone()
    assert row is not None
    assert row["module"] == "test"
    assert row["message"] == "hello"


def test_failed_logon_counting(store: AgentStore) -> None:
    store.record_failed_logon(4625, "203.0.113.1", "admin", "PC")
    count = store.record_failed_logon(4625, "203.0.113.1", "admin", "PC")
    assert count == 2
    assert store.get_failed_logon_count("203.0.113.1") == 2


def test_block_ip(store: AgentStore) -> None:
    store.block_ip("198.51.100.1", "test")
    assert store.is_ip_blocked("198.51.100.1")
    assert not store.is_ip_blocked("198.51.100.2")


def test_baseline_process(store: AgentStore) -> None:
    store.update_baseline_process("chrome.exe")
    assert store.is_baseline_process("chrome.exe")
    assert store.is_baseline_process("CHROME.EXE")


def test_health_snapshot(store: AgentStore) -> None:
    store.log_health_snapshot(
        {
            "ram_percent": 55.0,
            "ram_available_mb": 4096,
            "disk_percent_used": 60.0,
            "disk_free_gb": 100.0,
            "defender_enabled": True,
            "firewall_enabled": True,
        }
    )
    with store._conn() as conn:
        row = conn.execute("SELECT * FROM health_snapshots").fetchone()
    assert row["ram_percent"] == 55.0

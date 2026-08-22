"""Tests for work log and notification policy."""

from pathlib import Path

import pytest

from agent.store.db import AgentStore
from dvielle.gui.notify_policy import (
    is_minimized_to_tray,
    set_minimized_to_tray,
    should_popup,
)
from dvielle.gui.work_log_window import format_work_log_report


@pytest.fixture
def store(tmp_path: Path) -> AgentStore:
    return AgentStore(tmp_path / "test.db")


def test_log_work_and_retrieve(store: AgentStore) -> None:
    store.log_work("OPEN", "Session started")
    store.log_work("START", "Agent started")
    rows = store.get_work_log()
    assert len(rows) == 2
    assert rows[0]["action"] == "OPEN"
    assert rows[1]["message"] == "Agent started"


def test_clear_work_log(store: AgentStore) -> None:
    store.log_work("OPEN", "one")
    store.log_work("CLOSE", "two")
    removed = store.clear_work_log()
    assert removed == 2
    assert store.get_work_log() == []


def test_log_event_mirrors_to_work_log(store: AgentStore) -> None:
    store.log_event("security", "CRITICAL", "Defender off", None)
    rows = store.get_work_log()
    assert len(rows) == 1
    assert rows[0]["action"] == "SECURITY"
    assert "Defender" in rows[0]["message"]


def test_format_work_log_report_empty() -> None:
    text = format_work_log_report([])
    assert "No work log entries yet" in text


def test_format_work_log_report_order() -> None:
    class Row:
        def __init__(self, ts: str, action: str, message: str) -> None:
            self._data = {"ts": ts, "action": action, "message": message}

        def __getitem__(self, key: str) -> str:
            return self._data[key]

    rows = [
        Row("2026-08-22T10:00:00+00:00", "OPEN", "Launched"),
        Row("2026-08-22T10:05:00+00:00", "START", "Agent on"),
    ]
    text = format_work_log_report(rows)
    assert "OPEN" in text
    assert "Total actions logged: 2" in text


def test_notify_policy_quiet_in_tray() -> None:
    set_minimized_to_tray(False)
    assert should_popup("CRITICAL") is False
    assert should_popup("WARNING") is False

    set_minimized_to_tray(True)
    assert should_popup("CRITICAL") is True
    assert should_popup("WARNING") is False
    assert is_minimized_to_tray() is True

    set_minimized_to_tray(False)

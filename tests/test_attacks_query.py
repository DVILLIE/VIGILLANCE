"""Honesty tests for Security-log query sentinels (COLLECTION_DEGRADED)."""

from __future__ import annotations

from agent.modules import attacks


def test_no_events_is_healthy_not_degraded() -> None:
    events, degraded, err = attacks._parse_security_query_stdout("NO_EVENTS|\n")
    assert events == []
    assert degraded is False
    assert err is None


def test_access_denied_is_degraded_with_clear_error() -> None:
    events, degraded, err = attacks._parse_security_query_stdout("ACCESS_DENIED|\n")
    assert events == []
    assert degraded is True
    assert err == "access_denied"


def test_query_fail_still_degraded() -> None:
    events, degraded, err = attacks._parse_security_query_stdout("QUERY_FAIL|\n")
    assert events == []
    assert degraded is True
    assert err == "Get-WinEvent failed"


def test_parses_4625_and_ignores_4776_as_ip() -> None:
    raw = "\n".join(
        [
            "4625|100|203.0.113.50|alice|WS1|-",
            "4776|101|-|bob|WS2|CLIENTBOX",
            "TRUNCATED|",
        ]
    )
    events, degraded, err = attacks._parse_security_query_stdout(raw)
    assert err is None
    assert degraded is True  # truncated
    assert len(events) == 2
    assert events[0]["source_ip"] == "203.0.113.50"
    assert events[1]["source_ip"] is None
    assert events[1]["source_host"] == "CLIENTBOX"

"""Tests for resource advisor logic."""

from agent.modules.resource_advisor import (
    ProcessFootprint,
    _build_cpu_advice,
    _build_ram_advice,
    _score_closability,
)


def test_score_closability_foreground_zero() -> None:
    assert _score_closability("chrome.exe", is_foreground=True, cpu=50, mem_mb=1000) == 0.0


def test_score_closability_background_discord() -> None:
    score = _score_closability("discord.exe", is_foreground=False, cpu=5, mem_mb=800)
    assert score > 40


def test_build_ram_advice_suggests_background() -> None:
    processes = [
        ProcessFootprint(1, "chrome.exe", 2, 2100, is_foreground=True),
        ProcessFootprint(2, "Discord.exe", 1, 800, closability=60),
        ProcessFootprint(3, "steam.exe", 0.5, 400, closability=55),
    ]
    advice = _build_ram_advice(92.0, processes)
    assert advice is not None
    assert "RAM 92%" in advice.headline
    assert "background" in advice.suggestion.lower() or "Discord" in advice.suggestion


def test_build_cpu_advice_names_culprit() -> None:
    processes = [
        ProcessFootprint(1, "obs64.exe", 45, 500, is_foreground=True),
        ProcessFootprint(2, "chrome.exe", 15, 1200, closability=50),
    ]
    advice = _build_cpu_advice(95.0, processes)
    assert advice is not None
    assert "obs64.exe" in advice.headline
    assert advice.resource == "CPU"

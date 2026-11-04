"""Defender exclusion observer — fixtures only; never adds ExclusionPath."""

import json
from pathlib import Path

from agent.engine.catalogs import options_for
from agent.engine.watch import observation_from_exclusion
from agent.modules import defender_exclusions as de


def test_parse_ok_snapshot():
    stdout = "\n".join(
        [
            "STATUS:OK",
            "PATH_COUNT:1",
            "PATH:C:\\EvilTemp",
            "PROC_COUNT:0",
            "EXT_COUNT:0",
            "DisableRealtimeMonitoring:False",
            "DisableIOAVProtection:False",
            "DisableBehaviorMonitoring:False",
        ]
    )
    snap = de.parse_exclusion_transcript(stdout)
    assert snap.coverage == "complete"
    assert snap.paths == ["C:\\EvilTemp"]
    assert snap.disable_realtime is False


def test_access_denied_partial():
    snap = de.parse_exclusion_transcript("STATUS:ACCESS_DENIED\nDETAIL:Must be an administrator\n")
    assert snap.coverage == "partial"
    assert "access denied" in snap.coverage_detail.lower()
    assert snap.paths == []


def test_diff_new_path_and_baseline(tmp_path: Path):
    snap = de.ExclusionSnapshot(
        "complete",
        "ok",
        paths=["C:\\NewExclude"],
        processes=[],
        extensions=[],
        disable_realtime=False,
        disable_ioav=False,
        disable_behavior=False,
    )
    assert de.diff_facts(None, snap) == []
    de.save_baseline(tmp_path, {"paths": [], "processes": [], "extensions": [], "disable_realtime": False})
    facts = de.diff_facts(de.load_baseline(tmp_path), snap)
    assert len(facts) == 1
    assert facts[0]["kind"] == "defender_exclusion_added"
    assert "NewExclude" in facts[0]["label"]


def test_diff_preference_weakened():
    previous = {
        "paths": [],
        "processes": [],
        "extensions": [],
        "disable_realtime": False,
        "disable_ioav": False,
        "disable_behavior": False,
    }
    snap = de.ExclusionSnapshot(
        "complete",
        "ok",
        disable_realtime=True,
        disable_ioav=False,
        disable_behavior=False,
    )
    facts = de.diff_facts(previous, snap)
    assert any(f["kind"] == "defender_preference_weakened" for f in facts)


def test_observation_catalog_and_no_exclusion_write_in_module_source():
    src = Path(de.__file__).read_text(encoding="utf-8")
    assert "Add-MpPreference" not in src
    assert "ExclusionPath" in src  # observe only
    obs = observation_from_exclusion(
        {
            "kind": "defender_exclusion_added",
            "subject": "exclusion:path:c:\\evil",
            "label": "C:\\Evil",
            "channel": "ExclusionPath",
        }
    )
    assert obs is not None and obs.kind == "defender_exclusion_added"
    opts = options_for("safety", "defender_exclusion_added")
    assert any(o.id == "open_settings" for o in opts)

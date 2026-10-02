"""Shipped defaults do not endorse another product as DVielle's brand."""

from __future__ import annotations

from pathlib import Path

import yaml

from agent.modules.connection_intel import ORG_HINTS
from agent.modules.resource_advisor import APP_FAMILIES

ROOT = Path(__file__).resolve().parents[1]

# Default-config and friendly-family names. Honest detectors may still name
# these processes and domains when explaining evidence.
FORBIDDEN_DEFAULT = {
    "cursor.exe",
    "code.exe",
    "devenv.exe",
    "pycharm.exe",
    "pycharm64.exe",
    "windsurf.exe",
    "claude.exe",
    "chatgpt.exe",
    "copilot.exe",
    "ollama.exe",
}


def test_default_protect_lists_are_empty() -> None:
    raw = yaml.safe_load((ROOT / "config" / "config.yaml").read_text(encoding="utf-8"))
    protected = [str(x).lower() for x in raw["workload"]["protected_foreground_processes"]]
    never = [str(x).lower() for x in raw["resource_advisor"]["never_close"]]
    assert protected == []
    assert never == []
    assert FORBIDDEN_DEFAULT.isdisjoint(protected)
    assert FORBIDDEN_DEFAULT.isdisjoint(never)


def test_app_families_have_no_ide_friendly_label() -> None:
    assert {key.lower() for key in APP_FAMILIES}.isdisjoint(FORBIDDEN_DEFAULT)
    for family in APP_FAMILIES.values():
        friendly = str(family.get("friendly", "")).lower()
        assert "cursor" not in friendly
        assert "claude" not in friendly
        assert "copilot" not in friendly
        assert "chatgpt" not in friendly


def test_editor_domain_is_not_a_shipped_label() -> None:
    domains = {domain for domain, _label in ORG_HINTS}
    assert "cursor.com" not in domains
    assert "openai.com" in domains


def test_editor_rules_are_not_part_of_the_product_tree() -> None:
    assert not (ROOT / ".cursor" / "rules" / "deep-web-research-first.mdc").exists()
    assert ".cursor/" in (ROOT / ".gitignore").read_text(encoding="utf-8")


def test_windows_agent_note_names_dvielle() -> None:
    text = (ROOT / "WINDOWS_SYSTEM_AGENT.md").read_text(encoding="utf-8")
    assert "cursor.com" not in text.lower()
    assert "DVielle" in text

def test_brand_icon_and_gif_paths_resolve() -> None:
    from dvielle.brand import ICON_ICO, LOGO_ANIMATED_GIF, LOGO_STILL_PNG, load_brand_pil_image

    assert ICON_ICO.is_file()
    assert LOGO_ANIMATED_GIF.is_file()
    assert LOGO_STILL_PNG.is_file()
    img = load_brand_pil_image(32)
    assert img is not None
    assert img.size == (32, 32)

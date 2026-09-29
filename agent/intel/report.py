"""Assemble a local intel report. A missing feed is intel: unavailable."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from agent.intel.abuse import abuse_view
from agent.intel.inventory import load_inventory
from agent.intel.kev import load_kev
from agent.intel.match import match_feeds
from agent.intel.osv import load_osv

ASSUMPTIONS: tuple[str, ...] = (
    "Feeds are read from local files. Fetch stays off unless a caller turns it on.",
    "A missing file is unavailable. DVielle does not invent KEV or OSV hits.",
    "Matches run only against a local inventory file the operator supplied.",
    "abuse.ch dumps are not bundled. The default report does not fetch them.",
)


def load_local_intel(directory: Path, *, abuse_enabled: bool = False) -> dict[str, Any]:
    kev = load_kev(directory / "kev.json")
    osv = load_osv(directory / "osv.json")
    inventory = load_inventory(directory / "inventory.json")
    return {
        "intel": _label(kev, osv),
        "kev": _public(kev),
        "osv": _public(osv),
        "inventory": {key: inventory[key] for key in ("state", "count", "detail")},
        "matches": match_feeds(kev, osv, inventory),
        "abuse_ch": abuse_view(enabled=abuse_enabled),
        "fetch": "off",
        "assumptions": list(ASSUMPTIONS),
    }


def _label(kev: dict[str, Any], osv: dict[str, Any]) -> str:
    states = {kev.get("state"), osv.get("state")}
    if states <= {"unavailable"}:
        return "unavailable"
    if states == {"loaded"}:
        return "loaded"
    if "loaded" in states:
        return "partial"
    return "invalid"


def _public(feed: dict[str, Any]) -> dict[str, Any]:
    hidden = {"rows"}
    return {key: value for key, value in feed.items() if key not in hidden}

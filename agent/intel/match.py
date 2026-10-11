"""Match loaded feeds to a local inventory. Unknown version compares are not hits."""

from __future__ import annotations

import re
from typing import Any

from packaging.version import InvalidVersion, Version

KEV_ASSUMPTION = (
    "KEV names a vendor and product. It does not name the installed version. "
    "A name match is a candidate, not proof this copy is exploitable."
)
OSV_ASSUMPTION = (
    "An OSV hit requires the same ecosystem and name, and either an exact versions entry "
    "or a supported ecosystem/SemVer range. Unsupported comparisons are unassessed, not negative results."
)


def match_feeds(kev: dict[str, Any], osv: dict[str, Any], inventory: dict[str, Any]) -> dict[str, Any]:
    if kev.get("state") != "loaded" and osv.get("state") != "loaded":
        return {
            "state": "unavailable",
            "hits": [],
            "detail": "No loaded feed. Matches were not invented.",
        }
    if inventory.get("state") != "loaded":
        return {
            "state": "unavailable",
            "hits": [],
            "detail": "No usable local inventory. Feed rows were not matched, and this is not a clean bill.",
        }
    hits: list[dict[str, Any]] = []
    assessments: list[dict[str, Any]] = []
    for item in inventory.get("items") or []:
        hits.extend(_kev_hits(item, kev.get("rows") or []))
        item_hits = _osv_hits(item, osv.get("rows") or [])
        hits.extend(item_hits)
        status, reason = _assessment(item, osv, item_hits)
        assessments.append({"package": item.get("name"), "ecosystem": item.get("ecosystem"),
                            "version": item.get("version"), "status": status, "reason": reason})
    detail = (
        "Compared the local inventory to the loaded feeds. "
        + ("No candidate was produced. " if not hits else "")
        + "This is not a statement that the computer is free of vulnerabilities."
    )
    return {"state": "compared", "hits": hits, "assessments": assessments, "detail": detail, "assumptions": [KEV_ASSUMPTION, OSV_ASSUMPTION]}


def _kev_hits(item: dict[str, str], rows: list[dict[str, str]]) -> list[dict[str, Any]]:
    product = _norm(item.get("product") or item.get("name"))
    vendor = _norm(item.get("vendor"))
    found: list[dict[str, Any]] = []
    for row in rows:
        if _norm(row.get("product")) != product or not product:
            continue
        row_vendor = _norm(row.get("vendorProject"))
        if vendor and row_vendor and vendor != row_vendor:
            continue
        found.append(
            {
                "feed": "kev",
                "kind": "name_candidate",
                "id": row.get("cveID"),
                "package": item.get("name"),
                "version": item.get("version"),
                "assumption": KEV_ASSUMPTION,
            }
        )
    return found


def _osv_hits(item: dict[str, str], rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    found: list[dict[str, Any]] = []
    for row in rows:
        if row.get("withdrawn"):
            continue
        for affected in row.get("affected") or []:
            if not _same_package(item, affected):
                continue
            if _version_affected(item.get("version") or "", affected) is not True:
                continue
            found.append(
                {
                    "feed": "osv",
                    "kind": "version_match",
                    "id": row.get("id"),
                    "package": item.get("name"),
                    "version": item.get("version"),
                    "assumption": OSV_ASSUMPTION,
                }
            )
            break
    return found


def _same_package(item: dict[str, str], affected: dict[str, Any]) -> bool:
    ecosystem = _norm(item.get("ecosystem"))
    if ecosystem != _norm(affected.get("ecosystem")):
        return False
    left, right = str(item.get("name") or "").strip(), str(affected.get("name") or "").strip()
    if ecosystem == "pypi":
        left, right = re.sub(r"[-_.]+", "-", left).lower(), re.sub(r"[-_.]+", "-", right).lower()
    if not left or left != right:
        return False
    # An OSV purl may be unversioned while the inventory purl includes its version.
    # Ecosystem/name are authoritative here; purl is retained as provenance.
    return True


def _assessment(item: dict[str, str], osv: dict[str, Any], hits: list[dict[str, Any]]) -> tuple[str, str]:
    if hits:
        return "affected", "Matched a loaded advisory's affected version data."
    if osv.get("state") != "loaded":
        return "unassessed", "OSV records are unavailable or invalid."
    comparisons = []
    for row in osv.get("rows") or []:
        if not row.get("withdrawn"):
            comparisons.extend(_version_affected(item.get("version") or "", affected)
                               for affected in row.get("affected") or [] if _same_package(item, affected))
    if any(value is None for value in comparisons):
        return "unassessed", "A matching advisory needs an unsupported or invalid version comparison."
    if comparisons:
        return "unaffected", "Not affected by the matching records loaded; this is not complete vulnerability coverage."
    for row in osv.get("queries") or []:
        query = row["query"]
        package = query["package"]
        if query.get("version") == item.get("version") and _same_package(item, package):
            if not row["vulnerability_ids"]:
                return "unaffected", "Completed OSV query returned no advisories at the cache retrieval time."
            return "unassessed", "Query returned advisories but their version coverage could not be established."
    return "unassessed", "This package has no matching advisory or completed query coverage."


def _version_affected(version: str, affected: dict[str, Any]) -> bool | None:
    versions = affected.get("versions") or []
    if version in versions:
        return True
    outcomes = [_range_affected(version, block, ecosystem=affected.get("ecosystem", ""))
                for block in affected.get("ranges") or []]
    if True in outcomes:
        return True
    if None in outcomes:
        return None
    if outcomes or versions:
        return False
    return None


_SEMVER = re.compile(
    r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
    r"(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?"
    r"(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?"
)


def _version_key(version: str, kind: str, ecosystem: str) -> Any:
    if not isinstance(version, str) or not version or len(version) > 256:
        return None
    if kind == "ECOSYSTEM" and ecosystem.casefold() == "pypi":
        try:
            return Version(version)
        except InvalidVersion:
            return None
    if kind != "SEMVER":
        return None
    match = _SEMVER.fullmatch(version)
    if match is None:
        return None
    major, minor, patch, prerelease, _build = match.groups()
    tokens = []
    for token in prerelease.split(".") if prerelease else []:
        if token.isdigit():
            if len(token) > 1 and token[0] == "0":
                return None
            tokens.append((0, int(token)))
        else:
            tokens.append((1, token))
    return (int(major), int(minor), int(patch), 0 if prerelease else 1, tuple(tokens))


def _range_affected(version: str, block: dict[str, Any], *, ecosystem: str = "") -> bool | None:
    """OSV sorted-events/BeforeLimits algorithm; unsupported ecosystems stay unknown."""
    kind = block.get("type")
    current = _version_key(version, kind, ecosystem)
    if current is None:
        return None
    events = block.get("events")
    if not isinstance(events, list) or not events or len(events) > 1000:
        return None
    transitions = []
    limits = []
    categories = set()
    for event in events:
        if not isinstance(event, dict) or len(event) != 1:
            return None
        category, token = next(iter(event.items()))
        if category not in {"introduced", "fixed", "last_affected", "limit"} or not isinstance(token, str):
            return None
        categories.add(category)
        if category == "limit" and token == "*":
            limits.append(True)
            continue
        before_all = category == "introduced" and token == "0"
        key = None if before_all else _version_key(token, kind, ecosystem)
        if key is None and not before_all:
            return None
        if category == "limit":
            limits.append(current < key)
        else:
            # The special introduced=0 sorts before every real ecosystem version.
            transitions.append((0 if before_all else 1, key, category))
    if "introduced" not in categories or {"fixed", "last_affected"} <= categories:
        return None
    if limits and not any(limits):
        return False
    priority = {"introduced": 0, "fixed": 1, "last_affected": 2}
    transitions.sort(key=lambda value: (value[0], value[1], priority[value[2]]))
    vulnerable = False
    for order, key, category in transitions:
        if category == "introduced" and (order == 0 or current >= key):
            vulnerable = True
        elif category == "fixed" and current >= key:
            vulnerable = False
        elif category == "last_affected" and current > key:
            vulnerable = False
    return vulnerable


def _norm(value: Any) -> str:
    if not isinstance(value, str):
        return ""
    return " ".join(value.split()).casefold()

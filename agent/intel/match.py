"""Match loaded feeds to a local inventory. Unknown version compares are not hits."""

from __future__ import annotations

from typing import Any

KEV_ASSUMPTION = (
    "KEV names a vendor and product. It does not name the installed version. "
    "A name match is a candidate, not proof this copy is exploitable."
)
OSV_ASSUMPTION = (
    "An OSV hit requires the same ecosystem and name, and either an exact versions entry "
    "or a numeric introduced/fixed range. A version that cannot be compared is not a hit."
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
    for item in inventory.get("items") or []:
        hits.extend(_kev_hits(item, kev.get("rows") or []))
        hits.extend(_osv_hits(item, osv.get("rows") or []))
    detail = (
        "Compared the local inventory to the loaded feeds. "
        + ("No candidate was produced. " if not hits else "")
        + "This is not a statement that the computer is free of vulnerabilities."
    )
    return {"state": "compared", "hits": hits, "detail": detail, "assumptions": [KEV_ASSUMPTION, OSV_ASSUMPTION]}


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
            if not _version_affected(item.get("version") or "", affected):
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
    if _norm(item.get("ecosystem")) != _norm(affected.get("ecosystem")):
        return False
    if _norm(item.get("name")) != _norm(affected.get("name")):
        return False
    item_purl = _norm(item.get("purl"))
    row_purl = _norm(affected.get("purl"))
    if item_purl and row_purl and item_purl != row_purl:
        return False
    return bool(_norm(item.get("name")))


def _version_affected(version: str, affected: dict[str, Any]) -> bool:
    if version in set(affected.get("versions") or []):
        return True
    for block in affected.get("ranges") or []:
        if _range_affected(version, block) is True:
            return True
    return False


def _range_affected(version: str, block: dict[str, Any]) -> bool | None:
    if block.get("type") not in {"ECOSYSTEM", "SEMVER"}:
        return None
    introduced: tuple[int, ...] | None = None
    fixed: tuple[int, ...] | None = None
    last_affected: tuple[int, ...] | None = None
    saw_introduced = False
    current = _numeric(version)
    if current is None:
        return None
    for event in block.get("events") or []:
        if "introduced" in event:
            saw_introduced = True
            token = str(event.get("introduced") or "")
            introduced = (0,) if token == "0" else _numeric(token)
            if token != "0" and introduced is None:
                return None
        elif "fixed" in event:
            fixed = _numeric(str(event.get("fixed") or ""))
            if fixed is None:
                return None
        elif "last_affected" in event:
            last_affected = _numeric(str(event.get("last_affected") or ""))
            if last_affected is None:
                return None
        elif "limit" in event:
            continue
    if not saw_introduced or introduced is None:
        return None
    if fixed is not None and last_affected is not None:
        return None
    if _cmp(current, introduced) < 0:
        return False
    if fixed is not None:
        return _cmp(current, fixed) < 0
    if last_affected is not None:
        return _cmp(current, last_affected) <= 0
    return None


def _numeric(version: str) -> tuple[int, ...] | None:
    text = version.strip()
    if not text or text == "*":
        return None
    parts = text.split(".")
    numbers: list[int] = []
    for part in parts:
        if not part.isdigit():
            return None
        numbers.append(int(part))
    return tuple(numbers)


def _cmp(left: tuple[int, ...], right: tuple[int, ...]) -> int:
    width = max(len(left), len(right))
    padded_left = left + (0,) * (width - len(left))
    padded_right = right + (0,) * (width - len(right))
    return (padded_left > padded_right) - (padded_left < padded_right)


def _norm(value: Any) -> str:
    if not isinstance(value, str):
        return ""
    return " ".join(value.split()).casefold()

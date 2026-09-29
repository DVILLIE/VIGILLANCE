"""OSV record loader. Apache-2.0 notices stay with the feed. No invented IDs."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

OSV_NOTICE = (
    "OSV records are Apache-2.0. "
    "Canonical license: https://github.com/ossf/osv-schema/blob/main/LICENSE. "
    "Copyright holders are those named by the OpenSSF OSV project and the record authors. "
    "DVielle does not rewrite record fields and does not claim ownership of them."
)


def load_osv(path: Path | None) -> dict[str, Any]:
    if path is None or not path.is_file():
        return _unavailable("No OSV file is present. No vulnerability IDs were invented.")
    try:
        raw = path.read_bytes()
        payload = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return _invalid("The OSV file is not UTF-8 JSON. No IDs were invented.")
    records = _collect(payload)
    kept: list[dict[str, Any]] = []
    for record in records:
        parsed = _record(record)
        if parsed is not None:
            kept.append(parsed)
    if not kept:
        return _invalid("The OSV file had no records with id and modified. No IDs were invented.")
    sidecar = _sidecar(path)
    return {
        "state": "loaded",
        "count": len(kept),
        "rows": kept,
        "license": "Apache-2.0",
        "notice": OSV_NOTICE,
        "provenance": {
            "source": "local-file",
            "path": str(path),
            "sha256": hashlib.sha256(raw).hexdigest(),
            "license": "Apache-2.0",
            "retrieved_at": sidecar.get("retrieved_at"),
            "url": sidecar.get("url") or "https://api.osv.dev/v1/querybatch",
        },
    }


def _collect(payload: Any) -> list[Any]:
    if isinstance(payload, list):
        return payload
    if not isinstance(payload, dict):
        return []
    if isinstance(payload.get("vulns"), list):
        return list(payload["vulns"])
    results = payload.get("results")
    if isinstance(results, list):
        rows: list[Any] = []
        for item in results:
            vulns = item.get("vulns") if isinstance(item, dict) else None
            if isinstance(vulns, list):
                rows.extend(vulns)
        return rows
    if isinstance(payload.get("id"), str):
        return [payload]
    return []


def _record(row: Any) -> dict[str, Any] | None:
    if not isinstance(row, dict):
        return None
    identifier = row.get("id")
    modified = row.get("modified")
    if not isinstance(identifier, str) or not identifier.strip():
        return None
    if not isinstance(modified, str) or not modified.strip():
        return None
    withdrawn = row.get("withdrawn")
    affected: list[dict[str, Any]] = []
    for item in row.get("affected") or []:
        parsed = _affected(item)
        if parsed is not None:
            affected.append(parsed)
    return {
        "id": identifier.strip(),
        "modified": modified.strip(),
        "withdrawn": withdrawn.strip() if isinstance(withdrawn, str) and withdrawn.strip() else None,
        "affected": affected,
    }


def _affected(item: Any) -> dict[str, Any] | None:
    if not isinstance(item, dict):
        return None
    package = item.get("package") if isinstance(item.get("package"), dict) else {}
    name = package.get("name")
    ecosystem = package.get("ecosystem")
    if not isinstance(name, str) or not name.strip():
        return None
    versions = [value.strip() for value in item.get("versions") or [] if isinstance(value, str) and value.strip()]
    ranges: list[dict[str, Any]] = []
    for block in item.get("ranges") or []:
        if not isinstance(block, dict):
            continue
        kind = block.get("type")
        events = block.get("events")
        if not isinstance(kind, str) or not isinstance(events, list):
            continue
        ranges.append({"type": kind, "events": [event for event in events if isinstance(event, dict)]})
    return {
        "ecosystem": ecosystem.strip() if isinstance(ecosystem, str) else "",
        "name": name.strip(),
        "purl": package.get("purl").strip() if isinstance(package.get("purl"), str) else "",
        "versions": versions,
        "ranges": ranges,
    }


def _sidecar(path: Path) -> dict[str, Any]:
    extra = path.with_name(path.name + ".provenance.json")
    if not extra.is_file():
        return {}
    try:
        payload = json.loads(extra.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return {}
    return payload if isinstance(payload, dict) else {}


def _unavailable(detail: str) -> dict[str, Any]:
    return {
        "state": "unavailable",
        "count": 0,
        "rows": [],
        "license": "Apache-2.0",
        "notice": OSV_NOTICE,
        "provenance": {"source": "absent"},
        "detail": detail,
    }


def _invalid(detail: str) -> dict[str, Any]:
    body = _unavailable(detail)
    body["state"] = "invalid"
    body["provenance"] = {"source": "local-file", "schema": "rejected"}
    return body

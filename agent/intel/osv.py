"""OSV record loader with source-specific attribution and bounded input."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from agent.intel.io import MAX_SIDECAR_BYTES, read_bounded

OSV_NOTICE = (
    "The OSV schema is Apache-2.0; aggregated advisory records retain their source-specific licenses. "
    "Schema license: https://github.com/ossf/osv-schema/blob/main/LICENSE. "
    "Source terms: https://google.github.io/osv.dev/data/. No blanket advisory license is asserted. "
    "D\'Vielle does not rewrite record fields and does not claim ownership of them."
)


def load_osv(path: Path | None) -> dict[str, Any]:
    if path is None or not path.is_file():
        return _unavailable("No OSV file is present. No vulnerability IDs were invented.")
    try:
        raw = read_bounded(path)
        payload = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeError, ValueError, RecursionError):
        return _invalid("The OSV file is not UTF-8 JSON. No IDs were invented.")
    records = _collect(payload)
    if len(records) > 2000:
        return _invalid("The OSV cache exceeds its record-count limit.")
    kept: list[dict[str, Any]] = []
    for record in records:
        try:
            parsed = _record(record)
        except (TypeError, ValueError):
            parsed = None
        if parsed is not None:
            kept.append(parsed)
        else:
            return _invalid("The OSV file contains incomplete or invalid records; summaries alone are not coverage.")
    complete = isinstance(payload, dict) and payload.get("complete") is True
    queries = payload.get("queries") if complete else []
    if complete and not _valid_queries(queries, {row["id"] for row in kept}):
        return _invalid("The OSV query coverage record is incomplete or inconsistent.")
    if not kept and not complete:
        return _invalid("The OSV file had no complete records or completed query coverage.")
    sidecar = _sidecar(path)
    return {
        "state": "loaded",
        "count": len(kept),
        "rows": kept,
        "license": "source-specific",
        "notice": OSV_NOTICE,
        "queries": queries,
        "complete": complete,
        "source_notices": [source_notice(record) for record in records],
        "provenance": {
            "source": "local-file",
            "path": str(path),
            "sha256": hashlib.sha256(raw).hexdigest(),
            "license": "source-specific",
            "retrieved_at": sidecar.get("retrieved_at") or (payload.get("retrieved_at") if isinstance(payload, dict) else None),
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
    if not isinstance(identifier, str) or not identifier.strip() or len(identifier) > 256:
        return None
    if not isinstance(modified, str) or not modified.strip():
        return None
    withdrawn = row.get("withdrawn")
    if withdrawn is not None and not isinstance(withdrawn, str):
        return None
    affected: list[dict[str, Any]] = []
    package_rows = row.get("affected") or []
    if not isinstance(package_rows, list) or len(package_rows) > 1000:
        return None
    for item in package_rows:
        parsed = _affected(item)
        if parsed is not None:
            affected.append(parsed)
        else:
            return None
    if not withdrawn and not affected:
        return None
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
    if not isinstance(name, str) or not name.strip() or len(name) > 512:
        return None
    listed_versions = item.get("versions") or []
    if not isinstance(listed_versions, list) or any(not isinstance(value, str) or not value.strip() or len(value) > 256
                                                   for value in listed_versions):
        return None
    versions = [value.strip() for value in listed_versions]
    ranges: list[dict[str, Any]] = []
    blocks = item.get("ranges") or []
    if not isinstance(blocks, list) or len(blocks) > 1000:
        return None
    for block in blocks:
        if not isinstance(block, dict):
            return None
        kind = block.get("type")
        events = block.get("events")
        if not isinstance(kind, str) or not isinstance(events, list) or not events or len(events) > 1000:
            return None
        if any(not isinstance(event, dict) or len(event) != 1
               or any(key not in {"introduced", "fixed", "last_affected", "limit"}
                      or not isinstance(value, str) or not value or len(value) > 256
                      for key, value in event.items()) for event in events):
            return None
        ranges.append({"type": kind, "events": events})
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
        payload = json.loads(read_bounded(extra, MAX_SIDECAR_BYTES).decode("utf-8"))
        if payload.get("sha256") != hashlib.sha256(read_bounded(path)).hexdigest():
            return {}
    except (OSError, UnicodeError, ValueError, AttributeError, RecursionError):
        return {}
    return payload if isinstance(payload, dict) else {}


def _unavailable(detail: str) -> dict[str, Any]:
    return {
        "state": "unavailable",
        "count": 0,
        "rows": [],
        "license": "source-specific",
        "notice": OSV_NOTICE,
        "provenance": {"source": "absent"},
        "detail": detail,
    }


def _invalid(detail: str) -> dict[str, Any]:
    body = _unavailable(detail)
    body["state"] = "invalid"
    body["provenance"] = {"source": "local-file", "schema": "rejected"}
    return body


def _valid_queries(queries: Any, identifiers: set[str]) -> bool:
    if not isinstance(queries, list) or not queries or len(queries) > 1000:
        return False
    seen = set()
    for row in queries:
        if not isinstance(row, dict) or not isinstance(row.get("query"), dict):
            return False
        query = row["query"]
        package = query.get("package")
        ids = row.get("vulnerability_ids")
        if (not isinstance(package, dict) or not isinstance(query.get("version"), str)
                or not all(isinstance(package.get(key), str) and package[key] for key in ("name", "ecosystem"))
                or not isinstance(ids, list) or any(not isinstance(key, str) or key not in identifiers for key in ids)):
            return False
        identity = (package["ecosystem"], package["name"], query["version"])
        if identity in seen:
            return False
        seen.add(identity)
    return True


def source_notice(record: dict[str, Any]) -> dict[str, Any]:
    """Preserve source identity without assigning the schema's license to data."""
    identifier = str(record.get("id") or "")
    references = record.get("references") if isinstance(record.get("references"), list) else []
    return {
        "id": identifier,
        "database_prefix": identifier.split("-", 1)[0],
        "record_url": "https://osv.dev/vulnerability/" + identifier,
        "source_references": [row["url"] for row in references if isinstance(row, dict) and isinstance(row.get("url"), str)],
        "license": "source-specific; consult originating database terms before redistribution",
        "terms_index": "https://google.github.io/osv.dev/data/",
    }

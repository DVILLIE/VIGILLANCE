"""Explicit, bounded KEV/OSV fetch; failed feeds keep their previous cache."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable
from urllib import request
from urllib.parse import quote

from agent.intel.NOTICES import write_notices
from agent.intel.inventory import load_inventory
from agent.intel.io import MAX_FEED_BYTES, publish
from agent.intel.kev import _row as kev_row
from agent.intel.osv import _record as osv_record, source_notice
from agent.intel.report import load_local_intel

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
OSV_URL = "https://api.osv.dev/v1/querybatch"
OSV_RECORD_URL = "https://api.osv.dev/v1/vulns/"
MAX_QUERIES = 1000
BATCH_SIZE = 100
MAX_PAGES = 20
MAX_RECORDS = 2000
Transport = Callable[..., tuple[int, bytes]]


def fetch_feeds(directory: Path, *, enabled: bool, transport: Transport | None) -> dict[str, Any]:
    if not enabled or transport is None:
        report = load_local_intel(directory)
        report["fetch"] = "off" if not enabled else "unavailable"
        report["detail"] = "Nothing was downloaded. Fetch is off or no transport is configured."
        return report
    directory.mkdir(parents=True, exist_ok=True)
    write_notices(directory)
    results: dict[str, str] = {}
    try:
        raw = _get(transport, KEV_URL)
        catalog = _json(raw)
        rows = catalog.get("vulnerabilities") if isinstance(catalog, dict) else None
        if not isinstance(rows, list) or not rows or len(rows) > 50000 or any(kev_row(row) is None for row in rows):
            raise ValueError("KEV response did not contain valid vulnerability rows")
        _save(directory / "kev.json", raw, KEV_URL)
        results["kev"] = "updated"
    except (OSError, ValueError, TypeError, RecursionError) as exc:
        results["kev"] = f"failed; previous cache retained: {type(exc).__name__}"
    try:
        queries = _queries(load_inventory(directory / "inventory.json"))
        if queries:
            payload = _fetch_osv(transport, queries)
            raw = json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8")
            _save(directory / "osv.json", raw, OSV_URL)
            results["osv"] = "updated"
        else:
            results["osv"] = "not queried; no usable inventory"
    except (OSError, ValueError, TypeError, RecursionError) as exc:
        results["osv"] = f"failed; previous cache retained: {type(exc).__name__}"
    report = load_local_intel(directory)
    report["fetch"] = "partial" if any(value.startswith("failed") for value in results.values()) else "opt-in"
    report["fetch_results"] = results
    report["detail"] = "Only complete, validated responses replace each feed cache. Fetch was explicitly enabled."
    return report


def _fetch_osv(transport: Transport, queries: list[dict[str, Any]]) -> dict[str, Any]:
    associations = [{"query": query, "vulnerability_ids": []} for query in queries]
    identifiers: dict[str, str] = {}
    downloaded = 0
    for offset in range(0, len(queries), BATCH_SIZE):
        pending = [(index, dict(queries[index])) for index in range(offset, min(offset + BATCH_SIZE, len(queries)))]
        seen_tokens: dict[int, set[str]] = {index: set() for index, _query in pending}
        for _page in range(MAX_PAGES):
            request_body = json.dumps({"queries": [query for _index, query in pending]}).encode("utf-8")
            raw = _get(transport, OSV_URL, body=request_body)
            downloaded += len(raw)
            if downloaded > MAX_FEED_BYTES:
                raise ValueError("OSV query responses exceeded total byte budget")
            response = _json(raw)
            rows = response.get("results") if isinstance(response, dict) else None
            if not isinstance(rows, list) or len(rows) != len(pending):
                raise ValueError("OSV response lost query ordering or result entries")
            following = []
            for (index, query), row in zip(pending, rows):
                if not isinstance(row, dict) or not isinstance(row.get("vulns", []), list):
                    raise ValueError("OSV query result was not an object with a vulnerability list")
                for vuln in row.get("vulns", []):
                    if not isinstance(vuln, dict) or not isinstance(vuln.get("id"), str) or not vuln["id"]:
                        raise ValueError("OSV summary omitted its identifier")
                    if not isinstance(vuln.get("modified"), str) or not vuln["modified"]:
                        raise ValueError("OSV summary omitted its modification timestamp")
                    identifier = vuln["id"]
                    identifiers[identifier] = vuln["modified"]
                    if len(identifiers) > MAX_RECORDS:
                        raise ValueError("OSV record count exceeded limit")
                    associated = associations[index]["vulnerability_ids"]
                    if identifier not in associated:
                        associated.append(identifier)
                token = row.get("next_page_token")
                if token is not None and not isinstance(token, str):
                    raise ValueError("OSV page token is not a string")
                if token:
                    if token in seen_tokens[index]:
                        raise ValueError("OSV repeated a pagination token")
                    seen_tokens[index].add(token)
                    following.append((index, {**query, "page_token": token}))
            pending = following
            if not pending:
                break
        else:
            raise ValueError("OSV pagination exceeded limit")
    records = []
    for identifier, modified in identifiers.items():
        raw = _get(transport, OSV_RECORD_URL + quote(identifier, safe=""))
        downloaded += len(raw)
        if downloaded > MAX_FEED_BYTES:
            raise ValueError("OSV download exceeded total byte budget")
        record = _json(raw)
        normalized = osv_record(record)
        if normalized is None or record.get("id") != identifier or record.get("modified") != modified:
            raise ValueError("OSV full record did not match its query summary; retry required")
        if not record.get("withdrawn") and not normalized["affected"]:
            raise ValueError("OSV record was a summary without affected package data")
        records.append(record)
    return {
        "vulns": records,
        "queries": associations,
        "complete": True,
        "retrieved_at": datetime.now(timezone.utc).isoformat(),
        "source_notices": [source_notice(record) for record in records],
    }


def _get(transport: Transport, url: str, *, body: bytes | None = None) -> bytes:
    status, raw = transport(url, method="POST" if body is not None else "GET", body=body,
                            headers={"Content-Type": "application/json"} if body is not None else {})
    if status != 200 or not isinstance(raw, bytes) or not raw or len(raw) > MAX_FEED_BYTES:
        raise ValueError("Feed response status, body or byte limit was not accepted")
    return raw


def _json(raw: bytes) -> Any:
    return json.loads(raw.decode("utf-8"))


def default_transport(url: str, *, method: str, body: bytes | None, headers: dict[str, str]) -> tuple[int, bytes]:
    req = request.Request(url, data=body, headers=headers, method=method)
    with request.urlopen(req, timeout=20) as response:
        raw = response.read(MAX_FEED_BYTES + 1)
        if len(raw) > MAX_FEED_BYTES:
            raise ValueError("Feed response exceeded byte limit")
        return int(response.status), raw


def _queries(inventory: dict[str, Any]) -> list[dict[str, Any]]:
    queries = []
    for item in inventory.get("items") or []:
        if item.get("ecosystem") and item.get("name") and item.get("version"):
            query = {"version": item["version"], "package": {"name": item["name"], "ecosystem": item["ecosystem"]}}
            if query not in queries:
                queries.append(query)
            if len(queries) > MAX_QUERIES:
                raise ValueError("Inventory query count exceeded limit")
    return queries


def _save(path: Path, raw: bytes, url: str) -> None:
    publish(path, raw)
    provenance = {"retrieved_at": datetime.now(timezone.utc).isoformat(), "url": url,
                  "sha256": hashlib.sha256(raw).hexdigest()}
    try:
        publish(path.with_name(path.name + ".provenance.json"), json.dumps(provenance).encode("utf-8"))
    except OSError:
        pass  # Readers reject an old sidecar whose content hash differs.

"""Opt-in KEV and OSV download. The resident pass does not call this."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable
from urllib import request

from agent.intel.NOTICES import write_notices
from agent.intel.inventory import load_inventory
from agent.intel.report import load_local_intel

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
OSV_URL = "https://api.osv.dev/v1/querybatch"
Transport = Callable[..., tuple[int, bytes]]


def fetch_feeds(
    directory: Path,
    *,
    enabled: bool,
    transport: Transport | None,
) -> dict[str, Any]:
    """Download KEV, and OSV only for inventory rows, when fetch is explicitly enabled."""
    if not enabled:
        report = load_local_intel(directory)
        report["fetch"] = "off"
        report["detail"] = "Feed fetch is off. Local files were read if present. Nothing was downloaded."
        return report
    if transport is None:
        report = load_local_intel(directory)
        report["fetch"] = "unavailable"
        report["detail"] = "Fetch was requested but no transport is configured. Nothing was downloaded."
        return report
    directory.mkdir(parents=True, exist_ok=True)
    write_notices(directory)
    status, body = transport(KEV_URL, method="GET", body=None, headers={})
    if status == 200 and body:
        (directory / "kev.json").write_bytes(body)
        _provenance(directory / "kev.json.provenance.json", KEV_URL)
    inventory = load_inventory(directory / "inventory.json")
    queries = _queries(inventory)
    if queries:
        payload = json.dumps({"queries": queries}).encode("utf-8")
        osv_status, osv_body = transport(
            OSV_URL,
            method="POST",
            body=payload,
            headers={"Content-Type": "application/json"},
        )
        if osv_status == 200 and osv_body:
            (directory / "osv.json").write_bytes(osv_body)
            _provenance(directory / "osv.json.provenance.json", OSV_URL)
            (directory / "osv.NOTICE").write_text(
                "Fetched by DVielle. Record fields were not modified.\n"
                "License: Apache-2.0 https://github.com/ossf/osv-schema/blob/main/LICENSE\n",
                encoding="utf-8",
            )
    report = load_local_intel(directory)
    report["fetch"] = "opt-in"
    report["detail"] = "Fetch ran only because it was enabled. OSV was queried only for inventory rows."
    return report


def default_transport(url: str, *, method: str, body: bytes | None, headers: dict[str, str]) -> tuple[int, bytes]:
    """Network transport for an explicit opt-in call. The collector does not use it."""
    req = request.Request(url, data=body, headers=headers, method=method)
    with request.urlopen(req, timeout=20) as response:
        return int(response.status), response.read()


def _queries(inventory: dict[str, Any]) -> list[dict[str, Any]]:
    queries: list[dict[str, Any]] = []
    for item in inventory.get("items") or []:
        if item.get("ecosystem") and item.get("name") and item.get("version"):
            queries.append(
                {
                    "version": item["version"],
                    "package": {"name": item["name"], "ecosystem": item["ecosystem"]},
                }
            )
    return queries


def _provenance(path: Path, url: str) -> None:
    path.write_text(
        json.dumps(
            {
                "retrieved_at": datetime.now(timezone.utc).isoformat(),
                "url": url,
            }
        ),
        encoding="utf-8",
    )

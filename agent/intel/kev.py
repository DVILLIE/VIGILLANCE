"""CISA KEV catalog loader. CC0, no logo, no endorsement, no invented rows."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

_CVE = re.compile(r"^CVE-\d{4}-\d{4,}$")

KEV_DISCLAIMER = (
    "CISA KEV is used under CC0 1.0. This is not a CISA or DHS endorsement. "
    "DVielle does not display the CISA logo or the DHS seal. "
    "Third-party links in the catalog keep their own licenses."
)


def load_kev(path: Path | None) -> dict[str, Any]:
    if path is None or not path.is_file():
        return _unavailable("No CISA KEV file is present. No exploited-vulnerability rows were invented.")
    try:
        raw = path.read_bytes()
        payload = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return _invalid("The KEV file is not UTF-8 JSON. No rows were invented.")
    rows = payload.get("vulnerabilities") if isinstance(payload, dict) else None
    if not isinstance(rows, list):
        return _invalid("The KEV file has no vulnerabilities list. No rows were invented.")
    kept: list[dict[str, str]] = []
    for row in rows:
        parsed = _row(row)
        if parsed is not None:
            kept.append(parsed)
    if not kept:
        return _invalid("The KEV file had no usable CVE rows. No rows were invented.")
    sidecar = _sidecar(path)
    return {
        "state": "loaded",
        "count": len(kept),
        "rows": kept,
        "license": "CC0-1.0",
        "disclaimer": KEV_DISCLAIMER,
        "logos": "none",
        "endorsement": "none",
        "catalog_version": _text(payload.get("catalogVersion")) or None,
        "date_released": _text(payload.get("dateReleased")) or None,
        "provenance": {
            "source": "local-file",
            "path": str(path),
            "sha256": hashlib.sha256(raw).hexdigest(),
            "license": "CC0-1.0",
            "retrieved_at": sidecar.get("retrieved_at"),
            "url": sidecar.get("url") or "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
        },
    }


def _row(row: Any) -> dict[str, str] | None:
    if not isinstance(row, dict):
        return None
    cve = _text(row.get("cveID"))
    product = _text(row.get("product"))
    vendor = _text(row.get("vendorProject"))
    if not _CVE.match(cve) or not product or not vendor:
        return None
    return {
        "cveID": cve,
        "vendorProject": vendor,
        "product": product,
        "vulnerabilityName": _text(row.get("vulnerabilityName")),
        "dateAdded": _text(row.get("dateAdded")),
        "requiredAction": _text(row.get("requiredAction")),
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


def _text(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ""


def _unavailable(detail: str) -> dict[str, Any]:
    return {
        "state": "unavailable",
        "count": 0,
        "rows": [],
        "license": "CC0-1.0",
        "disclaimer": KEV_DISCLAIMER,
        "logos": "none",
        "endorsement": "none",
        "catalog_version": None,
        "date_released": None,
        "provenance": {"source": "absent"},
        "detail": detail,
    }


def _invalid(detail: str) -> dict[str, Any]:
    body = _unavailable(detail)
    body["state"] = "invalid"
    body["provenance"] = {"source": "local-file", "schema": "rejected"}
    return body

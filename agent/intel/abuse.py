"""abuse.ch runtime fetch. Default off. No bundled dump. No invented indicators."""

from __future__ import annotations

from typing import Any, Callable

# ThreatFox community API. Auth-Key header is required.
# https://threatfox.abuse.ch/api/  (fetched 2026-09-29)
ABUSE_URL = "https://threatfox-api.abuse.ch/api/v1/"
Transport = Callable[..., tuple[int, bytes]]


def abuse_view(*, enabled: bool = False) -> dict[str, Any]:
    return {
        "enabled": bool(enabled),
        "bundled": False,
        "status": "off" if not enabled else "not_fetched",
        "hits": [],
        "detail": (
            "abuse.ch is off. DVielle does not ship abuse.ch dumps."
            if not enabled
            else "abuse.ch is enabled in config but this pass did not fetch. No indicators were invented."
        ),
    }


def fetch_abuse_ch(*, enabled: bool, auth_key: str | None, transport: Transport | None) -> dict[str, Any]:
    """Fetch recent ThreatFox IOCs only when enabled and the caller supplies an Auth-Key.

    The response is not written to disk. A missing key, a disabled switch, or a
    bad payload returns no hits.
    """
    if not enabled:
        return abuse_view(enabled=False)
    key = (auth_key or "").strip()
    if not key:
        return {
            "enabled": True,
            "bundled": False,
            "status": "unavailable",
            "hits": [],
            "detail": "Auth-Key required. Nothing was fetched and no dump was bundled.",
        }
    if transport is None:
        return {
            "enabled": True,
            "bundled": False,
            "status": "unavailable",
            "hits": [],
            "detail": "No transport is configured. Nothing was fetched.",
        }
    status, body = transport(
        ABUSE_URL,
        method="POST",
        body=b'{"query":"get_iocs","days":1}',
        headers={"Auth-Key": key, "Content-Type": "application/json"},
    )
    if status != 200 or not body:
        return {
            "enabled": True,
            "bundled": False,
            "status": "unavailable",
            "hits": [],
            "detail": "The abuse.ch response was not usable. No indicators were invented.",
            "stored": False,
        }
    return _parse(body)


def _parse(body: bytes) -> dict[str, Any]:
    import json

    try:
        payload = json.loads(body.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError):
        return {
            "enabled": True,
            "bundled": False,
            "status": "unavailable",
            "hits": [],
            "detail": "The abuse.ch body was not JSON. No indicators were invented.",
            "stored": False,
        }
    if not isinstance(payload, dict) or payload.get("query_status") != "ok" or not isinstance(payload.get("data"), list):
        return {
            "enabled": True,
            "bundled": False,
            "status": "unavailable",
            "hits": [],
            "detail": "The abuse.ch query was not ok. No indicators were invented.",
            "stored": False,
        }
    hits = []
    for row in payload["data"]:
        if isinstance(row, dict) and isinstance(row.get("ioc"), str) and row["ioc"].strip():
            hits.append(
                {
                    "ioc": row["ioc"].strip(),
                    "ioc_type": row.get("ioc_type") if isinstance(row.get("ioc_type"), str) else "",
                    "provenance": "runtime Auth-Key fetch; not redistributed",
                }
            )
    return {
        "enabled": True,
        "bundled": False,
        "status": "fetched",
        "hits": hits,
        "stored": False,
        "detail": "Fetched at runtime with the caller Auth-Key. The body was not saved into the product.",
    }

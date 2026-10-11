"""Opt-in bounded OSV lookup; package versions only, no uploads of files."""
from __future__ import annotations

import http.client
import json
import socket
import ssl

from agent.assessment.engine import resolve_origin

MAX_RESPONSE = 262144


def parse_results(payload, selected: list[dict]) -> list[dict]:
    """Reject partial or malformed coverage rather than suggesting a clean result."""
    results = payload.get("results") if isinstance(payload, dict) else None
    if not isinstance(results, list) or len(results) != len(selected):
        raise ValueError("OSV query coverage did not match the submitted inventory.")
    rows = []
    for package, result in zip(selected, results):
        if not isinstance(result, dict) or result.get("next_page_token"):
            raise ValueError("OSV query coverage is incomplete.")
        vulns = result.get("vulns", [])
        if not isinstance(vulns, list) or len(vulns) > 100:
            raise ValueError("OSV advisory list exceeded the limit.")
        ids = []
        for vuln in vulns:
            identifier = vuln.get("id") if isinstance(vuln, dict) else None
            if (not isinstance(identifier, str) or not identifier or len(identifier) > 128
                    or any(ord(ch) < 32 or ord(ch) == 127 for ch in identifier)):
                raise ValueError("OSV returned an invalid advisory identifier.")
            ids.append(identifier)
        rows.append({"name": package["name"], "version": package["version"], "advisory_ids": ids})
    return rows


def query_versions(packages: list[dict], scope, stop) -> dict:
    if scope.share_runtime_versions is not True or scope.authorized is not True:
        raise ValueError("Runtime-version sharing requires an explicit per-run choice.")
    scope.check(stop)
    selected = [row for row in packages if row.get("version")][:20]
    queries = [{"package": {"name": row["name"], "ecosystem": "PyPI"},
                "version": row["version"]} for row in selected]
    if not queries:
        return {"state": "not_evaluated", "packages": [], "detail": "No runtime versions available."}
    addresses = resolve_origin("api.osv.dev", 443, scope, stop)
    if not addresses or len(addresses) > 16:
        raise ValueError("OSV address resolution was not bounded.")
    connection = http.client.HTTPConnection("api.osv.dev", 443, timeout=8)
    try:
        scope.check(stop)
        connection.sock = socket.create_connection((addresses[0], 443), timeout=8)
        from agent.assessment.cryptography import assessment_tls_context
        connection.sock = assessment_tls_context().wrap_socket(connection.sock, server_hostname="api.osv.dev")
        scope.check(stop)
        connection.request("POST", "/v1/querybatch", body=json.dumps({"queries": queries}).encode(),
                           headers={"Content-Type": "application/json", "Connection": "close",
                                    "User-Agent": "DVielle-Authorized-Assessment/1"})
        response = connection.getresponse()
        if response.status != 200:
            raise ValueError("OSV did not return a successful query response.")
        raw = response.read(MAX_RESPONSE + 1)
        if len(raw) > MAX_RESPONSE:
            raise ValueError("OSV response exceeded the limit.")
        scope.check(stop)
        payload = json.loads(raw)
        rows = parse_results(payload, selected)
        return {"state": "queried", "source": "https://api.osv.dev/v1/querybatch", "packages": rows,
                "detail": "Version applicability only; reachability and exploitation were not established.",
                "license": "Advisory records retain source-specific licenses."}
    finally:
        connection.close()

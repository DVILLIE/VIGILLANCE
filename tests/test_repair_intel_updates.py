"""Contract regression fixtures; these are not live vulnerability/security claims."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone

import pytest

from agent.intel.fetch import KEV_URL, OSV_RECORD_URL, OSV_URL, fetch_feeds
from agent.intel.match import _range_affected, match_feeds
from agent.intel.osv import load_osv
from agent.intel.io import read_bounded
from agent.update import tuf
from tests.test_worldclass_p3 import NOW, TARGET, _installed, _keys, _publish


def _json(value):
    return json.dumps(value).encode("utf-8")


def _record(identifier="x_FIXTURE-1", package="sample"):
    return {"id": identifier, "modified": "2026-10-09T00:00:00Z",
            "affected": [{"package": {"ecosystem": "PyPI", "name": package},
                          "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}]}],
            "references": [{"type": "ADVISORY", "url": "https://example.invalid/fixture"}]}


def _inventory(path):
    (path / "inventory.json").write_bytes(_json({"items": [
        {"ecosystem": "PyPI", "name": "sample", "version": "1.0.0"},
        {"ecosystem": "PyPI", "name": "other", "version": "1.0.0"}]}))


def test_osv_batch_hydrates_records_and_paginates_only_remaining_queries(tmp_path):
    _inventory(tmp_path)
    calls = []
    records = [_record(), _record("x_FIXTURE-2")]

    def transport(url, *, method, body, headers):
        calls.append((url, json.loads(body) if body else None))
        if url == KEV_URL:
            return 503, b""
        if url == OSV_URL:
            queries = json.loads(body)["queries"]
            if len(queries) == 2:
                return 200, _json({"results": [{"vulns": [{"id": records[0]["id"], "modified": records[0]["modified"]}],
                                               "next_page_token": "page-2"}, {}]})
            assert len(queries) == 1 and queries[0]["package"]["name"] == "sample"
            assert queries[0]["page_token"] == "page-2"
            return 200, _json({"results": [{"vulns": [{"id": records[1]["id"], "modified": records[1]["modified"]}]}]})
        return 200, _json(next(row for row in records if url == OSV_RECORD_URL + row["id"]))

    report = fetch_feeds(tmp_path, enabled=True, transport=transport)
    assert report["osv"]["state"] == "loaded"
    assert len(report["matches"]["hits"]) == 2
    assert {row["package"]: row["status"] for row in report["matches"]["assessments"]} == {
        "sample": "affected", "other": "unaffected"}
    cached = json.loads((tmp_path / "osv.json").read_text())
    assert cached["vulns"] == records
    assert cached["queries"][0]["vulnerability_ids"] == [row["id"] for row in records]
    assert cached["queries"][1]["vulnerability_ids"] == []
    assert cached["source_notices"][0]["database_prefix"] == "x_FIXTURE"
    assert "source-specific" in report["osv"]["license"]


@pytest.mark.parametrize("fault", ["http", "schema", "repeat", "summary", "oversize", "network"])
def test_failed_osv_refresh_preserves_previous_cache(tmp_path, monkeypatch, fault):
    _inventory(tmp_path)
    old = _json({"vulns": [_record()]})
    (tmp_path / "osv.json").write_bytes(old)
    if fault == "oversize":
        monkeypatch.setattr("agent.intel.fetch.MAX_FEED_BYTES", 1000)

    def transport(url, **kwargs):
        if url == KEV_URL:
            return 503, b""
        if fault == "network":
            raise OSError("fixture transport failure")
        if fault == "http":
            return 429, b"retry later"
        if fault == "schema":
            return 200, b'{"results":[]}'
        if fault == "oversize":
            return 200, b" " * 1001
        if url == OSV_URL:
            count = len(json.loads(kwargs["body"])["queries"])
            result = {"vulns": [{"id": "x_FIXTURE-1", "modified": _record()["modified"]}]}
            if fault == "repeat":
                result["next_page_token"] = "same-token"
            return 200, _json({"results": [result] * count})
        return 200, _json({"id": "x_FIXTURE-1", "modified": _record()["modified"]})

    report = fetch_feeds(tmp_path, enabled=True, transport=transport)
    assert report["fetch"] == "partial"
    assert report["fetch_results"]["osv"].startswith("failed")
    assert (tmp_path / "osv.json").read_bytes() == old


def test_osv_empty_completed_query_is_valid_but_raw_summaries_are_not(tmp_path):
    path = tmp_path / "osv.json"
    path.write_bytes(_json({"results": [{"vulns": [{"id": "x_FIXTURE-1", "modified": "2026"}]}]}))
    assert load_osv(path)["state"] == "invalid"
    path.write_bytes(_json({"vulns": [], "complete": True, "queries": [
        {"query": {"version": "1", "package": {"ecosystem": "PyPI", "name": "sample"}}, "vulnerability_ids": []}]}))
    assert load_osv(path)["state"] == "loaded"
    assert load_osv(path)["count"] == 0


@pytest.mark.parametrize("version,expected", [("1.0.0", True), ("1.5.0", True), ("2.0.0", False),
                                              ("2.5.0", False), ("3.0.0", True), ("99.0.0", True)])
def test_osv_multiple_intervals_and_open_ended_introduced(version, expected):
    # Deliberately unordered, as the OSV evaluation algorithm sorts events.
    block = {"type": "SEMVER", "events": [{"introduced": "3.0.0"}, {"fixed": "2.0.0"}, {"introduced": "1.0.0"}]}
    assert _range_affected(version, block) is expected


def test_osv_limits_prereleases_and_ecosystem_unknowns():
    limit = {"type": "SEMVER", "events": [{"introduced": "0"}, {"limit": "2.0.0"}, {"limit": "3.0.0"}]}
    assert _range_affected("2.5.0", limit) is True
    assert _range_affected("3.0.0", limit) is False
    prerelease = {"type": "SEMVER", "events": [{"introduced": "1.0.0-alpha.2"}, {"fixed": "1.0.0"}]}
    assert _range_affected("1.0.0-alpha.10", prerelease) is True
    assert _range_affected("1.0.0+build.1", prerelease) is False
    assert _range_affected("1.0.0-alpha.02", prerelease) is None
    pypi = {"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.0"}]}
    assert _range_affected("1.0rc1", pypi, ecosystem="PyPI") is True
    assert _range_affected("1.0", pypi, ecosystem="PyPI") is False
    assert _range_affected("1.0", pypi, ecosystem="Debian") is None
    report = match_feeds({}, {"state": "loaded", "rows": [{"id": "x_FIXTURE", "affected": [
        {"name": "sample", "ecosystem": "Debian", "ranges": [pypi]}]}]},
                         {"state": "loaded", "items": [{"name": "sample", "ecosystem": "Debian", "version": "1.0"}]})
    assert report["assessments"][0]["status"] == "unassessed"


def test_tuf_failed_target_can_retry_with_same_trusted_timestamp(tmp_path):
    _keys()
    repo, store = tmp_path / "repo", tmp_path / "store"
    _publish(repo, store, package=b"package", on_disk=b"corrupt")
    failed = tuf.verify_update(store, repo, TARGET, now=NOW)
    assert failed["last_reason"] == "bad_hash"
    assert (store / "timestamp.json").is_file()
    _publish(repo, store, package=b"package", bootstrap=False)
    retried = tuf.verify_update(store, repo, TARGET, now=NOW)
    assert retried["last_result"] == "accepted"
    assert _installed(store) == b"package"
    assert tuf.verify_update(store, repo, TARGET, now=NOW)["last_result"] == "unchanged"


def test_tuf_cached_timestamp_still_expires_and_equal_version_cannot_replace_it(tmp_path):
    _keys()
    repo, store = tmp_path / "repo", tmp_path / "store"
    _publish(repo, store, package=b"package", timestamp_expires="2026-10-10T00:00:00Z")
    assert tuf.verify_update(store, repo, TARGET, now=NOW)["last_result"] == "accepted"
    trusted = (store / "timestamp.json").read_bytes()
    _publish(repo, store, package=b"different", bootstrap=False)  # same timestamp version, altered signed metadata
    result = tuf.verify_update(store, repo, TARGET, now=NOW)
    assert result["last_reason"] == "bad_hash"
    assert (store / "timestamp.json").read_bytes() == trusted
    assert _installed(store) == b"package"
    frozen = tuf.verify_update(store, repo, TARGET, now=datetime(2026, 10, 11, tzinfo=timezone.utc))
    assert frozen["last_reason"] == "freeze"


def test_tuf_activation_record_failure_restores_artifact_and_allows_retry(tmp_path, monkeypatch):
    _keys()
    repo, store = tmp_path / "repo", tmp_path / "store"
    _publish(repo, store, package=b"previous")
    assert tuf.verify_update(store, repo, TARGET, now=NOW)["last_result"] == "accepted"
    previous_record = (store / "installed.json").read_bytes()
    _publish(repo, store, package=b"next", timestamp_version=2, snapshot_version=2, targets_version=2, bootstrap=False)
    write = tuf._atomic_bytes
    failures = []

    def fail_once(path, payload):
        if path.name == "installed.json" and not failures:
            failures.append(True)
            raise OSError("fixture disk write failure")
        write(path, payload)

    monkeypatch.setattr(tuf, "_atomic_bytes", fail_once)
    result = tuf.verify_update(store, repo, TARGET, now=NOW)
    assert result["last_reason"] == "io_error"
    assert _installed(store) == b"previous"
    assert json.loads((store / "installed.json").read_bytes()) == json.loads(previous_record)
    assert not (store / "activation.json").exists()
    assert tuf.verify_update(store, repo, TARGET, now=NOW)["last_result"] == "accepted"
    assert _installed(store) == b"next"


def test_tuf_interrupted_activation_recovers_before_new_work(tmp_path):
    _keys()
    repo, store = tmp_path / "repo", tmp_path / "store"
    _publish(repo, store, package=b"previous")
    assert tuf.verify_update(store, repo, TARGET, now=NOW)["last_result"] == "accepted"
    previous = json.loads((store / "installed.json").read_bytes())
    backup_name = ".rollback-" + "1" * 32
    (store / "files" / backup_name).write_bytes(b"previous")
    (store / "files" / TARGET).write_bytes(b"partial")
    journal = {"target": TARGET, "backup": backup_name,
               "backup_sha256": hashlib.sha256(b"previous").hexdigest(),
               "previous": previous, "next": {"sha256": hashlib.sha256(b"partial").hexdigest()}}
    (store / "activation.json").write_bytes(_json(journal))
    assert tuf.verify_update(store, repo, TARGET, now=NOW)["last_result"] == "unchanged"
    assert _installed(store) == b"previous"
    assert not (store / "activation.json").exists()


def test_tuf_store_lock_refuses_second_update(tmp_path):
    with tuf._store_lock(tmp_path):
        result = tuf.verify_update(tmp_path, tmp_path / "repo", TARGET, now=NOW)
    assert result["last_reason"] == "busy"


def test_tuf_crash_between_artifact_and_record_is_recovered(tmp_path, monkeypatch):
    class Interrupted(BaseException):
        pass

    _keys()
    repo, store = tmp_path / "repo", tmp_path / "store"
    _publish(repo, store, package=b"previous")
    assert tuf.verify_update(store, repo, TARGET, now=NOW)["last_result"] == "accepted"
    previous = json.loads((store / "installed.json").read_bytes())
    _publish(repo, store, package=b"next", timestamp_version=2, snapshot_version=2, targets_version=2, bootstrap=False)
    write = tuf._atomic_bytes

    def interrupt_after_artifact(path, payload):
        write(path, payload)
        if path.parent.name == "files" and path.name == TARGET:
            raise Interrupted()

    monkeypatch.setattr(tuf, "_atomic_bytes", interrupt_after_artifact)
    with pytest.raises(Interrupted):
        tuf.verify_update(store, repo, TARGET, now=NOW)
    assert (store / "activation.json").exists()
    monkeypatch.setattr(tuf, "_atomic_bytes", write)
    # Reject the new request after restoring the interrupted prior install.
    result = tuf.verify_update(store, repo, "../invalid", now=NOW)
    assert result["last_reason"] == "bad_metadata"
    assert _installed(store) == b"previous"
    assert json.loads((store / "installed.json").read_bytes()) == previous
    assert not (store / "activation.json").exists()


def test_bounded_local_read_and_last_affected_limits(tmp_path):
    path = tmp_path / "large.json"
    path.write_bytes(b"x" * 101)
    with pytest.raises(ValueError):
        read_bounded(path, 100)
    inclusive = {"type": "SEMVER", "events": [{"introduced": "0"}, {"last_affected": "1.0.0"}, {"limit": "*"}]}
    assert _range_affected("1.0.0", inclusive) is True
    assert _range_affected("1.0.1", inclusive) is False

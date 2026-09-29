"""P4: local CISA KEV and OSV intel, and a Defender-safe privacy assistant."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from agent.edition_matrix import build_edition_matrix
from agent.engine.loop import ResolutionEngine
from agent.engine.models import PolicyDenied
from agent.intel.abuse import fetch_abuse_ch
from agent.intel.fetch import fetch_feeds
from agent.intel.report import load_local_intel
from agent.modules.defender_health import MapsCheck
from agent.modules.privacy_assistant import (
    apply_privacy_choice,
    assess_microsoft_block,
    observe_privacy,
)
from agent.policy.actions import USER_APPROVED_ONLY, ActionKind
from agent.store.db import AgentStore
from agent.update.tuf import PRIVILEGED_AUTO_UPDATE
from agent.version import get_version
from dvielle.gui.observations import prevention_evidence_line, privacy_evidence_clause

ROOT = Path(__file__).resolve().parents[1]
P4_SOURCES = (
    ROOT / "agent" / "intel" / "kev.py",
    ROOT / "agent" / "intel" / "osv.py",
    ROOT / "agent" / "intel" / "match.py",
    ROOT / "agent" / "intel" / "report.py",
    ROOT / "agent" / "intel" / "abuse.py",
    ROOT / "agent" / "intel" / "inventory.py",
    ROOT / "agent" / "modules" / "privacy_assistant.py",
)


def _kev() -> dict:
    return {
        "title": "CISA Catalog of Known Exploited Vulnerabilities",
        "catalogVersion": "2026.09.29",
        "dateReleased": "2026-09-29T00:00:00.000Z",
        "count": 1,
        "vulnerabilities": [
            {
                "cveID": "CVE-2021-44228",
                "vendorProject": "Apache",
                "product": "Log4j",
                "vulnerabilityName": "Apache Log4j Remote Code Execution",
                "dateAdded": "2021-12-10",
                "requiredAction": "Apply updates per vendor instructions.",
                "dueDate": "2021-12-24",
            }
        ],
    }


def _osv(version_fixed: str = "1.2.3") -> dict:
    return {
        "vulns": [
            {
                "id": "GHSA-test-1111",
                "modified": "2024-01-01T00:00:00Z",
                "affected": [
                    {
                        "package": {"ecosystem": "PyPI", "name": "example-pkg"},
                        "ranges": [
                            {
                                "type": "ECOSYSTEM",
                                "events": [{"introduced": "0"}, {"fixed": version_fixed}],
                            }
                        ],
                        "versions": ["1.0.0"],
                    }
                ],
            },
            {
                "id": "GHSA-withdrawn",
                "modified": "2024-02-01T00:00:00Z",
                "withdrawn": "2024-03-01T00:00:00Z",
                "affected": [
                    {
                        "package": {"ecosystem": "PyPI", "name": "example-pkg"},
                        "versions": ["1.0.0"],
                    }
                ],
            },
        ]
    }


def _inventory(*items: dict) -> dict:
    return {"items": list(items)}


def _write(directory: Path, name: str, payload: dict) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    (directory / name).write_text(json.dumps(payload), encoding="utf-8")


def test_version_is_2_2_0():
    assert get_version() == "2.2.0"
    assert PRIVILEGED_AUTO_UPDATE is False


def test_missing_feeds_are_unavailable_and_do_not_invent_hits(tmp_path: Path):
    report = load_local_intel(tmp_path / "intel")
    assert report["intel"] == "unavailable"
    assert report["matches"]["state"] == "unavailable"
    assert report["matches"]["hits"] == []
    assert report["abuse_ch"]["bundled"] is False
    assert report["abuse_ch"]["status"] == "off"
    assert report["fetch"] == "off"
    assert "not a CISA or DHS endorsement" in report["kev"]["disclaimer"]
    assert report["kev"]["logos"] == "none"
    assert "Apache-2.0" in report["osv"]["notice"]


def test_invalid_schema_does_not_become_a_hit(tmp_path: Path):
    directory = tmp_path / "intel"
    _write(directory, "kev.json", {"vulnerabilities": [{"cveID": "not-a-cve", "product": "Log4j"}]})
    _write(directory, "osv.json", {"vulns": [{"summary": "missing id"}]})
    _write(directory, "inventory.json", _inventory({"name": "Log4j", "version": "2.14.1", "product": "Log4j", "vendor": "Apache"}))
    report = load_local_intel(directory)
    assert report["intel"] == "invalid"
    assert report["matches"]["hits"] == []
    assert report["kev"]["count"] == 0
    assert report["osv"]["count"] == 0


def test_inventory_match_is_a_candidate_and_absent_inventory_is_not_compared(tmp_path: Path):
    directory = tmp_path / "intel"
    _write(directory, "kev.json", _kev())
    _write(directory, "osv.json", _osv())
    bare = load_local_intel(directory)
    assert bare["intel"] == "loaded"
    assert bare["matches"]["state"] == "unavailable"
    assert bare["matches"]["hits"] == []
    assert "not a clean bill" in bare["matches"]["detail"]

    _write(
        directory,
        "inventory.json",
        _inventory(
            {"name": "Log4j", "version": "2.14.1", "product": "Log4j", "vendor": "Apache"},
            {"name": "example-pkg", "version": "1.0.0", "ecosystem": "PyPI"},
            {"name": "example-pkg", "version": "1.2.0", "ecosystem": "PyPI"},
            {"name": "example-pkg", "version": "1.2.3", "ecosystem": "PyPI"},
            {"name": "example-pkg", "version": "1.2.3rc1", "ecosystem": "PyPI"},
        ),
    )
    report = load_local_intel(directory)
    hits = report["matches"]["hits"]
    assert report["matches"]["state"] == "compared"
    kev_hits = [hit for hit in hits if hit["feed"] == "kev"]
    osv_hits = [hit for hit in hits if hit["feed"] == "osv"]
    assert [hit["id"] for hit in kev_hits] == ["CVE-2021-44228"]
    assert kev_hits[0]["kind"] == "name_candidate"
    assert "not proof" in kev_hits[0]["assumption"]
    assert {hit["version"] for hit in osv_hits} == {"1.0.0", "1.2.0"}
    assert all(hit["id"] == "GHSA-test-1111" for hit in osv_hits)
    assert "GHSA-withdrawn" not in {hit["id"] for hit in hits}
    assert report["kev"]["endorsement"] == "none"


def test_fetch_stays_off_and_osv_is_not_queried_without_inventory(tmp_path: Path):
    calls: list[str] = []

    def transport(url: str, *, method: str, body: bytes | None, headers: dict) -> tuple[int, bytes]:
        calls.append(url)
        if "known_exploited" in url:
            return 200, json.dumps(_kev()).encode("utf-8")
        return 200, json.dumps(_osv()).encode("utf-8")

    skipped = fetch_feeds(tmp_path / "off", enabled=False, transport=transport)
    assert skipped["fetch"] == "off"
    assert calls == []
    fetched = fetch_feeds(tmp_path / "on", enabled=True, transport=transport)
    assert calls == ["https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"]
    assert fetched["kev"]["state"] == "loaded"
    assert fetched["osv"]["state"] == "unavailable"
    assert (tmp_path / "on" / "NOTICES.txt").is_file()
    assert "not an endorsement" in (tmp_path / "on" / "NOTICES.txt").read_text(encoding="utf-8")


def test_abuse_ch_default_off_and_runtime_key_is_not_stored(tmp_path: Path):
    calls: list[dict] = []

    def transport(url: str, *, method: str, body: bytes | None, headers: dict) -> tuple[int, bytes]:
        calls.append({"url": url, "headers": headers, "body": body})
        payload = {"query_status": "ok", "data": [{"ioc": "example.invalid", "ioc_type": "domain"}]}
        return 200, json.dumps(payload).encode("utf-8")

    off = fetch_abuse_ch(enabled=False, auth_key="secret", transport=transport)
    assert off["status"] == "off"
    assert off["hits"] == []
    assert calls == []
    missing = fetch_abuse_ch(enabled=True, auth_key="", transport=transport)
    assert missing["status"] == "unavailable"
    assert missing["hits"] == []
    assert calls == []
    fetched = fetch_abuse_ch(enabled=True, auth_key="secret", transport=transport)
    assert fetched["status"] == "fetched"
    assert fetched["bundled"] is False
    assert fetched["stored"] is False
    assert fetched["hits"] == [
        {"ioc": "example.invalid", "ioc_type": "domain", "provenance": "runtime Auth-Key fetch; not redistributed"}
    ]
    assert calls[0]["headers"]["Auth-Key"] == "secret"
    assert list(tmp_path.rglob("*")) == []
    assert not list((ROOT / "agent" / "intel").glob("*.json"))


def _engine(tmp_path: Path, state: dict, *, stick: bool = True):
    engine = ResolutionEngine(AgentStore(tmp_path / "agent.db"), learn_dir=tmp_path / "learn", log_dir=tmp_path / "logs")
    calls: list[str] = []

    def reader() -> dict:
        return dict(state)

    def runner(script: str) -> tuple[str | None, bool]:
        calls.append(script)
        if not stick:
            return "SET:OK\n", False
        if "AdvertisingInfo" in script:
            key = "AdvertisingId"
        elif "CloudContent" in script:
            key = "TailoredExperiences"
        else:
            key = "AllowTelemetryPolicy"
        if "Remove-ItemProperty" in script:
            state.pop(key, None)
        else:
            state[key] = int(script.split("Value ", 1)[1].split()[0])
        return "SET:OK\n", False

    engine.handler_ctx.privacy_reader = reader
    engine.handler_ctx.privacy_runner = runner
    return engine, calls, state


def _perform(engine, choice: str, edition: str, *, auto: bool = False):
    finding = {
        "id": "finding-privacy",
        "subject_identity": f"privacy:{choice}",
        "title_simple": "Prefer Required diagnostic data",
        "evidence_refs": ["AllowTelemetry was read"],
        "signals": {"choice": choice, "edition": edition},
    }
    token = engine.policy.issue(finding["id"], "privacy.set_choice", auto=auto, subject=finding["subject_identity"])
    return engine.handlers.invoke("privacy.set_choice", finding, engine.handler_ctx, token)


def test_home_required_is_verified_and_security_off_is_not_written(tmp_path: Path):
    engine, calls, state = _engine(tmp_path, {"AllowTelemetryPolicy": 3, "AdvertisingId": 1})
    applied = _perform(engine, "required_diagnostics", "Home")
    assert applied["performed"] is True
    assert applied["verified"] is True
    assert state["AllowTelemetryPolicy"] == 1
    assert "DVIELLE_PRIVACY_SET" in calls[0]
    assert "New-NetFirewallRule" not in calls[0]
    refused = _perform(engine, "security_off", "Core")
    assert refused["performed"] is False
    assert "cannot claim Security=Off" in refused["message"]
    assert len(calls) == 1
    assert state["AllowTelemetryPolicy"] == 1


def test_enterprise_security_off_is_reread_and_a_mismatch_is_not_applied(tmp_path: Path):
    engine, calls, state = _engine(tmp_path, {"AllowTelemetryPolicy": 1})
    applied = _perform(engine, "security_off", "Enterprise")
    assert applied["performed"] is True
    assert state["AllowTelemetryPolicy"] == 0
    assert "not a claim that Microsoft traffic stopped" in applied["message"]
    sticky = _engine(tmp_path / "mismatch", {"AllowTelemetryPolicy": 3}, stick=False)
    missed = _perform(sticky[0], "required_diagnostics", "Enterprise")
    assert missed["performed"] is False
    assert missed["verified"] is False
    assert sticky[2]["AllowTelemetryPolicy"] == 3
    assert calls


def test_direct_call_and_auto_protect_do_not_write(tmp_path: Path):
    state = {"AllowTelemetryPolicy": 3}

    def reader():
        return dict(state)

    def runner(script: str):
        raise AssertionError(script)

    with pytest.raises(PolicyDenied):
        apply_privacy_choice(choice="required_diagnostics", edition="Home", reader=reader, runner=runner)
    engine = ResolutionEngine(
        AgentStore(tmp_path / "agent.db"),
        learn_dir=tmp_path / "learn",
        auto_enabled=True,
    )
    with pytest.raises(PolicyDenied):
        engine.policy.issue("f", "privacy.set_choice", auto=True, subject="privacy:required_diagnostics")
    assert ActionKind.SET_PRIVACY_CHOICE in USER_APPROVED_ONLY
    assert state["AllowTelemetryPolicy"] == 3


def test_broad_microsoft_block_surfaces_maps_and_proposes_nothing():
    maps = MapsCheck("pass", "ValidateMapsConnection completed", "fixture", 0)
    blocked = assess_microsoft_block(
        ["definitions.wdcp.microsoft.com", "windowsupdate.com", "crl.microsoft.com"],
        maps=maps,
    )
    assert blocked["proposed"] is False
    assert blocked["rule"] is None
    assert any("wdcp.microsoft.com" in item for item in blocked["protected"])
    assert "MAPS ValidateMapsConnection result: pass" in blocked["consequence"]
    assert "does not block Microsoft Defender cloud endpoints" in blocked["consequence"]
    broad = assess_microsoft_block(["microsoft.com"], maps=maps)
    assert broad["proposed"] is False
    assert broad["broad"] is True
    narrow = assess_microsoft_block(["example.com"], maps=maps)
    assert narrow["proposed"] is False
    assert "rule" not in narrow


def test_evidence_strip_separates_observed_unknown_and_missing_intel():
    assistant = observe_privacy(
        edition="Home",
        reader=lambda: {"AllowTelemetryPolicy": 3, "AllowTelemetryLocal": None, "AdvertisingId": 1, "TailoredExperiences": None},
    )
    assert assistant["security_off"] == "unsupported"
    assert assistant["preferred"] == "Required"
    assert "cannot claim Security=Off" in assistant["recommendation"]
    unknown = {row for row in assistant["unknown"]}
    assert "AllowTelemetryLocal" in unknown
    assert "TailoredExperiences" in unknown
    stamp = datetime.now(timezone.utc).isoformat()
    data = {
        "runtime": {"state": "running", "heartbeat_at": stamp},
        "collectors": {
            "security": {"status": "ok", "interval_seconds": 120, "last_success_at": stamp},
            "heartbeat": {"status": "ok", "interval_seconds": 5, "last_success_at": stamp},
        },
        "security": {"defender_health": {"all_clear": False}, "maps": {"result": "unavailable"}},
        "privacy": {"intel": {"intel": "unavailable", "kev": {"count": 0}, "osv": {"count": 0}, "matches": {"state": "unavailable"}},
                    "assistant": assistant},
    }
    clause = privacy_evidence_clause(data)
    assert "intel: unavailable" in clause
    assert "observed AllowTelemetryPolicy Optional" in clause
    assert "unknown" in clause
    assert "Security=Off unsupported" in clause
    line = prevention_evidence_line(data)
    assert "intel: unavailable" in line
    home = build_edition_matrix("Home", edition_id="Core")
    assert home.features["windows_sandbox"] == "UNAVAILABLE"
    assert "modification" in " ".join(home.notes)


def test_p4_sources_keep_the_hard_locks():
    blob = "\n".join(path.read_text(encoding="utf-8") for path in P4_SOURCES)
    runtime = (ROOT / "agent" / "runtime.py").read_text(encoding="utf-8")
    assert "ExclusionPath" not in blob
    assert "Add-MpPreference" not in blob
    assert "api.github.com" not in blob
    assert "New-NetFirewallRule" not in blob
    assert "urlopen" not in blob
    assert "fetch_feeds" not in runtime
    assert "urlopen" not in runtime
    notices = (ROOT / "agent" / "intel" / "NOTICES.txt").read_text(encoding="utf-8")
    assert "CC0" in notices
    assert "not an endorsement" in notices
    assert "Apache" in notices
    assert "does not bundle" in notices

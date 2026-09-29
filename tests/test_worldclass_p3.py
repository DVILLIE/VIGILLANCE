"""P3: Windows Sandbox open-unfamiliar, offline TUF verification, ACL'd pipe."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from agent.engine.handlers import HandlerContext
from agent.engine.loop import ResolutionEngine
from agent.engine.models import PolicyDenied
from agent.modules.sandbox import open_unfamiliar, observe_sandbox
from agent.privilege.pipe import InProcessPipe, build_pipe_sddl, describe_pipe
from agent.store.db import AgentStore
from agent.update.canonical import canonical
from agent.update.tuf import PRIVILEGED_AUTO_UPDATE, attestation_view, verify_update
from agent.version import get_version
from dvielle.gui.observations import prevention_evidence_line

ROOT = Path(__file__).resolve().parents[1]
EXPIRES = "2030-01-01T00:00:00Z"
PAST = "2020-01-01T00:00:00Z"
NOW = datetime(2026, 9, 29, tzinfo=timezone.utc)
TARGET = "dvielle-agent.bin"
P3_SOURCES = (
    ROOT / "agent" / "modules" / "sandbox.py",
    ROOT / "agent" / "update" / "tuf.py",
    ROOT / "agent" / "update" / "canonical.py",
    ROOT / "agent" / "privilege" / "pipe.py",
)


class _Key:
    def __init__(self) -> None:
        self.private = Ed25519PrivateKey.generate()
        raw = self.private.public_key().public_bytes(encoding=Encoding.Raw, format=PublicFormat.Raw)
        self.obj = {"keytype": "ed25519", "scheme": "ed25519", "keyval": {"public": raw.hex()}}
        self.keyid = hashlib.sha256(canonical(self.obj)).hexdigest()

    def sign(self, payload: bytes) -> str:
        return self.private.sign(payload).hex()


def _sign(signed: dict, *keys: _Key) -> dict:
    payload = canonical(signed)
    return {
        "signatures": [{"keyid": key.keyid, "sig": key.sign(payload)} for key in keys],
        "signed": signed,
    }


def _dump(body: dict) -> bytes:
    return json.dumps(body, separators=(",", ":"), sort_keys=True).encode("utf-8")


def _role(keys: list[_Key], threshold: int) -> dict:
    return {"keyids": [key.keyid for key in keys], "threshold": threshold}


def _root(
    version: int,
    root_keys: list[_Key],
    root_threshold: int,
    targets: _Key,
    snapshot: _Key,
    timestamp: _Key,
    signers: list[_Key],
    *,
    expires: str = EXPIRES,
) -> bytes:
    pool = {key.keyid: key.obj for key in [*root_keys, targets, snapshot, timestamp, *signers]}
    signed = {
        "_type": "root",
        "spec_version": "1.0.36",
        "version": version,
        "expires": expires,
        "consistent_snapshot": True,
        "keys": pool,
        "roles": {
            "root": _role(root_keys, root_threshold),
            "targets": _role([targets], 1),
            "snapshot": _role([snapshot], 1),
            "timestamp": _role([timestamp], 1),
        },
    }
    return _dump(_sign(signed, *signers))


def _publish(
    repo: Path,
    store: Path,
    *,
    package: bytes,
    on_disk: bytes | None = None,
    version: str = "2.1.0",
    timestamp_version: int = 1,
    snapshot_version: int = 1,
    targets_version: int = 1,
    timestamp_expires: str = EXPIRES,
    snapshot_inner_version: int | None = None,
    delegations: dict | None = None,
    bootstrap: bool = True,
    successor: bytes | None = None,
    timestamp_signer: _Key | None = None,
    snapshot_signer: _Key | None = None,
    targets_signer: _Key | None = None,
    root_key: _Key | None = None,
    targets_key: _Key | None = None,
    snapshot_key: _Key | None = None,
    timestamp_key: _Key | None = None,
) -> None:
    root_key = root_key or _publish.root
    targets_key = targets_key or _publish.targets
    snapshot_key = snapshot_key or _publish.snapshot
    timestamp_key = timestamp_key or _publish.timestamp
    repo.mkdir(parents=True, exist_ok=True)
    store.mkdir(parents=True, exist_ok=True)
    if bootstrap and not (store / "root.json").is_file():
        (store / "root.json").write_bytes(
            _root(1, [root_key], 1, targets_key, snapshot_key, timestamp_key, [root_key])
        )
    if successor is not None:
        (repo / "2.root.json").write_bytes(successor)
    stored = package if on_disk is None else on_disk
    digest = hashlib.sha256(package).hexdigest()
    (repo / f"{digest}.{TARGET}").write_bytes(stored)
    targets_signed = {
        "_type": "targets",
        "spec_version": "1.0.36",
        "version": targets_version,
        "expires": EXPIRES,
        "targets": {
            TARGET: {
                "length": len(package),
                "hashes": {"sha256": digest},
                "custom": {"version": version, "component": "dvielle-agent"},
            }
        },
    }
    if delegations is not None:
        targets_signed["delegations"] = delegations
    targets_raw = _dump(_sign(targets_signed, targets_signer or targets_key))
    (repo / f"{targets_version}.targets.json").write_bytes(targets_raw)
    inner_snapshot = snapshot_inner_version or snapshot_version
    snapshot_signed = {
        "_type": "snapshot",
        "spec_version": "1.0.36",
        "version": inner_snapshot,
        "expires": EXPIRES,
        "meta": {"targets.json": _meta(targets_version, targets_raw)},
    }
    snapshot_raw = _dump(_sign(snapshot_signed, snapshot_signer or snapshot_key))
    (repo / f"{snapshot_version}.snapshot.json").write_bytes(snapshot_raw)
    timestamp_signed = {
        "_type": "timestamp",
        "spec_version": "1.0.36",
        "version": timestamp_version,
        "expires": timestamp_expires,
        "meta": {"snapshot.json": _meta(snapshot_version, snapshot_raw)},
    }
    (repo / "timestamp.json").write_bytes(_dump(_sign(timestamp_signed, timestamp_signer or timestamp_key)))


def _meta(version: int, raw: bytes) -> dict:
    return {"version": version, "length": len(raw), "hashes": {"sha256": hashlib.sha256(raw).hexdigest()}}


_publish.root = _Key()
_publish.targets = _Key()
_publish.snapshot = _Key()
_publish.timestamp = _Key()


def _keys() -> None:
    """Each test gets fresh keys so a trusted root cannot leak across cases."""
    _publish.root = _Key()
    _publish.targets = _Key()
    _publish.snapshot = _Key()
    _publish.timestamp = _Key()


def _installed(store: Path) -> bytes | None:
    path = store / "files" / TARGET
    if not path.is_file():
        return None
    return path.read_bytes()


def _fresh(security: dict) -> dict:
    stamp = datetime.now(timezone.utc).isoformat()
    return {
        "runtime": {"state": "running", "heartbeat_at": stamp},
        "collectors": {
            "heartbeat": {"interval_seconds": 5},
            "security": {"status": "ok", "last_success_at": stamp, "interval_seconds": 60},
        },
        "security": security,
        "capability": {},
    }


def test_version_is_2_1_0():
    assert get_version() == "2.2.0"
    assert PRIVILEGED_AUTO_UPDATE is False


def test_canonical_json_sorts_keys_and_escapes_controls():
    assert canonical({"b": 1, "a": "x"}) == b'{"a":"x","b":1}'
    assert canonical({"z": "a\nb"}) == b'{"z":"a\\u000ab"}'
    with pytest.raises(ValueError):
        canonical(1.5)


def test_home_checklist_does_not_launch_or_invent_a_sandbox(tmp_path: Path):
    calls: list[list[str]] = []
    body = open_unfamiliar(
        sku="Home",
        host_folder=r"C:\Unfamiliar",
        feature_installed=True,
        sandbox_exe=r"C:\Windows\System32\WindowsSandbox.exe",
        folder_exists=lambda _path: True,
        launch=lambda argv: calls.append(argv) or 0,
        wsb_dir=tmp_path,
    )
    assert body["offer"] == "UNAVAILABLE"
    assert body["launched"] is False
    assert body["performed"] is False
    assert body["running"] is False
    text = " ".join(body["checklist"])
    assert "SAC" in text and "ASR" in text and "CFA" in text and "Firewall" in text
    assert "not supported on Windows Home" in text
    assert "Application Guard" in text
    assert "Hyper-V" in text
    assert "isolated" not in body["message"].lower()
    assert calls == []
    assert list(tmp_path.glob("*.wsb")) == []


def test_pro_without_the_feature_stays_limited_and_does_not_open_a_window(tmp_path: Path):
    calls: list[list[str]] = []
    body = open_unfamiliar(
        sku="ProOrHigher",
        host_folder=r"C:\Unfamiliar",
        feature_installed=False,
        sandbox_exe=r"C:\Windows\System32\WindowsSandbox.exe",
        folder_exists=lambda _path: True,
        launch=lambda argv: calls.append(argv) or 0,
        wsb_dir=tmp_path,
    )
    assert body["offer"] == "LIMITED"
    assert "not installed" in body["message"]
    assert body["launched"] is False
    assert calls == []


def test_desktop_executable_is_not_labeled_sandbox(tmp_path: Path):
    calls: list[list[str]] = []
    body = open_unfamiliar(
        sku="ProOrHigher",
        host_folder=r"C:\Unfamiliar",
        feature_installed=True,
        sandbox_exe=r"C:\Windows\explorer.exe",
        folder_exists=lambda _path: True,
        launch=lambda argv: calls.append(argv) or 0,
        wsb_dir=tmp_path,
    )
    assert body["offer"] == "REFUSED"
    assert body["launched"] is False
    assert "not Windows Sandbox" in body["message"]
    assert "isolated" not in body["message"].lower()
    assert calls == []


def test_writable_map_and_relative_folder_do_not_launch(tmp_path: Path):
    calls: list[list[str]] = []

    def launch(argv: list[str]) -> int:
        calls.append(argv)
        return 0

    writable = open_unfamiliar(
        sku="ProOrHigher",
        host_folder=r"C:\Unfamiliar",
        feature_installed=True,
        sandbox_exe=r"C:\Windows\System32\WindowsSandbox.exe",
        folder_exists=lambda _path: True,
        launch=launch,
        wsb_dir=tmp_path,
        read_only=False,
    )
    relative = open_unfamiliar(
        sku="ProOrHigher",
        host_folder="Unfamiliar",
        feature_installed=True,
        sandbox_exe=r"C:\Windows\System32\WindowsSandbox.exe",
        folder_exists=lambda _path: True,
        launch=launch,
        wsb_dir=tmp_path,
    )
    assert writable["offer"] == "REFUSED"
    assert "read-only" in writable["message"]
    assert relative["offer"] == "REFUSED"
    assert calls == []


def test_unknown_edition_and_unknown_feature_do_not_launch():
    unknown = observe_sandbox("Unknown", feature_installed=True)
    assert unknown["offer"] == "UNKNOWN"
    assert unknown["running"] is False
    missing = observe_sandbox("ProOrHigher", feature_installed=None)
    assert missing["offer"] == "UNKNOWN"
    assert "not observed" in missing["message"]
    server = observe_sandbox("Server", feature_installed=True)
    assert server["offer"] == "UNAVAILABLE"


def test_pro_launch_is_limited_until_a_network_probe_and_refuses_a_bad_probe(tmp_path: Path):
    from agent.policy.dual import _mutate_depth

    calls: list[list[str]] = []
    token = _mutate_depth.set(1)
    try:
        limited = open_unfamiliar(
            sku="ProOrHigher",
            host_folder=r"C:\Unfamiliar",
            feature_installed=True,
            sandbox_exe=r"C:\Windows\System32\WindowsSandbox.exe",
            folder_exists=lambda _path: True,
            launch=lambda argv: calls.append(list(argv)) or 0,
            network_probe=None,
            wsb_dir=tmp_path,
        )
    finally:
        _mutate_depth.reset(token)
    assert limited["isolation"] == "LIMITED"
    assert limited["network_verification"] == "UNKNOWN"
    assert limited["performed"] is True
    assert "not a verified network-off claim" in limited["message"]
    assert "isolated" not in limited["message"].lower()
    wsb = Path(limited["wsb"]).read_text(encoding="utf-8")
    assert "<Networking>Disable</Networking>" in wsb
    assert "<ReadOnly>true</ReadOnly>" in wsb
    assert ">Enable<" not in wsb
    assert "false" not in wsb.lower()
    assert calls[0][0].lower().endswith("windowssandbox.exe")
    assert all(not part.lower().endswith("explorer.exe") for part in calls[0])
    assert "explorer.exe" in wsb

    def enabled(_path: str) -> str:
        return "enabled"

    token = _mutate_depth.set(1)
    try:
        failed = open_unfamiliar(
            sku="ProOrHigher",
            host_folder=r"C:\Unfamiliar",
            feature_installed=True,
            sandbox_exe=r"C:\Windows\System32\WindowsSandbox.exe",
            folder_exists=lambda _path: True,
            launch=lambda argv: 0,
            network_probe=enabled,
            wsb_dir=tmp_path,
        )
    finally:
        _mutate_depth.reset(token)
    assert failed["network_verification"] == "failed"
    assert failed["isolation"] == "REFUSED"
    assert failed["performed"] is False
    assert "not disabled" in failed["message"]

    def disabled(_path: str) -> str:
        return "disabled"

    token = _mutate_depth.set(1)
    try:
        verified = open_unfamiliar(
            sku="ProOrHigher",
            host_folder=r"C:\Unfamiliar",
            feature_installed=True,
            sandbox_exe=r"C:\Windows\System32\WindowsSandbox.exe",
            folder_exists=lambda _path: True,
            launch=lambda argv: 0,
            network_probe=disabled,
            wsb_dir=tmp_path,
        )
    finally:
        _mutate_depth.reset(token)
    assert verified["isolation"] == "VERIFIED"
    assert verified["network_verification"] == "verified"
    assert any("Group Policy" in item for item in verified["assumptions"])
    assert "not a claim that malware cannot leave the sandbox" in verified["message"]


def test_sandbox_launch_requires_cortex_and_auto_protect_cannot(tmp_path: Path):
    calls: list[list[str]] = []
    with pytest.raises(PolicyDenied):
        open_unfamiliar(
            sku="ProOrHigher",
            host_folder=r"C:\Unfamiliar",
            feature_installed=True,
            sandbox_exe=r"C:\Windows\System32\WindowsSandbox.exe",
            folder_exists=lambda _path: True,
            launch=lambda argv: calls.append(argv) or 0,
            wsb_dir=tmp_path,
        )
    assert calls == []
    engine = ResolutionEngine(
        AgentStore(tmp_path / "agent.db"),
        learn_dir=tmp_path / "learn",
        log_dir=tmp_path / "logs",
        handler_ctx=HandlerContext(
            lookup=lambda _pid: None,
            close=lambda _pid, _name: (False, "unused"),
            sandbox_launch=lambda argv: calls.append(list(argv)) or 0,
            sandbox_folder_exists=lambda _path: True,
            sandbox_wsb_dir=tmp_path,
        ),
    )
    with pytest.raises(PolicyDenied):
        engine.policy.issue("f", "safety.open_unfamiliar", auto=True, subject=r"C:\Unfamiliar")
    finding = {
        "id": "finding-sandbox",
        "subject_identity": r"C:\Unfamiliar",
        "title_simple": "Open this unfamiliar folder in Windows Sandbox",
        "evidence_refs": ["user asked to open an unfamiliar file"],
        "signals": {
            "sku": "Home",
            "host_folder": r"C:\Unfamiliar",
            "feature_installed": True,
            "sandbox_exe": r"C:\Windows\System32\WindowsSandbox.exe",
        },
    }
    issued = engine.policy.issue(finding["id"], "safety.open_unfamiliar", auto=False, subject=finding["subject_identity"])
    home = engine.handlers.invoke("safety.open_unfamiliar", finding, engine.handler_ctx, issued)
    assert home["offer"] == "UNAVAILABLE"
    assert calls == []
    finding["signals"]["sku"] = "ProOrHigher"
    finding["signals"]["network_probe"] = "unavailable"
    issued = engine.policy.issue(finding["id"], "safety.open_unfamiliar", auto=False, subject=finding["subject_identity"])
    opened = engine.handlers.invoke("safety.open_unfamiliar", finding, engine.handler_ctx, issued)
    assert opened["isolation"] == "LIMITED"
    assert opened["performed"] is True
    assert len(calls) == 1


def test_tuf_accepts_a_consistent_repo_and_keeps_last_good_on_faults(tmp_path: Path):
    _keys()
    repo = tmp_path / "repo"
    store = tmp_path / "tuf"
    good = b"good-package"
    _publish(repo, store, package=good)
    accepted = verify_update(store, repo, TARGET, now=NOW)
    assert accepted["last_result"] == "accepted"
    assert accepted["installed_version"] == "2.1.0"
    assert accepted["privileged_auto_update"] is False
    assert accepted["live_binary_attestation"] == "UNCHECKED"
    assert accepted["artifact_sha256"] == hashlib.sha256(good).hexdigest()
    assert _installed(store) == good

    _publish(repo, store, package=good, timestamp_version=1, bootstrap=False)
    same = verify_update(store, repo, TARGET, now=NOW)
    assert same["last_result"] == "unchanged"
    assert _installed(store) == good

    _publish(repo, store, package=good, timestamp_version=1, snapshot_version=1, targets_version=1, bootstrap=False)
    # Trusted timestamp is already version 1. A lower snapshot version needs a higher timestamp
    # that points backward. Build that next.
    _publish(
        repo,
        store,
        package=good,
        timestamp_version=2,
        snapshot_version=1,
        targets_version=1,
        bootstrap=False,
    )
    # snapshot version stays 1, which is not a decrease. Use an explicit rollback below.

    rolled = _rollback_targets(repo, store)
    assert rolled["last_result"] == "rejected"
    assert rolled["last_reason"] == "rollback"
    assert "kept" in rolled["message"]
    assert _installed(store) == good

    _publish(repo, store, package=good, timestamp_version=4, timestamp_expires=PAST, snapshot_version=4, targets_version=4, bootstrap=False)
    frozen = verify_update(store, repo, TARGET, now=NOW)
    assert frozen["last_reason"] == "freeze"
    assert frozen["installed_version"] == "2.1.0"
    assert _installed(store) == good

    bad = b"bad-package!"
    assert len(bad) == len(good)
    _publish(
        repo,
        store,
        package=good,
        on_disk=bad,
        timestamp_version=5,
        snapshot_version=5,
        targets_version=5,
        bootstrap=False,
    )
    hashed = verify_update(store, repo, TARGET, now=NOW)
    assert hashed["last_reason"] == "bad_hash"
    assert _installed(store) == good
    assert hashed["installed_version"] == "2.1.0"


def _rollback_targets(repo: Path, store: Path) -> dict:
    """Trusted targets metadata is version 1. Publish a snapshot that lists version 1 after we
    first advance the trusted snapshot to targets version 2, then roll it back.
    """
    good = b"good-package"
    _publish(repo, store, package=good, timestamp_version=2, snapshot_version=2, targets_version=2, bootstrap=False)
    advanced = verify_update(store, repo, TARGET, now=NOW)
    assert advanced["last_result"] == "accepted"
    _publish(repo, store, package=good, timestamp_version=3, snapshot_version=3, targets_version=1, bootstrap=False)
    return verify_update(store, repo, TARGET, now=NOW)


def test_tuf_rejects_bad_signature_mix_and_match_and_delegation(tmp_path: Path):
    _keys()
    repo = tmp_path / "repo"
    store = tmp_path / "tuf"
    good = b"good-package"
    _publish(repo, store, package=good)
    body = json.loads((repo / "timestamp.json").read_text(encoding="utf-8"))
    body["signatures"][0]["sig"] = "0" * 128
    (repo / "timestamp.json").write_text(json.dumps(body), encoding="utf-8")
    refused = verify_update(store, repo, TARGET, now=NOW)
    assert refused["last_reason"] == "signature"
    assert _installed(store) is None

    _keys()
    repo = tmp_path / "repo2"
    store = tmp_path / "tuf2"
    _publish(repo, store, package=good, snapshot_version=7, snapshot_inner_version=1)
    mixed = verify_update(store, repo, TARGET, now=NOW)
    assert mixed["last_reason"] == "mix_and_match"
    assert _installed(store) is None

    _keys()
    repo = tmp_path / "repo3"
    store = tmp_path / "tuf3"
    _publish(
        repo,
        store,
        package=good,
        delegations={"keys": {}, "roles": [{"name": "projects", "threshold": 1, "paths": [TARGET]}]},
    )
    delegated = verify_update(store, repo, TARGET, now=NOW)
    assert delegated["last_reason"] == "unsupported"
    assert _installed(store) is None


def test_tuf_root_rotation_needs_both_thresholds(tmp_path: Path):
    _keys()
    repo = tmp_path / "repo"
    store = tmp_path / "tuf"
    good = b"good-package"
    _publish(repo, store, package=good)
    assert verify_update(store, repo, TARGET, now=NOW)["last_result"] == "accepted"
    new_root = _Key()
    new_targets = _Key()
    new_snapshot = _Key()
    new_timestamp = _Key()
    only_new = _root(2, [new_root], 1, new_targets, new_snapshot, new_timestamp, [new_root])
    _publish(
        repo,
        store,
        package=good,
        timestamp_version=2,
        snapshot_version=2,
        targets_version=2,
        bootstrap=False,
        successor=only_new,
        targets_key=new_targets,
        snapshot_key=new_snapshot,
        timestamp_key=new_timestamp,
        targets_signer=new_targets,
        snapshot_signer=new_snapshot,
        timestamp_signer=new_timestamp,
    )
    rejected = verify_update(store, repo, TARGET, now=NOW)
    assert rejected["last_reason"] == "signature"
    assert _installed(store) == good
    both = _root(2, [new_root], 1, new_targets, new_snapshot, new_timestamp, [_publish.root, new_root])
    _publish(
        repo,
        store,
        package=b"rotated!!",
        version="2.1.1",
        timestamp_version=2,
        snapshot_version=2,
        targets_version=2,
        bootstrap=False,
        successor=both,
        targets_key=new_targets,
        snapshot_key=new_snapshot,
        timestamp_key=new_timestamp,
    )
    # The failed attempt may have persisted nothing of the new root because the signature
    # check happens before persist. Timestamp on disk is still version 1, so version 2 is new.
    rotated = verify_update(store, repo, TARGET, now=NOW)
    assert rotated["last_result"] == "accepted"
    assert rotated["installed_version"] == "2.1.1"
    assert _installed(store) == b"rotated!!"


def test_pipe_acl_refuses_strangers_and_undefined_ops(tmp_path: Path):
    calls: list[str] = []

    def runner(script: str) -> tuple[str, bool]:
        calls.append(script)
        return "STATUS:OK", False

    pipe = InProcessPipe({"installed-user"}, runner, "ab" * 32)
    stranger = pipe.request("other", {"v": 1, "op": "restrict_network", "token": "ab" * 32, "params": {}})
    assert stranger["code"] == "acl_denied"
    assert stranger["performed"] is False
    undefined = pipe.request(
        "installed-user",
        {"v": 1, "op": "download_github_release", "token": "ab" * 32, "params": {}},
    )
    exclusion = pipe.request(
        "installed-user",
        {"v": 1, "op": "Add-MpPreference", "token": "ab" * 32, "params": {"ExclusionPath": "C:\\DVILLIE"}},
    )
    assert undefined["code"] == "undefined_op"
    assert exclusion["code"] == "undefined_op"
    assert calls == []
    program = tmp_path / "App.exe"
    program.write_bytes(b"MZ")
    missing = pipe.request(
        "installed-user",
        {
            "v": 1,
            "op": "restrict_network",
            "token": "nope",
            "params": {"program": str(program), "profile": "Public"},
        },
    )
    assert missing["code"] == "refused"
    assert calls == []
    sddl = build_pipe_sddl("S-1-5-21-100-200-300-400")
    assert "S-1-5-21-100-200-300-400" in sddl
    assert "S-1-1-0" not in sddl
    assert "(A;;GRGW;;;SY)" in sddl
    with pytest.raises(ValueError):
        build_pipe_sddl("S-1-1-0")
    with pytest.raises(ValueError):
        build_pipe_sddl("S-1-5-32-545")
    described = describe_pipe("S-1-5-21-100-200-300-400")
    assert described["allows_everyone"] is False
    assert described["privileged_service"] is False
    assert described["resident_runlevel"] == "Limited"
    assert described["defined_op"] == "restrict_network"
    assert "not created" in describe_pipe(None)["reason"]


def test_evidence_strip_shows_sandbox_offer_and_tuf_without_a_live_measurement():
    view = attestation_view(Path("/tmp/does-not-exist-dvielle-tuf"))
    data = _fresh(
        {
            "defender_health": {"all_clear": True, "am_running_mode": "Normal", "realtime": "on", "signature_age_days": 0, "signature_freshness": "current"},
            "maps": {"result": "pass"},
            "edition_matrix": {"sku": "Home", "features": {"windows_sandbox": "UNAVAILABLE", "asr": "AVAILABLE", "cfa": "AVAILABLE", "firewall": "AVAILABLE", "smart_app_control": "UNKNOWN", "app_control_authoring": "UNAVAILABLE"}},
            "sandbox": observe_sandbox("Home", feature_installed=True),
            "update": view,
        }
    )
    line = prevention_evidence_line(data)
    assert "Sandbox UNAVAILABLE" in line
    assert "Sandbox offer UNAVAILABLE" in line
    assert "no sandbox session" in line
    assert "privileged auto-update off" in line
    assert "live binary UNCHECKED" in line
    assert "isolated" not in line.lower()


def test_p3_sources_do_not_open_forbidden_paths():
    blob = "\n".join(path.read_text(encoding="utf-8") for path in P3_SOURCES)
    assert "ExclusionPath" not in blob
    assert "Add-MpPreference" not in blob
    assert "api.github.com" not in blob
    assert "urlopen" not in blob
    assert "wdcp.microsoft.com" not in blob
    assert "hvsirdpclient" not in blob
    assert "New-VM" not in blob
    install = (ROOT / "installer" / "install-dvielle.ps1").read_text(encoding="utf-8")
    assert "[string]$RunLevel = 'Limited'" in install
    assert PRIVILEGED_AUTO_UPDATE is False

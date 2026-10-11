"""TUF client path for DVielle package metadata. No privileged auto-update.

Follows The Update Framework specification 1.0.36 (5 August 2026):
https://theupdateframework.github.io/specification/v1.0.36/

Top-level roles are root, timestamp, snapshot, and targets. The client checks
the root chain (version N+1 signed by both the trusted and the new root
thresholds), rejects a lower version (rollback), rejects an expiration that is
not later than the fixed update start time (freeze), and rejects a snapshot or
targets file whose sha256 or length does not match the referring role (bad
hash / mix-and-match). A failed cycle does not replace the installed file.

POUF dvielle-json-ed25519-1: JSON metadata, canonical JSON signatures, ed25519
keys, sha256 required on snapshot, targets, and the package file. Delegations
are refused. This module does not open a network connection and does not fetch
a GitHub Release. The running process is not measured; live binary attestation
stays UNCHECKED.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from agent.ownership import atomic_json
from agent.update.canonical import canonical

SPEC = "1.0.36"
PRIVILEGED_AUTO_UPDATE = False
LIVE_BINARY_ATTESTATION = "UNCHECKED"
MAX_META_BYTES = 1024 * 1024
MAX_TARGET_BYTES = 64 * 1024 * 1024
MAX_ROOT_STEPS = 1024
_NAME = re.compile(r"[A-Za-z0-9._-]+")
_HEX64 = re.compile(r"[0-9a-f]{64}")
_SPEC = re.compile(r"1\.\d+\.\d+")
_VERSION = re.compile(r"[0-9A-Za-z._+-]{1,32}")
_KEPT = " The previous install was kept."


class _Stop(Exception):
    def __init__(self, code: str, reason: str, message: str) -> None:
        self.code = code
        self.reason = reason
        self.message = message


def attestation_view(store: Path) -> dict[str, Any]:
    """Version and metadata attestation. Does not contact a repository."""
    installed = _read_json(Path(store) / "installed.json")
    attempt = _read_json(Path(store) / "last_attempt.json")
    has_root = (Path(store) / "root.json").is_file()
    version = installed.get("version") if isinstance(installed.get("version"), str) else None
    return {
        "spec": f"TUF-{SPEC}",
        "pouf": "dvielle-json-ed25519-1",
        "privileged_auto_update": PRIVILEGED_AUTO_UPDATE,
        "update_channel": "offline-manual",
        "installed_version": version,
        "artifact_sha256": installed.get("sha256") if isinstance(installed.get("sha256"), str) else None,
        "metadata_attestation_sha256": installed.get("metadata_attestation_sha256")
        if isinstance(installed.get("metadata_attestation_sha256"), str)
        else None,
        "live_binary_attestation": LIVE_BINARY_ATTESTATION,
        "last_result": attempt.get("code") if isinstance(attempt.get("code"), str) else ("unknown" if has_root else "not_configured"),
        "last_reason": attempt.get("reason") if isinstance(attempt.get("reason"), str) else "",
        "assumptions": [
            "Trust starts from the root metadata shipped out of band. There is no trust-on-first-use.",
            "Online timestamp keys are not sufficient to authorize an installable file.",
            "A rejected candidate does not replace the last file whose hash matched.",
            "This record is metadata attestation. It is not a measurement of the running process.",
            "Privileged auto-update is off. A GitHub Release asset is not an update channel.",
        ],
    }


def verify_update(
    store: Path,
    repository: Path,
    target: str,
    *,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Serialize an offline verification/activation cycle in the trusted store."""
    store = Path(store)
    try:
        store.mkdir(parents=True, exist_ok=True)
        with _store_lock(store):
            return _verify_update_locked(store, repository, target, now=now)
    except (OSError, _Stop) as exc:
        view = attestation_view(store)
        view["last_result"] = "rejected"
        view["last_reason"] = exc.reason if isinstance(exc, _Stop) else "io_error"
        view["message"] = "The update store could not be locked or accessed. No update cycle was started."
        return view


def _verify_update_locked(
    store: Path, repository: Path, target: str, *, now: datetime | None = None
) -> dict[str, Any]:
    """Verify one local repository against the trusted store.

    ``repository`` is a directory of metadata and the package file. Nothing is
    downloaded. On failure the installed file is left in place.
    """
    store = Path(store)
    repository = Path(repository)
    start = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    store.mkdir(parents=True, exist_ok=True)
    try:
        _recover_install(store)
        if (store / "installed.json").is_file():
            installed = _read_json(store / "installed.json")
            name, digest, length = installed.get("target"), installed.get("sha256"), installed.get("length")
            if (not isinstance(name, str) or not _NAME.fullmatch(name) or name.startswith(".")
                    or not isinstance(digest, str) or not _HEX64.fullmatch(digest)
                    or isinstance(length, bool) or not isinstance(length, int) or not 0 <= length <= MAX_TARGET_BYTES):
                raise _Stop("rejected", "recovery_required", "The installation record is unreadable or invalid.")
        before = _artifact_sha(store)
    except (OSError, _Stop, ValueError, RecursionError):
        view = attestation_view(store)
        view.update(last_result="rejected", last_reason="recovery_required",
                    message="Interrupted activation could not be recovered. No new update was attempted.")
        return view
    try:
        if PRIVILEGED_AUTO_UPDATE:
            raise _Stop("rejected", "refused", "Privileged auto-update is not part of this version." + _KEPT)
        if not _NAME.fullmatch(target) or target.startswith("."):
            raise _Stop("rejected", "bad_metadata", "The package name was not a single file name." + _KEPT)
        _cycle(store, repository, target, start)
    except _Stop as stop:
        after = _artifact_sha(store)
        if before != after:
            raise RuntimeError("update failure replaced the installed file") from stop
        try:
            _record(store, stop.code, stop.reason, stop.message)
        except OSError:
            pass
        view = attestation_view(store)
        view.update(last_result=stop.code, last_reason=stop.reason)
        view["message"] = stop.message
        return view
    except (OSError, ValueError, RecursionError):
        try:
            _recover_install(store, rollback=True)
            kept = before == _artifact_sha(store)
        except (OSError, _Stop, ValueError):
            kept = False
        reason = "io_error" if kept else "recovery_required"
        message = "The update encountered a storage error." + (_KEPT if kept else " Activation recovery is required.")
        try:
            _record(store, "rejected", reason, message)
        except OSError:
            pass
        view = attestation_view(store)
        view.update(last_result="rejected", last_reason=reason, message=message)
        return view
    try:
        _record(store, "accepted", "", "Verified metadata and activated the hash-matching package.")
    except OSError:
        pass
    view = attestation_view(store)
    view.update(last_result="accepted", last_reason="")
    view["message"] = (
        "Verified root, timestamp, snapshot, and targets. The package hash matched. "
        "Privileged auto-update is not enabled. The running process was not measured."
    )
    return view


def _cycle(store: Path, repository: Path, target: str, start: datetime) -> None:
    root_body = _update_root(store, repository, start)
    consistent = root_body["signed"].get("consistent_snapshot", False)
    if not isinstance(consistent, bool):
        raise _Stop("rejected", "bad_metadata", "consistent_snapshot must be a boolean." + _KEPT)
    timestamp_body = _update_timestamp(store, repository, root_body, start)
    snapshot_body = _update_snapshot(store, repository, root_body, timestamp_body, consistent, start)
    targets_body = _update_targets(store, repository, root_body, snapshot_body, consistent, start)
    _install_target(store, repository, targets_body, target, consistent)


def _update_root(store: Path, repository: Path, start: datetime) -> dict[str, Any]:
    current_raw = _read_file(store / "root.json", MAX_META_BYTES)
    if current_raw is None:
        raise _Stop("rejected", "no_root", "No trusted root metadata is installed. Nothing was fetched or installed.")
    current = _envelope(current_raw, "root")
    _verify_role(current, current, "root")
    steps = 0
    while steps < MAX_ROOT_STEPS:
        steps += 1
        version = _version(current["signed"]) + 1
        raw = _read_file(repository / f"{version}.root.json", MAX_META_BYTES)
        if raw is None:
            break
        new = _envelope(raw, "root")
        if _version(new["signed"]) != version:
            raise _Stop("rejected", "rollback", "Root metadata was not exactly the next version." + _KEPT)
        _verify_role(new, current, "root")
        _verify_role(new, new, "root")
        _check_spec(new["signed"])
        if not isinstance(new["signed"].get("consistent_snapshot"), bool):
            raise _Stop("rejected", "bad_metadata", "consistent_snapshot must be a boolean." + _KEPT)
        _atomic_bytes(store / "root.json", raw)
        if _role_keyids(current, "timestamp") != _role_keyids(new, "timestamp") or _role_keyids(
            current, "snapshot"
        ) != _role_keyids(new, "snapshot"):
            (store / "timestamp.json").unlink(missing_ok=True)
            (store / "snapshot.json").unlink(missing_ok=True)
        current = new
    else:
        raise _Stop("rejected", "endless_data", "The root chain was too long." + _KEPT)
    _check_expiry(current["signed"], start)
    return current


def _update_timestamp(
    store: Path, repository: Path, root: dict[str, Any], start: datetime
) -> dict[str, Any]:
    raw = _require(repository / "timestamp.json")
    new = _envelope(raw, "timestamp")
    _verify_role(new, root, "timestamp")
    meta = new["signed"].get("meta")
    if not isinstance(meta, dict) or set(meta) != {"snapshot.json"}:
        raise _Stop("rejected", "bad_metadata", "Timestamp metadata must describe only snapshot.json." + _KEPT)
    _meta_entry(new["signed"], "snapshot.json", MAX_META_BYTES)
    previous = _load_optional(store / "timestamp.json", "timestamp")
    if previous is not None:
        new_version = _version(new["signed"])
        old_version = _version(previous["signed"])
        if new_version < old_version:
            raise _Stop("rejected", "rollback", "Timestamp metadata moved to an older version." + _KEPT)
        if new_version == old_version:
            # Discard the same-version remote envelope, but resume unfinished target
            # work using trusted cached metadata. Expired cached metadata is refused.
            _verify_role(previous, root, "timestamp")
            _check_expiry(previous["signed"], start)
            return previous
        if _meta_entry(new["signed"], "snapshot.json", MAX_META_BYTES)["version"] < _meta_entry(
            previous["signed"], "snapshot.json", MAX_META_BYTES
        )["version"]:
            raise _Stop("rejected", "rollback", "Timestamp metadata rolled the snapshot version backward." + _KEPT)
    _check_expiry(new["signed"], start)
    _atomic_bytes(store / "timestamp.json", raw)
    return new


def _update_snapshot(
    store: Path,
    repository: Path,
    root: dict[str, Any],
    timestamp: dict[str, Any],
    consistent: bool,
    start: datetime,
) -> dict[str, Any]:
    entry = _meta_entry(timestamp["signed"], "snapshot.json", MAX_META_BYTES)
    name = f"{entry['version']}.snapshot.json" if consistent else "snapshot.json"
    raw = _require(repository / name)
    _bind(raw, entry)
    new = _envelope(raw, "snapshot")
    _verify_role(new, root, "snapshot")
    if _version(new["signed"]) != entry["version"]:
        raise _Stop("rejected", "mix_and_match", "Snapshot version did not match timestamp metadata." + _KEPT)
    previous = _load_optional(store / "snapshot.json", "snapshot")
    if previous is not None:
        old_meta = previous["signed"].get("meta")
        new_meta = new["signed"].get("meta")
        if not isinstance(old_meta, dict) or not isinstance(new_meta, dict):
            raise _Stop("rejected", "bad_metadata", "Snapshot metadata did not list files." + _KEPT)
        for filename in old_meta:
            if filename not in new_meta:
                raise _Stop("rejected", "rollback", "Snapshot metadata dropped a previously listed file." + _KEPT)
            if _meta_entry(new["signed"], filename, MAX_META_BYTES)["version"] < _meta_entry(
                previous["signed"], filename, MAX_META_BYTES
            )["version"]:
                raise _Stop("rejected", "rollback", "Snapshot metadata rolled a targets version backward." + _KEPT)
    if "targets.json" not in (new["signed"].get("meta") or {}):
        raise _Stop("rejected", "bad_metadata", "Snapshot metadata did not list targets.json." + _KEPT)
    _check_expiry(new["signed"], start)
    _atomic_bytes(store / "snapshot.json", raw)
    return new


def _update_targets(
    store: Path,
    repository: Path,
    root: dict[str, Any],
    snapshot: dict[str, Any],
    consistent: bool,
    start: datetime,
) -> dict[str, Any]:
    entry = _meta_entry(snapshot["signed"], "targets.json", MAX_META_BYTES)
    name = f"{entry['version']}.targets.json" if consistent else "targets.json"
    raw = _require(repository / name)
    _bind(raw, entry)
    new = _envelope(raw, "targets")
    _verify_role(new, root, "targets")
    if _version(new["signed"]) != entry["version"]:
        raise _Stop("rejected", "mix_and_match", "Targets version did not match snapshot metadata." + _KEPT)
    delegations = new["signed"].get("delegations")
    if delegations not in (None, {}):
        roles = delegations.get("roles") if isinstance(delegations, dict) else ["present"]
        if roles:
            raise _Stop(
                "rejected",
                "unsupported",
                "Delegated targets metadata is not verified by this client." + _KEPT,
            )
    _check_expiry(new["signed"], start)
    _atomic_bytes(store / "targets.json", raw)
    return new


def _install_target(
    store: Path, repository: Path, targets: dict[str, Any], target: str, consistent: bool
) -> None:
    listed = targets["signed"].get("targets")
    if not isinstance(listed, dict) or target not in listed or not isinstance(listed[target], dict):
        raise _Stop("rejected", "missing_target", "Trusted targets metadata does not list that package." + _KEPT)
    info = listed[target]
    entry = {
        "version": 1,
        "length": info.get("length"),
        "hashes": info.get("hashes"),
    }
    if isinstance(entry["length"], int) and not isinstance(entry["length"], bool) and entry["length"] > MAX_TARGET_BYTES:
        raise _Stop("rejected", "endless_data", "The package length is above the client limit." + _KEPT)
    checked = _meta_entry({"meta": {target: entry}}, target, MAX_TARGET_BYTES)
    digest = checked["hashes"]["sha256"]
    filename = f"{digest}.{target}" if consistent else target
    custom = info.get("custom") if isinstance(info.get("custom"), dict) else {}
    version = custom.get("version")
    shown = version if isinstance(version, str) and _VERSION.fullmatch(version) else "UNKNOWN"
    attestation = hashlib.sha256(canonical(targets["signed"])).hexdigest()
    installed = {
            "version": shown,
            "target": target,
            "sha256": digest,
            "length": checked["length"],
            "metadata_attestation_sha256": attestation,
        }
    if _read_json(store / "installed.json") == installed and _artifact_sha(store) == digest:
        raise _Stop("unchanged", "same_version", "Trusted metadata and the installed target already match.")
    raw = _require(repository / filename, limit=MAX_TARGET_BYTES)
    _bind(raw, checked)
    _commit_install(store, target, raw, installed)


def _record(store: Path, code: str, reason: str, message: str) -> None:
    atomic_json(
        store / "last_attempt.json",
        {
            "code": code,
            "reason": reason,
            "message": message,
            "privileged_auto_update": False,
            "live_binary_attestation": LIVE_BINARY_ATTESTATION,
        },
    )


def _envelope(raw: bytes, expected: str) -> dict[str, Any]:
    try:
        body = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise _Stop("rejected", "bad_metadata", "Metadata was not JSON." + _KEPT) from exc
    if not isinstance(body, dict):
        raise _Stop("rejected", "bad_metadata", "Metadata was not an object." + _KEPT)
    signed = body.get("signed")
    signatures = body.get("signatures")
    if not isinstance(signed, dict) or not isinstance(signatures, list) or not signatures:
        raise _Stop("rejected", "bad_metadata", "Metadata did not contain a signed object and signatures." + _KEPT)
    if signed.get("_type") != expected:
        raise _Stop("rejected", "bad_metadata", "Metadata role type did not match the file." + _KEPT)
    _check_spec(signed)
    _version(signed)
    return body


def _check_spec(signed: dict[str, Any]) -> None:
    spec = signed.get("spec_version")
    if not isinstance(spec, str) or not _SPEC.fullmatch(spec):
        raise _Stop("rejected", "bad_metadata", "spec_version must be a 1.x.y string." + _KEPT)


def _version(signed: dict[str, Any]) -> int:
    value = signed.get("version")
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise _Stop("rejected", "bad_metadata", "Metadata version was not a positive integer." + _KEPT)
    return value


def _check_expiry(signed: dict[str, Any], start: datetime) -> None:
    raw = signed.get("expires")
    if not isinstance(raw, str):
        raise _Stop("rejected", "bad_metadata", "Metadata did not contain an expiration." + _KEPT)
    try:
        stamp = datetime.strptime(raw, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise _Stop("rejected", "bad_metadata", "Metadata expiration was not UTC YYYY-MM-DDTHH:MM:SSZ." + _KEPT) from exc
    if stamp <= start:
        raise _Stop(
            "rejected",
            "freeze",
            "Metadata expiration is not later than the update start time." + _KEPT,
        )


def _keys(signed: dict[str, Any]) -> dict[str, dict[str, Any]]:
    raw = signed.get("keys")
    if not isinstance(raw, dict) or not raw:
        raise _Stop("rejected", "bad_metadata", "Root metadata did not contain keys." + _KEPT)
    found: dict[str, dict[str, Any]] = {}
    for keyid, key in raw.items():
        if not isinstance(keyid, str) or not isinstance(key, dict):
            raise _Stop("rejected", "bad_metadata", "A root key was not an object." + _KEPT)
        try:
            digest = hashlib.sha256(canonical(key)).hexdigest()
        except ValueError as exc:
            raise _Stop("rejected", "bad_metadata", "A root key could not be canonicalized." + _KEPT) from exc
        if digest != keyid:
            raise _Stop("rejected", "bad_metadata", "A key identifier did not match the key." + _KEPT)
        found[keyid] = key
    return found


def _role(signed: dict[str, Any], name: str) -> tuple[list[str], int]:
    roles = signed.get("roles")
    if not isinstance(roles, dict) or not isinstance(roles.get(name), dict):
        raise _Stop("rejected", "bad_metadata", f"Root metadata has no {name} role." + _KEPT)
    role = roles[name]
    keyids = role.get("keyids")
    threshold = role.get("threshold")
    if not isinstance(keyids, list) or not keyids or any(not isinstance(item, str) for item in keyids):
        raise _Stop("rejected", "bad_metadata", f"The {name} role keys were not a list." + _KEPT)
    if isinstance(threshold, bool) or not isinstance(threshold, int) or threshold < 1 or threshold > len(set(keyids)):
        raise _Stop("rejected", "bad_metadata", f"The {name} threshold is not usable." + _KEPT)
    return keyids, threshold


def _role_keyids(body: dict[str, Any], name: str) -> tuple[str, ...]:
    keyids, _threshold = _role(body["signed"], name)
    return tuple(sorted(set(keyids)))


def _verify_role(body: dict[str, Any], root: dict[str, Any], role_name: str) -> None:
    keys = _keys(root["signed"])
    keyids, threshold = _role(root["signed"], role_name)
    try:
        payload = canonical(body["signed"])
    except ValueError as exc:
        raise _Stop("rejected", "bad_metadata", "Signed metadata could not be canonicalized." + _KEPT) from exc
    accepted: set[str] = set()
    for item in body["signatures"]:
        if not isinstance(item, dict):
            continue
        keyid = item.get("keyid")
        sig = item.get("sig")
        if not isinstance(keyid, str) or not isinstance(sig, str) or keyid in accepted:
            continue
        if keyid not in keyids or keyid not in keys:
            continue
        if _ed25519(keys[keyid], sig, payload):
            accepted.add(keyid)
    if len(accepted) < threshold:
        raise _Stop("rejected", "signature", f"The {role_name} role did not meet its signature threshold." + _KEPT)


def _ed25519(key: dict[str, Any], signature: str, payload: bytes) -> bool:
    if key.get("keytype") != "ed25519" or key.get("scheme") != "ed25519":
        return False
    keyval = key.get("keyval")
    public = keyval.get("public") if isinstance(keyval, dict) else None
    if not isinstance(public, str) or not _HEX64.fullmatch(public):
        return False
    if not re.fullmatch(r"[0-9a-f]{128}", signature):
        return False
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(public)).verify(bytes.fromhex(signature), payload)
    except (InvalidSignature, ValueError):
        return False
    return True


def _meta_entry(signed: dict[str, Any], filename: str, limit: int) -> dict[str, Any]:
    meta = signed.get("meta")
    if not isinstance(meta, dict) or not isinstance(meta.get(filename), dict):
        raise _Stop("rejected", "bad_metadata", f"Metadata did not describe {filename}." + _KEPT)
    entry = meta[filename]
    version = entry.get("version")
    length = entry.get("length")
    hashes = entry.get("hashes")
    if isinstance(version, bool) or not isinstance(version, int) or version < 1:
        raise _Stop("rejected", "bad_metadata", f"{filename} version was not a positive integer." + _KEPT)
    if isinstance(length, bool) or not isinstance(length, int) or length < 0:
        raise _Stop("rejected", "bad_metadata", f"{filename} length was not an integer." + _KEPT)
    if length > limit:
        raise _Stop("rejected", "endless_data", f"{filename} is larger than the client limit." + _KEPT)
    digest = hashes.get("sha256") if isinstance(hashes, dict) else None
    if not isinstance(digest, str) or not _HEX64.fullmatch(digest):
        raise _Stop("rejected", "bad_hash", f"{filename} did not include a sha256 hash." + _KEPT)
    return {"version": version, "length": length, "hashes": {"sha256": digest}}


def _bind(raw: bytes, entry: dict[str, Any]) -> None:
    if len(raw) != entry["length"]:
        raise _Stop("rejected", "bad_hash", "A metadata or package length did not match." + _KEPT)
    if hashlib.sha256(raw).hexdigest() != entry["hashes"]["sha256"]:
        raise _Stop("rejected", "bad_hash", "A metadata or package hash did not match." + _KEPT)


def _load_optional(path: Path, expected: str) -> dict[str, Any] | None:
    raw = _read_file(path, MAX_META_BYTES)
    if raw is None:
        return None
    return _envelope(raw, expected)


def _require(path: Path, limit: int = MAX_META_BYTES) -> bytes:
    raw = _read_file(path, limit)
    if raw is None:
        raise _Stop("rejected", "missing_metadata", f"{path.name} was not in the local repository." + _KEPT)
    return raw


def _read_file(path: Path, limit: int) -> bytes | None:
    if not _NAME.fullmatch(path.name):
        raise _Stop("rejected", "bad_metadata", "A repository file name was not accepted." + _KEPT)
    if not path.is_file():
        return None
    with path.open("rb") as stream:
        raw = stream.read(limit + 1)
    if len(raw) > limit:
        raise _Stop("rejected", "endless_data", f"{path.name} is larger than the client limit." + _KEPT)
    return raw


def _atomic_bytes(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(f".{path.name}.{uuid4().hex}.tmp")
    try:
        with temp.open("xb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp, path)
    finally:
        temp.unlink(missing_ok=True)


def _read_json(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {}
    try:
        raw = _read_file(path, MAX_META_BYTES)
        body = json.loads(raw.decode("utf-8")) if raw is not None else {}
    except (OSError, UnicodeError, ValueError, _Stop, RecursionError):
        return {}
    return body if isinstance(body, dict) else {}


def _artifact_sha(store: Path) -> str | None:
    installed = _read_json(store / "installed.json")
    target = installed.get("target")
    if not isinstance(target, str) or not _NAME.fullmatch(target):
        return None
    path = store / "files" / target
    if not path.is_file():
        return None
    raw = _read_file(path, MAX_TARGET_BYTES)
    return hashlib.sha256(raw).hexdigest() if raw is not None else None


@contextmanager
def _store_lock(store: Path):
    """OS releases this lock on crash; a leftover file never means a stale lock."""
    with (store / "update.lock").open("a+b") as stream:
        stream.seek(0, os.SEEK_END)
        if stream.tell() == 0:
            stream.write(b"\0")
            stream.flush()
        stream.seek(0)
        if os.name == "nt":
            import msvcrt
            try:
                msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
            except OSError as exc:
                raise _Stop("rejected", "busy", "Another update cycle owns this store.") from exc
            try:
                yield
            finally:
                stream.seek(0)
                msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            import fcntl
            try:
                fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError as exc:
                raise _Stop("rejected", "busy", "Another update cycle owns this store.") from exc
            try:
                yield
            finally:
                fcntl.flock(stream.fileno(), fcntl.LOCK_UN)


def _commit_install(store: Path, target: str, raw: bytes, installed: dict[str, Any]) -> None:
    destination = store / "files" / target
    backup_name = ".rollback-" + uuid4().hex
    backup = store / "files" / backup_name
    previous_bytes = _read_file(destination, MAX_TARGET_BYTES)
    previous = _read_json(store / "installed.json")
    if previous_bytes is not None:
        _atomic_bytes(backup, previous_bytes)
    journal = {"target": target, "backup": backup_name if previous_bytes is not None else None,
               "backup_sha256": hashlib.sha256(previous_bytes).hexdigest() if previous_bytes is not None else None,
               "previous": previous, "next": installed}
    try:
        _atomic_bytes(store / "activation.json", json.dumps(journal, allow_nan=False).encode("utf-8"))
    except OSError:
        backup.unlink(missing_ok=True)
        raise
    # Journal precedes both replacements. Recovery chooses a complete commit or
    # restores both old bytes and their corresponding installation record.
    _atomic_bytes(destination, raw)
    _atomic_bytes(store / "installed.json", json.dumps(installed, allow_nan=False).encode("utf-8"))
    _recover_install(store)


def _recover_install(store: Path, *, rollback: bool = False) -> None:
    path = store / "activation.json"
    if not path.is_file():
        return
    raw = _require(path)
    try:
        journal = json.loads(raw.decode("utf-8"))
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise _Stop("rejected", "recovery_required", "Activation journal is invalid.") from exc
    if not isinstance(journal, dict):
        raise _Stop("rejected", "recovery_required", "Activation journal must be an object.")
    target = journal.get("target")
    previous, next_record = journal.get("previous"), journal.get("next")
    backup_name = journal.get("backup")
    if (not isinstance(target, str) or not _NAME.fullmatch(target) or target.startswith(".")
            or not isinstance(previous, dict) or not isinstance(next_record, dict)
            or (backup_name is not None and not re.fullmatch(r"\.rollback-[0-9a-f]{32}", str(backup_name)))):
        raise _Stop("rejected", "recovery_required", "Activation journal fields are invalid.")
    destination = store / "files" / target
    current = _read_file(destination, MAX_TARGET_BYTES)
    complete = (_read_json(store / "installed.json") == next_record and current is not None
                and hashlib.sha256(current).hexdigest() == next_record.get("sha256"))
    if rollback or not complete:
        if backup_name is not None:
            old = _require(store / "files" / backup_name, MAX_TARGET_BYTES)
            if hashlib.sha256(old).hexdigest() != journal.get("backup_sha256"):
                raise _Stop("rejected", "recovery_required", "Activation backup hash is invalid.")
            _atomic_bytes(destination, old)
        else:
            destination.unlink(missing_ok=True)
        if previous:
            _atomic_bytes(store / "installed.json", json.dumps(previous, allow_nan=False).encode("utf-8"))
        else:
            (store / "installed.json").unlink(missing_ok=True)
    path.unlink()
    if backup_name is not None:
        try:
            (store / "files" / backup_name).unlink(missing_ok=True)
        except OSError:
            pass  # Commit/recovery is complete; an unused backup may remain.

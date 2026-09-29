"""Resident identity: venv Scripts launcher or the base interpreter, never a lookalike."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import importlib.util
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
_SPEC = importlib.util.spec_from_file_location("verify_runtime", ROOT / "scripts" / "verify_runtime.py")
verify_runtime = importlib.util.module_from_spec(_SPEC)
assert _SPEC.loader is not None
_SPEC.loader.exec_module(verify_runtime)

CREATED = 1_700_000_000.0


class _Process:
    def __init__(self, exe: Path, cmdline: list[str], create_time: float = CREATED) -> None:
        self._exe = exe
        self._cmdline = cmdline
        self._create_time = create_time

    def exe(self) -> str:
        return str(self._exe)

    def create_time(self) -> float:
        return self._create_time

    def cmdline(self) -> list[str]:
        return list(self._cmdline)


def _touch(path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"")
    return path


def _snapshot(**overrides: object) -> dict:
    runtime = {
        "state": "running",
        "owner_token": "lease-token",
        "heartbeat_at": datetime.now(timezone.utc).isoformat(),
        "owner_pid": 4242,
        "owner_create_time": CREATED,
    }
    runtime.update(overrides)
    return {"runtime": runtime}


def _bind(monkeypatch: pytest.MonkeyPatch, *, prefix: Path, base_prefix: Path, executable: Path, process: _Process) -> None:
    monkeypatch.setattr(verify_runtime.sys, "prefix", str(prefix))
    monkeypatch.setattr(verify_runtime.sys, "base_prefix", str(base_prefix))
    monkeypatch.setattr(verify_runtime.sys, "executable", str(executable))
    monkeypatch.setattr(verify_runtime.psutil, "Process", lambda pid: process)


def _layout(tmp_path: Path) -> tuple[Path, Path, Path, Path]:
    """Scripts redirector plus a pythoncore-shaped base install. No real user path."""
    venv = tmp_path / "install" / ".venv"
    scripts = venv / "Scripts"
    base = tmp_path / "Python" / "pythoncore-3.12-64"
    launcher = _touch(scripts / "python.exe")
    owner = _touch(base / "pythonw.exe")
    return venv, base, launcher, owner


def test_venv_base_prefix_owner_is_current(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    venv, base, launcher, owner = _layout(tmp_path)
    _bind(
        monkeypatch,
        prefix=venv,
        base_prefix=base,
        executable=launcher,
        process=_Process(owner, [str(owner), "-m", "agent.main"]),
    )
    assert verify_runtime.resident_is_current(_snapshot()) is True


def test_same_launcher_directory_stays_current(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    venv, base, launcher, _owner = _layout(tmp_path)
    sibling = _touch(launcher.parent / "pythonw.exe")
    _bind(
        monkeypatch,
        prefix=venv,
        base_prefix=base,
        executable=launcher,
        process=_Process(sibling, [str(sibling), "-m", "agent.main"]),
    )
    assert verify_runtime.resident_is_current(_snapshot()) is True


def test_posix_base_bin_is_the_interpreter_directory(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    venv = tmp_path / "venv"
    base = tmp_path / "base"
    launcher = _touch(venv / "bin" / "python")
    owner = _touch(base / "bin" / "python3.12")
    _bind(
        monkeypatch,
        prefix=venv,
        base_prefix=base,
        executable=launcher,
        process=_Process(owner, [str(owner), "-m", "agent.main"]),
    )
    assert verify_runtime.resident_is_current(_snapshot()) is True


def test_wrong_interpreter_directory_is_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    venv, base, launcher, _owner = _layout(tmp_path)
    other = _touch(tmp_path / "other" / "pythonw.exe")
    _bind(
        monkeypatch,
        prefix=venv,
        base_prefix=base,
        executable=launcher,
        process=_Process(other, [str(other), "-m", "agent.main"]),
    )
    assert verify_runtime.resident_is_current(_snapshot()) is False


def test_nested_file_under_base_prefix_is_not_the_interpreter_directory(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    venv, base, launcher, _owner = _layout(tmp_path)
    nested = _touch(base / "Lib" / "pythonw.exe")
    _bind(
        monkeypatch,
        prefix=venv,
        base_prefix=base,
        executable=launcher,
        process=_Process(nested, [str(nested), "-m", "agent.main"]),
    )
    assert verify_runtime.resident_is_current(_snapshot()) is False


def test_base_interpreter_is_rejected_when_verifier_is_not_in_a_venv(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _venv, base, launcher, owner = _layout(tmp_path)
    _bind(
        monkeypatch,
        prefix=base,
        base_prefix=base,
        executable=launcher,
        process=_Process(owner, [str(owner), "-m", "agent.main"]),
    )
    assert verify_runtime.resident_is_current(_snapshot()) is False


def test_stale_heartbeat_is_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    venv, base, launcher, owner = _layout(tmp_path)
    _bind(
        monkeypatch,
        prefix=venv,
        base_prefix=base,
        executable=launcher,
        process=_Process(owner, [str(owner), "-m", "agent.main"]),
    )
    old = (datetime.now(timezone.utc) - timedelta(seconds=31)).isoformat()
    assert verify_runtime.resident_is_current(_snapshot(heartbeat_at=old)) is False


def test_wrong_module_is_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    venv, base, launcher, owner = _layout(tmp_path)
    _bind(
        monkeypatch,
        prefix=venv,
        base_prefix=base,
        executable=launcher,
        process=_Process(owner, [str(owner), "-m", "agent.other"]),
    )
    assert verify_runtime.resident_is_current(_snapshot()) is False


def test_module_without_dash_m_is_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    venv, base, launcher, owner = _layout(tmp_path)
    _bind(
        monkeypatch,
        prefix=venv,
        base_prefix=base,
        executable=launcher,
        process=_Process(owner, [str(owner), "agent.main"]),
    )
    assert verify_runtime.resident_is_current(_snapshot()) is False


def test_non_python_image_is_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    venv, base, launcher, _owner = _layout(tmp_path)
    decoy = _touch(base / "cmd.exe")
    _bind(
        monkeypatch,
        prefix=venv,
        base_prefix=base,
        executable=launcher,
        process=_Process(decoy, [str(decoy), "-m", "agent.main"]),
    )
    assert verify_runtime.resident_is_current(_snapshot()) is False


def test_create_time_mismatch_is_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    venv, base, launcher, owner = _layout(tmp_path)
    _bind(
        monkeypatch,
        prefix=venv,
        base_prefix=base,
        executable=launcher,
        process=_Process(owner, [str(owner), "-m", "agent.main"], create_time=CREATED + 5),
    )
    assert verify_runtime.resident_is_current(_snapshot()) is False


def test_naive_heartbeat_is_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    venv, base, launcher, owner = _layout(tmp_path)
    _bind(
        monkeypatch,
        prefix=venv,
        base_prefix=base,
        executable=launcher,
        process=_Process(owner, [str(owner), "-m", "agent.main"]),
    )
    assert verify_runtime.resident_is_current(_snapshot(heartbeat_at="2026-09-29T12:00:00")) is False

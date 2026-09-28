"""Selected install root is the only config and data identity."""

from pathlib import Path

import pytest

from agent.runtime import runtime_paths
from agent.utils import resolve_config_paths, resolve_data_dir


def _tree(root: Path, *, data_dir: str | None, marker: str) -> Path:
    config = root / "config"
    config.mkdir(parents=True)
    data_line = "null" if data_dir is None else f'"{data_dir}"'
    (config / "config.yaml").write_text(
        "agent:\n"
        f"  data_dir: {data_line}\n"
        "modes: {monitor_only: true, enable_toasts: false}\n"
        "modules: {}\n"
        "logging: {level: INFO}\n",
        encoding="utf-8",
    )
    (config / "whitelists.yaml").write_text("{}\n", encoding="utf-8")
    (config / "telemetry-domains.txt").write_text(marker + "\n", encoding="utf-8")
    return config


def test_selected_config_does_not_bleed_into_another_tree(tmp_path, monkeypatch):
    other = tmp_path / "DVILLIE"
    selected = tmp_path / "Selected"
    _tree(other, data_dir=None, marker="other-tree")
    selected_config = _tree(selected, data_dir=None, marker="selected-tree")
    monkeypatch.setattr("agent.utils.PROJECT_ROOT", other)
    config, _whitelists, telemetry, install_root, data_dir = runtime_paths(selected_config)
    assert install_root == selected.resolve()
    assert data_dir == (selected / "data").resolve()
    assert telemetry.read_text(encoding="utf-8").strip() == "selected-tree"
    assert "other-tree" not in telemetry.read_text(encoding="utf-8")
    assert config["agent"]["data_dir"] is None


def test_default_tree_is_the_running_code_not_a_sibling_install(tmp_path, monkeypatch):
    sibling = tmp_path / "DVILLIE"
    here = tmp_path / "running"
    _tree(sibling, data_dir=None, marker="sibling")
    _tree(here, data_dir=None, marker="running")
    monkeypatch.setattr("agent.utils.PROJECT_ROOT", here)
    _config, _whitelists, telemetry, install_root, data_dir = runtime_paths(None)
    assert install_root == here.resolve()
    assert data_dir == (here / "data").resolve()
    assert telemetry.read_text(encoding="utf-8").strip() == "running"
    paths = resolve_config_paths(None)
    assert paths[0] == here / "config" / "config.yaml"


def test_foreign_data_dir_is_refused(tmp_path):
    from agent.runtime import load_runtime_config

    selected = tmp_path / "Selected"
    other = tmp_path / "Other" / "data"
    config_dir = _tree(selected, data_dir=str(other), marker="selected")
    config, _, telemetry = load_runtime_config(config_dir)
    with pytest.raises(ValueError, match="outside the selected install root"):
        resolve_data_dir(config, telemetry.resolve().parent.parent)


def test_start_verify_and_stop_share_runtime_paths():
    root = Path(__file__).resolve().parents[1]
    for relative in (
        "agent/main.py",
        "agent/controller.py",
        "scripts/verify_runtime.py",
        "dvielle/gui/app.py",
    ):
        text = (root / relative).read_text(encoding="utf-8")
        assert "runtime_paths" in text
        assert "_resolve_data_dir" not in text

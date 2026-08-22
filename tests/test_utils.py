"""Tests for utility helpers."""

import pytest

from agent.utils import ip_in_whitelist, load_yaml


def test_ip_in_whitelist_exact() -> None:
    assert ip_in_whitelist("127.0.0.1", ["127.0.0.1"])
    assert not ip_in_whitelist("8.8.8.8", ["127.0.0.1"])


def test_ip_in_whitelist_cidr() -> None:
    assert ip_in_whitelist("192.168.1.50", ["192.168.0.0/16"])
    assert not ip_in_whitelist("10.0.0.1", ["192.168.0.0/16"])


def test_load_yaml_missing(tmp_path) -> None:
    assert load_yaml(tmp_path / "missing.yaml") == {}

"""Shared pytest configuration for D'Vielle tests.

Some contract tests exercise the explicit *test harnesses* (GrantStore and
executable_lease with ``test_harness=True``, and ``LoopbackHelper``). The
product deliberately refuses to run those harnesses under an elevated
(administrator) token. Hosted CI runners such as GitHub's ``windows-latest``
run elevated, so these tests cannot exercise their contract there.

Tests marked ``requires_unelevated`` are skipped, with a clear reason, when
the test process itself is elevated. The product refusal is NOT relaxed or
patched here; it is still covered by tests that monkeypatch the elevation
probe (for example ``tests/test_repair_install_helper.py``) and by every
local, non-elevated run, where these tests execute normally.
"""
from __future__ import annotations

import pytest

ELEVATED_SKIP_REASON = (
    "Requires a non-elevated token: the product deliberately refuses elevated "
    "tokens for test harnesses (hosted CI runners are elevated). Run locally "
    "from a standard-user shell to exercise this test."
)


def _process_is_elevated() -> bool:
    try:
        from agent.privilege.helper import _is_elevated
    except Exception:  # pragma: no cover - import problems surface elsewhere
        return False
    try:
        return bool(_is_elevated())
    except Exception:  # pragma: no cover - treat an unknown probe as elevated
        return True


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line(
        "markers",
        "requires_unelevated: skip when the test process runs with an elevated "
        "(administrator) token, because the product refuses elevated test harnesses.",
    )


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    marked = [item for item in items if item.get_closest_marker("requires_unelevated")]
    if not marked or not _process_is_elevated():
        return
    skip = pytest.mark.skip(reason=ELEVATED_SKIP_REASON)
    for item in marked:
        item.add_marker(skip)
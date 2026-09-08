"""Pulse-hardening: run_hardened must bound wall time even when a descendant
holds the stdout pipe open (the CPython #88693 Windows wedge). The load-bearing
guarantee is 'returns within ~timeout + secondary', never minutes.
"""

from __future__ import annotations

import sys
import time

from agent.utils import run_hardened


def test_returns_output_normally():
    stdout, timed_out = run_hardened(
        [sys.executable, "-c", "print('hello-runner')"], timeout=10
    )
    assert timed_out is False
    assert stdout is not None and "hello-runner" in stdout


def test_missing_binary_is_degraded_not_raised():
    stdout, timed_out = run_hardened(["this_binary_does_not_exist_dv"], timeout=5)
    assert stdout is None
    assert timed_out is False  # spawn failure, not a timeout


def test_hung_child_is_bounded():
    """A child that sleeps far past the timeout must be killed and return fast."""
    t0 = time.monotonic()
    stdout, timed_out = run_hardened(
        [sys.executable, "-c", "import time; time.sleep(30)"], timeout=1, secondary=1
    )
    elapsed = time.monotonic() - t0
    assert timed_out is True
    assert elapsed < 12, f"runner took {elapsed:.1f}s — should be ~timeout+secondary"


def test_grandchild_holding_pipe_does_not_wedge():
    """The exact wedge: the direct child spawns a grandchild that inherits the
    stdout handle and sleeps, then the parent exits. With subprocess.run this hangs
    on the untimed second communicate(); run_hardened must still return promptly.
    """
    src = (
        "import subprocess, sys\n"
        "subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)'])\n"
        "sys.exit(0)\n"
    )
    t0 = time.monotonic()
    _stdout, _timed_out = run_hardened([sys.executable, "-c", src], timeout=1, secondary=1)
    elapsed = time.monotonic() - t0
    assert elapsed < 15, f"runner wedged for {elapsed:.1f}s on a pipe-holding grandchild"

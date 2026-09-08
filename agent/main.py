"""DVielle headless entry point — thin CLI over the shared Adaptive Nerve runtime.

Runtime construction (store, twin, policy, capability probe, collector cadence)
lives in agent.runtime.build_runtime, shared with the Mission Console controller
so both run the identical nerve loop. run_once is re-exported for compatibility.
"""

from __future__ import annotations

import argparse
import logging
import signal
import sys
import time
from pathlib import Path

from agent.runtime import build_runtime, run_once  # noqa: F401 (run_once re-exported)

_running = True
logger = logging.getLogger("dvielle")


def _handle_signal(signum, frame) -> None:
    global _running
    _running = False


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="DVielle — Deep Vigilance Agent")
    parser.add_argument("--once", action="store_true", help="Run one pulse cycle and exit")
    parser.add_argument("--config-dir", type=Path, default=None, help="Override config directory")
    args = parser.parse_args(argv)

    rt = build_runtime(config_dir=args.config_dir)

    signal.signal(signal.SIGINT, _handle_signal)
    signal.signal(signal.SIGTERM, _handle_signal)

    if args.once:
        rt.run_pulse_once()
        return 0

    rt.prime()  # prime heartbeat immediately
    while _running:
        try:
            rt.tick()
        except Exception:
            logger.exception("Nerve tick failed")
        time.sleep(rt.sleep_hint())

    logger.info("DVielle stopped")
    return 0


if __name__ == "__main__":
    sys.exit(main())

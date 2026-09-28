"""Resident headless agent with exclusive ownership and graceful lifecycle."""
from __future__ import annotations

import argparse
import logging
import signal
import sys
import time
from pathlib import Path

from agent.ownership import RuntimeAlreadyRunning, request_shutdown
from agent.runtime import build_runtime, run_once, runtime_paths  # noqa: F401

logger = logging.getLogger('dvielle')


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description='DVielle monitoring agent')
    group = parser.add_mutually_exclusive_group()
    group.add_argument('--once', action='store_true', help='One observe-only diagnostic pass')
    group.add_argument('--stop', action='store_true', help='Request graceful shutdown of the current owner')
    parser.add_argument('--config-dir', type=Path, default=None)
    args = parser.parse_args(argv)
    try:
        if args.stop:
            *_, data_dir = runtime_paths(args.config_dir)
            return 0 if request_shutdown(data_dir) else 1
        rt = build_runtime(config_dir=args.config_dir)
    except RuntimeAlreadyRunning:
        print('DVielle is already running; no duplicate collector was started.')
        return 0 if not args.once else 2
    except Exception as exc:
        print(f'DVielle startup failed: {exc}', file=sys.stderr)
        return 1

    from dvielle.gui.notify_policy import set_notification_mode
    set_notification_mode('headless')
    running = True

    def stop(signum, frame):
        nonlocal running
        running = False

    signal.signal(signal.SIGINT, stop)
    signal.signal(signal.SIGTERM, stop)
    try:
        if args.once:
            return 1 if rt.run_pulse_once() else 0
        rt.prime()
        while running and not rt.stop_requested():
            rt.tick()
            time.sleep(rt.sleep_hint())
        return 0
    except Exception:
        logger.exception('Runtime failed; exiting for scheduled restart')
        return 1
    finally:
        if not rt.close(timeout=60):
            logger.error('Collectors did not drain; owner lock held until process exit')


if __name__ == '__main__':
    sys.exit(main())

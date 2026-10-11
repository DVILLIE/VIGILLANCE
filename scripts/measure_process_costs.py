"""Bounded, read-only measurement of an explicitly selected process tree."""
from __future__ import annotations

import argparse
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import psutil
from agent.assessment.resources import ProcessTreeSampler
from agent.local_files import atomic_text


def main():
    parser = argparse.ArgumentParser(description="D'Vielle actual sampled process costs")
    parser.add_argument('--pid', type=int, required=True)
    parser.add_argument('--samples', type=int, default=20)
    parser.add_argument('--interval', type=float, default=1)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if not 2 <= args.samples <= 600 or not 0.1 <= args.interval <= 10 or args.pid <= 0:
        parser.error('Require positive PID, 2–600 samples and interval 0.1–10 seconds.')
    try:
        process = psutil.Process(args.pid)
        created = process.create_time()
        sampler = ProcessTreeSampler(args.pid, max_samples=args.samples)
        state = 'completed'
        started = datetime.now(timezone.utc).isoformat()
        for index in range(args.samples):
            if not process.is_running() or psutil.Process(args.pid).create_time() != created:
                state = 'target_exited_or_replaced'
                break
            sampler.sample()
            if index + 1 < args.samples:
                time.sleep(args.interval)
    except (psutil.Error, OSError) as exc:
        parser.error('Process observation unavailable: ' + type(exc).__name__)
    report = sampler.report()
    report.update(state=state, started=started,
        finished=datetime.now(timezone.utc).isoformat(),
        scope='Explicit selected process and visible descendants; not all application processes.',
        requested_samples=args.samples, interval_seconds=args.interval,
        target_identity={'pid': args.pid, 'created_epoch_seconds': created},
        mutations=[], acceptance='not_evaluated',
        workload='Actual current host activity; no controlled foreground workload or battery comparison.')
    atomic_text(args.output, json.dumps(report, indent=2, allow_nan=False))
    print(json.dumps({'state': state, 'total_samples': report['total_samples'],
                      'sampled_peak_rss_sum_bytes': report['sampled_peak_rss_sum_bytes']}))
    return 0 if state == 'completed' else 2


if __name__ == '__main__':
    raise SystemExit(main())

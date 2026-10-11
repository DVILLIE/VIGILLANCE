"""Observed process-tree costs; sampled evidence, never a hard-cap claim."""
from __future__ import annotations

import os
import time
from collections import deque

import psutil


class ProcessTreeSampler:
    def __init__(self, pid: int | None = None, *, max_samples: int = 1024):
        if type(max_samples) is not int or not 2 <= max_samples <= 10000:
            raise ValueError('Sample capacity must be an integer from 2 to 10000.')
        self.pid = os.getpid() if pid is None else pid
        self.previous: dict[tuple, float] = {}
        self.last = None
        self.samples = deque(maxlen=max_samples)
        self.total_samples = 0
        self.peak_rss = None
        self.partial_seen = False

    def sample(self) -> dict:
        now = time.monotonic()
        identities = {}
        rss = 0
        missing = 0
        try:
            root = psutil.Process(self.pid)
            processes = [root, *root.children(recursive=True)]
        except (psutil.Error, OSError):
            processes = []
            missing += 1
        for process in processes[:128]:
            try:
                with process.oneshot():
                    identity = (process.pid, process.create_time())
                    cpu = process.cpu_times()
                    identities[identity] = cpu.user + cpu.system
                    rss += process.memory_info().rss
            except (psutil.Error, OSError):
                missing += 1
        elapsed = now - self.last if self.last is not None else None
        shared = set(identities) & set(self.previous)
        delta = sum(max(0, identities[key] - self.previous[key]) for key in shared)
        cores = psutil.cpu_count(logical=True)
        lower_bound = delta / elapsed * 100 if shared and elapsed is not None and elapsed > 0 else None
        stable = self.last is not None and set(identities) == set(self.previous) and not missing
        core_percent = lower_bound if stable else None
        coverage = ('unavailable' if not identities else
                    'partial' if missing or len(processes) > 128 else 'sampled')
        sample = {'observed_monotonic': now, 'elapsed_seconds': elapsed,
                  'process_count': len(identities), 'rss_sum_bytes': rss if identities else None,
                  'cpu_core_percent': core_percent,
                  'cpu_lower_bound_core_percent': lower_bound,
                  'cpu_coverage': 'warming_up' if self.last is None else 'sampled' if stable and shared else 'partial',
                  'cpu_machine_percent': core_percent / cores if core_percent is not None and cores else None,
                  'unreadable_processes': missing, 'coverage': coverage,
                  'new_processes': len(set(identities) - set(self.previous)),
                  'departed_processes': len(set(self.previous) - set(identities))}
        self.previous, self.last = identities, now
        self.total_samples += 1
        if sample['rss_sum_bytes'] is not None:
            self.peak_rss = max(self.peak_rss or 0, sample['rss_sum_bytes'])
        self.partial_seen |= coverage != 'sampled'
        self.samples.append(sample)
        return sample

    def report(self) -> dict:
        measured = [sample for sample in self.samples if sample['rss_sum_bytes'] is not None]
        return {'scope': 'Assessment process and descendants visible at checkpoints; not every D\'Vielle process.',
                'samples': list(self.samples),
                'sampled_peak_rss_sum_bytes': self.peak_rss,
                'total_samples': self.total_samples,
                'retained_sample_capacity': self.samples.maxlen,
                'discarded_sample_details': self.total_samples - len(self.samples),
                'coverage': 'sampled' if measured and not self.partial_seen else 'partial',
                'notes': ['Shared pages can be counted in more than one RSS; this is not unique physical memory.',
                          'Short-lived processes between checkpoints and exited-process final CPU are not measured.',
                          'New processes require a second sample for a CPU delta; missing costs are not zero.',
                          'Checkpoint peaks are not continuous peaks or foreground-workload benchmarks.',
                          'No hard CPU cap, no zero-slowdown guarantee and no other user process termination.']}

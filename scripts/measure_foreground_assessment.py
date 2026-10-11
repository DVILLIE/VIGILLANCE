"""Actual bounded foreground comparison; never disables existing protection."""
import argparse
import hashlib
import json
import statistics
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import psutil
from agent.assessment import AssessmentEngine, AssessmentScope
from agent.local_files import atomic_text


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    block = bytes(range(256)) * 4096  # Fixed real work; not a fabricated performance result.
    rows, forbidden, errors = [], [], []
    started = datetime.now(timezone.utc).isoformat()

    def audit(event, arguments):
        if event in {'socket.connect','socket.getaddrinfo','socket.sendto'}:
            forbidden.append(event)
            raise PermissionError('This local-only measurement forbids Python network initiation.')

    sys.addaudithook(audit)
    def workload(phase):
        start = time.perf_counter()
        checksum = None
        for _ in range(600):
            checksum = hashlib.sha256(block).hexdigest()
        rows.append({'phase':phase, 'elapsed_seconds':time.perf_counter()-start,
                     'processed_bytes':len(block)*600,'result_sha256':checksum})
    for _ in range(4):
        workload('before')
    report_box = []
    ready = threading.Event()
    def assessment():
        try:
            engine = AssessmentEngine(args.directory)
            ready.set()
            report_box.append(engine.run(AssessmentScope()))
        except Exception as exc:
            errors.append(type(exc).__name__)
            ready.set()
    worker = threading.Thread(target=assessment, daemon=True)
    worker.start()
    ready.wait(5)
    for _ in range(4):
        active = worker.is_alive()
        workload('assessment_active' if active else 'assessment_already_finished')
    worker.join(timeout=60)
    for _ in range(4):
        workload('after')
    baseline = [row['elapsed_seconds'] for row in rows if row['phase'] in {'before','after'}]
    during = [row['elapsed_seconds'] for row in rows if row['phase'] == 'assessment_active']
    battery = psutil.sensors_battery()
    result = {'started':started,'finished':datetime.now(timezone.utc).isoformat(),
              'state':'completed' if not worker.is_alive() and report_box and not errors else 'incomplete',
              'scope':'This fixed SHA-256 foreground workload with one local assessment added; resident protection stayed enabled.',
              'trials':rows,'baseline_median_seconds':statistics.median(baseline),
              'concurrent_median_seconds':statistics.median(during) if during else None,
              'concurrent_over_baseline_ratio':statistics.median(during)/statistics.median(baseline) if during else None,
              'python_network_attempts_blocked':forbidden,'assessment_errors':errors,
              'assessment_id':report_box[0]['id'] if report_box else None,
              'assessment_state':report_box[0]['state'] if report_box else None,
              'attack_path_count':len(report_box[0].get('attack_path_review',{}).get('paths',[])) if report_box else None,
              'battery':{'available':battery is not None,'power_plugged':battery.power_plugged if battery else None,
                         'percent':battery.percent if battery else None,'discharge_comparison':'not_measured'},
              'mutations':[], 'acceptance':'not_evaluated',
              'limits':['One host and workload; ongoing user activity is not controlled.',
                        'Sequential phases are not randomized or a whole-app disabled comparison.',
                        'Python audit denial does not isolate Windows services or subprocess network behavior.',
                        'No universal slowdown, independent privacy, or battery-life certification.']}
    atomic_text(args.output, json.dumps(result, indent=2))
    print(json.dumps({key:result[key] for key in ('state','assessment_state','attack_path_count','concurrent_over_baseline_ratio','python_network_attempts_blocked')}))


if __name__ == '__main__':
    main()

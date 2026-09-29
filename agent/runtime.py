"""Single-owner, workload-aware monitoring runtime shared with attached consoles."""
from __future__ import annotations

import logging
import math
import os
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Any

import psutil

from agent.capability import probe_capabilities
from agent.modules.attacks import AttackMonitor
from agent.modules.browser_guard import BrowserGuard
from agent.modules.connections import ConnectionMonitor
from agent.modules.disk import DiskMonitor
from agent.modules.microsoft_guard import MicrosoftGuard
from agent.modules.network_info import NetworkMonitor
from agent.modules.privacy_guard import PrivacyGuard
from agent.modules.ram import RamMonitor
from agent.modules.resource_advisor import ResourceAdvisor
from agent.modules.security import SecurityMonitor
from agent.cpu_contract import published_contract
from agent.nerve import Cadence, CollectorSpec, CollectionIncomplete, NervePlane, default_intervals
from agent.ownership import RuntimeLease, RuntimeIntentionallyStopped, read_json
from agent.policy import PolicyGate
from agent.store.db import AgentStore
from agent.twin import SelfBudget, TwinStore
from agent.utils import (load_yaml, resolve_config_paths, resolve_data_dir,
                         set_process_priority, setup_logging, show_toast)
from agent.win_memory import memory_under_pressure
from agent.workload import WorkloadTracker

logger = logging.getLogger('dvielle')
COLLECTOR_NAMES = ('connections', 'attacks', 'browser_guard', 'ram', 'resource_advisor',
                   'disk', 'security', 'privacy_guard', 'network_info', 'microsoft_guard')


def _utc() -> str:
    return datetime.now(timezone.utc).isoformat()


def load_runtime_config(config_dir: Path | None = None) -> tuple[dict, dict, Path]:
    config_path, whitelist_path, telemetry_path = resolve_config_paths(config_dir)
    if not config_path.exists():
        raise FileNotFoundError(f'Missing agent config: {config_path}')
    config, whitelists = load_yaml(config_path), load_yaml(whitelist_path)
    if not isinstance(config, dict) or not isinstance(whitelists, dict):
        raise ValueError('configuration and whitelists must be mappings')
    for section in ('agent', 'modes', 'modules', 'nerve', 'logging', 'retention', 'workload', 'budget', 'network', 'thresholds'):
        if section in config and not isinstance(config[section], dict):
            raise ValueError(f'{section} must be a mapping')
    for section in ('modes', 'modules'):
        if any(not isinstance(v, bool) for v in config.get(section, {}).values()):
            raise ValueError(f'{section} values must be YAML true/false booleans')
    if not isinstance(config.get('network', {}).get('allow_public_ip_lookup', False), bool):
        raise ValueError('network.allow_public_ip_lookup must be a YAML true/false boolean')
    default_intervals(config)
    return config, whitelists, telemetry_path


def runtime_paths(config_dir: Path | None = None) -> tuple[dict, dict, Path, Path, Path]:
    """One install identity for start, verify, stop, config, and data.

    ``config_dir`` None means the tree that contains this code (``PROJECT_ROOT``).
    A selected config directory wins over any other install that happens to exist.
    """
    config, whitelists, telemetry_path = load_runtime_config(config_dir)
    install_root = telemetry_path.resolve().parent.parent
    return config, whitelists, telemetry_path, install_root, resolve_data_dir(config, install_root)


def _ingest_keep_on(store, observed: dict) -> None:
    """Feed the latest samples into the keep-on engine. Mutations stay behind DualGate."""
    try:
        from agent.engine.service import collect_startup_items, ingest_monitors

        ingest_monitors(
            store,
            security=observed.get("security"),
            advice=observed.get("advice") or [],
            disks=observed.get("disks") or [],
            startup_items=collect_startup_items(),
            collect_live=True,
        )
    except Exception:
        logger.exception("keep-on ingest failed")


def _collector_callbacks(store, config, whitelists, telemetry_file, scripts_dir, modes, twin, policy, observed=None):
    """Persistent providers with independent sampling and per-section timestamps."""
    cortex = policy.cortex if policy else None
    providers: dict[str, Any] = {}
    toast_times: dict[str, float] = {}
    observed = observed if observed is not None else {}

    def provider(name, factory):
        if name not in providers:
            providers[name] = factory()
        return providers[name]

    def toast(message, severity='WARNING'):
        now = time.monotonic()
        if modes.get('enable_toasts', True) and now - toast_times.get(message, -1e9) >= 300:
            toast_times[message] = now
            # Keep repeated alarms bounded without losing the durable evidence.
            if len(toast_times) > 128:
                for key, stamp in list(toast_times.items()):
                    if now - stamp >= 300:
                        toast_times.pop(key, None)
            show_toast('DVielle', message, severity=severity)

    def connections():
        p = provider('connections', lambda: ConnectionMonitor(store, config, whitelists))
        alerts = p.run(monitor_only=True)
        if getattr(p, 'collection_error', None):
            raise RuntimeError(p.collection_error)
        for a in alerts:
            toast(f'Review connection: {a.process_name} -> {a.remote_addr}')

    def attacks():
        p = provider('attacks', lambda: AttackMonitor(store, config, scripts_dir, cortex=cortex))
        alerts = p.run(enable_auto_block=False)
        if getattr(p, 'collection_error', None):
            raise RuntimeError(p.collection_error)
        for a in alerts:
            if a.attempt_count >= int(config.get('thresholds', {}).get('failed_logon_block_after', 5)) and a.source_ip:
                toast(f'Failed logons from {a.source_ip}: {a.attempt_count} in the observed window', 'CRITICAL')
        if any(a.collection_degraded for a in alerts):
            raise CollectionIncomplete('Security event coverage is incomplete; bounded catch-up continues at normal cadence')

    def browser():
        p = provider('browser_guard', lambda: BrowserGuard(store, config))
        for a in p.run():
            toast(a.message, a.severity)
        if getattr(p, 'collection_error', None):
            raise RuntimeError(p.collection_error)

    def ram():
        p = provider('ram', lambda: RamMonitor(store, config, scripts_dir, cortex=cortex))
        p.run(enable_trim=False)

    def advisor():
        p = provider('resource_advisor', lambda: ResourceAdvisor(store, config, cortex=cortex))
        # Heartbeat already primed psutil on its own thread. A fresh advisor thread's
        # cpu_percent(interval=0) is an unprimed 0.0, so reuse the timestamped sample.
        system = (twin.as_dict().get('system') or {}) if twin else None
        advice = list(p.run(system=system))
        observed["advice"] = advice
        for a in advice:
            toast(f'{a.headline}. {a.suggestion}')

    def disk():
        p = provider('disk', lambda: DiskMonitor(store, config))
        disks = p.run(enable_cleanup=False)
        if not disks:
            if twin:
                twin.patch(system={'disk_percent': None, 'disk_free_gb': None, 'disk_sampled_at': _utc()})
            raise RuntimeError('No readable disk samples')
        observed["disks"] = disks
        system_drive = os.environ.get('SystemDrive', 'C:').rstrip('\\').lower()
        primary = next((d for d in disks if d.mount.rstrip('\\/').lower() == system_drive), disks[0])
        if twin:
            twin.patch(system={'disk_percent': primary.percent_used, 'disk_free_gb': primary.free_gb,
                               'disk_sampled_at': _utc()})
        for d in disks:
            if d.low_space:
                toast(f'Low disk: {d.free_gb:.1f} GB free on {d.mount}. Review Windows Storage.')
        if getattr(p, 'collection_error', None):
            raise CollectionIncomplete(p.collection_error)

    def security():
        p = provider('security', lambda: SecurityMonitor(store, config, cortex=cortex))
        sec = p.run()
        observed["security"] = sec
        if twin:
            health = sec.defender_health or {}
            twin.patch(security={'defender_enabled': sec.defender_enabled,
                                 'realtime_protection': sec.realtime_protection,
                                 'firewall_enabled': sec.firewall_enabled,
                                 'issues': list(sec.issues), 'sampled_at': _utc(),
                                 'defender_health': health,
                                 'maps': sec.maps or {},
                                 'edition_matrix': sec.edition_matrix or {},
                                 'prevention': sec.prevention or {},
                                 'recovery': sec.recovery or {},
                                 'promotion': sec.promotion or {},
                                 'firewall_assist': sec.firewall_assist or {},
                                 'coverage': 'partial' if p.collection_error else 'complete'})
            query_updates = {}
            if health.get('query_state'):
                query_updates['defender'] = health['query_state']
            if sec.firewall_query_state:
                query_updates['firewall'] = sec.firewall_query_state
            if query_updates:
                twin.patch(capability=query_updates)
        for issue in sec.issues:
            toast(issue, 'CRITICAL')
        if p.collection_error:
            raise CollectionIncomplete(p.collection_error)

    def privacy():
        p = provider('privacy_guard', lambda: PrivacyGuard(store, config, telemetry_file))
        results = p.run()
        if twin:
            twin.patch(privacy={'checks': [vars(r) for r in results], 'sampled_at': _utc()})
        if getattr(p, 'collection_error', None):
            raise RuntimeError(p.collection_error)

    def microsoft():
        p = provider('microsoft_guard', lambda: MicrosoftGuard(store, config, telemetry_file,
                    scripts_dir, whitelists.get('never_block_domains', []), cortex=cortex))
        p.run(monitor_only=True)
        if getattr(p, 'collection_error', None):
            raise CollectionIncomplete(p.collection_error)

    def network():
        p = provider('network_info', lambda: NetworkMonitor(store, config))
        snap = p.run()
        if twin:
            twin.patch(network={**snap.to_dict(), 'sampled_at': _utc()})
        if getattr(p, 'collection_error', None):
            raise CollectionIncomplete(p.collection_error)

    return dict(zip(COLLECTOR_NAMES, (connections, attacks, browser, ram, advisor,
                                     disk, security, privacy, network, microsoft)))


def run_once(store, config, whitelists, telemetry_file, scripts_dir, modes, modules,
             twin: TwinStore | None = None, policy: PolicyGate | None = None) -> list[str]:
    """Explicit diagnostic pass. Collectors stay observe-only; keep-on may act only through DualGate."""
    observed: dict = {}
    callbacks = _collector_callbacks(store, config, whitelists, telemetry_file, scripts_dir, modes, twin, policy, observed)
    failed = []
    for name, callback in callbacks.items():
        if not modules.get(name, True):
            continue
        if name == 'microsoft_guard' and not modes.get('enable_microsoft_guard', True):
            continue
        try:
            callback()
        except Exception:
            failed.append(name)
            logger.exception('collector failed: %s', name)
    _ingest_keep_on(store, observed)
    return failed


@dataclass
class Runtime:
    store: AgentStore
    twin: TwinStore
    policy: PolicyGate
    nerve: NervePlane
    config: dict
    whitelists: dict
    telemetry_path: Path
    caps: Any
    intervals: dict[str, float]
    lease: RuntimeLease
    _heartbeat: Callable[[], None]
    _pulse: Callable[[], None]
    _callbacks: dict[str, Callable]
    _closed: bool = False

    def prime(self) -> None:
        spec = next(c for c in self.nerve.collectors if c.name == 'heartbeat')
        spec.running, spec.status = True, 'running'
        self.nerve._notify(spec)
        self.nerve._execute(spec)
        if spec.status == 'error':
            raise RuntimeError(spec.error)
        self.twin.publish()

    def run_pulse_once(self) -> list[str]:
        failed = []
        self.prime()
        for name, callback in self._callbacks.items():
            spec = next(c for c in self.nerve.collectors if c.name == name)
            if spec.enabled:
                spec.running, spec.status = True, 'running'
                self.nerve._notify(spec)
                self.nerve._execute(spec)
                if spec.status in {'error', 'partial'}:
                    failed.append(name)
        self._pulse()
        self.twin.publish()
        return failed

    def tick(self) -> list[str]:
        return self.nerve.run_due()

    def sleep_hint(self) -> float:
        return self.nerve.sleep_seconds()

    def stop_requested(self) -> bool:
        return self.lease.stop_requested()

    def close(self, timeout: float = 60.0) -> bool:
        if self._closed:
            return True
        self.twin.patch(runtime={'state': 'stopping'})
        try:
            self.twin.publish()
        except OSError:
            logger.exception('Cannot publish stopping state')
        if not self.nerve.close(timeout):
            return False
        self.twin.patch(runtime={'state': 'stopped', 'stopped_at': _utc()})
        try:
            self.twin.publish()
        except OSError:
            logger.exception('Cannot publish stopped state')
        finally:
            self.lease.release()
            self._closed = True
        return True


def build_runtime(config_dir: Path | None = None, *, on_pulse: Callable[[], None] | None = None,
                  previous_owner_token: str | None = None) -> Runtime:
    config, whitelists, telemetry_path, install_root, data_dir = runtime_paths(config_dir)
    lease = RuntimeLease(data_dir)
    lease.acquire()  # before stores, collectors, logs, or priority changes
    try:
        if previous_owner_token:
            previous = (read_json(data_dir / 'twin.json') or {}).get('runtime', {})
            if (isinstance(previous, dict) and previous.get('owner_token') == previous_owner_token
                    and previous.get('state') in {'stopping', 'stopped'}):
                raise RuntimeIntentionallyStopped('The previous owner stopped intentionally')
        return _build_owned(config, whitelists, telemetry_path, install_root, data_dir, lease, on_pulse)
    except BaseException:
        lease.release()
        raise


def _build_owned(config, whitelists, telemetry_path, install_root, data_dir, lease, on_pulse):
    log_cfg = config.get('logging', {})
    setup_logging(data_dir, level=log_cfg.get('level', 'INFO'),
                  max_mb=int(log_cfg.get('max_file_mb', 10)), backup_count=int(log_cfg.get('backup_count', 3)))
    set_process_priority(config.get('agent', {}).get('process_priority', 'below_normal'))
    store = AgentStore(data_dir / 'agent.db')
    twin = TwinStore(data_dir / 'twin.jsonl', latest_path=data_dir / 'twin.json',
                     max_snapshot_bytes=int(config.get('retention', {}).get('twin_max_mb', 5)) * 1024 * 1024)
    policy = PolicyGate.create(store)
    caps = probe_capabilities(deep=False)
    twin.set_capability(caps)
    intervals = default_intervals(config)
    if 'T3' in caps.tier:
        intervals['pulse'] = max(90, intervals['pulse'])
        intervals['heartbeat'] = max(8, intervals['heartbeat'])
    cfg = config.get('nerve', {})
    nerve = NervePlane(idle=False, max_workers=max(1, min(4, int(cfg.get('max_workers', 2)))))
    workload = WorkloadTracker(config)
    proc = psutil.Process()
    twin.patch(runtime={'state': 'starting', 'owner_pid': proc.pid,
                        'owner_create_time': proc.create_time(), 'owner_token': lease.token,
                        'started_at': _utc(), 'cycle_count': 0, 'monitor_only': True})
    twin.publish()
    budget = config.get('budget', {})
    cpu_limit = float(budget.get('max_cpu_percent', 1.0))
    rss_limit = float(budget.get('max_rss_mb', 150))
    if any(not math.isfinite(v) or v <= 0 for v in (cpu_limit, rss_limit)):
        raise ValueError('budget limits must be finite and positive')
    primed = False
    budget_high = 0
    budget_recovered = 0
    summary_lock = threading.Lock()

    def status(c):
        values = {'status': c.status, 'error': c.error, 'duration_ms': c.duration_ms,
                  'interval_seconds': c.interval_seconds, 'failures': c.failures}
        if c.status == 'running':
            values['last_attempt_at'] = _utc()
        elif c.status == 'ok':
            values['last_success_at'] = _utc()
        elif c.status == 'partial':
            values['last_partial_at'] = _utc()
        twin.collector_status(c.name, **values)

    nerve.on_status = status

    def heartbeat():
        nonlocal primed, budget_high, budget_recovered
        started = time.perf_counter()
        snap = twin.update_memory()
        twin.patch(memory={'sampled_at': _utc()})
        try:
            cpu = psutil.cpu_percent(interval=None)
            own_cpu = proc.cpu_percent(interval=None) / max(1, caps.cpu_count)
            rss = proc.memory_info().rss
        except (psutil.Error, OSError):
            cpu, own_cpu, rss = None, None, None
        if not primed:
            cpu, own_cpu = None, None  # first nonblocking sample has no valid interval
            primed = True
        state = workload.sample(cpu, memory_under_pressure(snap))
        nerve.workload_maximum, nerve.idle = state.maximum, state.idle
        twin.patch(workload=state.to_dict(), system={'cpu_percent': cpu, 'cpu_sampled_at': _utc()})
        over = (own_cpu is not None and own_cpu > cpu_limit) or (rss is not None and rss > rss_limit * 1024**2)
        recovered = own_cpu is not None and own_cpu <= cpu_limit * 0.75 and rss is not None and rss <= rss_limit * 1024**2
        budget_high = budget_high + 1 if over else 0
        budget_recovered = budget_recovered + 1 if recovered else 0
        if budget_high >= 3:
            nerve.budget_exceeded = True
        elif budget_recovered >= 3:
            nerve.budget_exceeded = False
        contract = published_contract(config)
        twin.update_self_budget(SelfBudget(rss_bytes=rss, cpu_percent=own_cpu,
            last_cycle_ms=(time.perf_counter() - started) * 1000, collectors_ran=['heartbeat'],
            exceeded=nerve.budget_exceeded, cpu_limit_percent=cpu_limit, rss_limit_mb=rss_limit,
            cpu_contract=contract,
            reason='Optional collection deferred: sustained footprint exceeds budget' if nerve.budget_exceeded
                  else ('Within configured budget' if own_cpu is not None else 'CPU interval not available')))
        twin.patch(runtime={'state': 'running', 'heartbeat_at': _utc()})
        status(next(c for c in nerve.collectors if c.name == 'heartbeat'))
        twin.publish()

    observed: dict = {}
    callbacks = _collector_callbacks(store, config, whitelists, telemetry_path, install_root / 'scripts',
                                      config.get('modes', {}), twin, policy, observed)

    def pulse():
        with summary_lock:
            data = twin.as_dict()
            mem, sysd, sec = data['memory'], data['system'], data['security']
            store.log_health_snapshot({'ram_percent': mem.get('memory_load_percent'),
                'ram_available_mb': mem.get('avail_phys_mb'), 'disk_percent_used': sysd.get('disk_percent'),
                'disk_free_gb': sysd.get('disk_free_gb'), 'defender_enabled': sec.get('defender_enabled'),
                'firewall_enabled': sec.get('firewall_enabled'),
                'details': {'sampled_at': {'memory': mem.get('sampled_at'), 'disk': sysd.get('disk_sampled_at'),
                                         'security': sec.get('sampled_at')}, 'collectors': data['collectors']}})
            twin.patch(runtime={'cycle_count': data['runtime']['cycle_count'] + 1, 'last_pulse_at': _utc()})
            twin.snapshot()
            _ingest_keep_on(store, observed)
            if on_pulse:
                try:
                    on_pulse()
                except Exception:
                    logger.exception('console callback failed')

    def capability():
        twin.set_capability(probe_capabilities(deep=True))

    def retention():
        store.prune_old(config.get('retention'))

    nerve.register(CollectorSpec('heartbeat', Cadence.HEARTBEAT, intervals['heartbeat'], run=heartbeat, critical=True))
    defaults = {'attacks': 30, 'security': 120, 'disk': 300, 'privacy_guard': 300, 'network_info': 300}
    overrides = cfg.get('collectors', {})
    if not isinstance(overrides, dict):
        raise ValueError('nerve.collectors must be a mapping')
    for name, callback in callbacks.items():
        critical = name in ('attacks', 'security', 'ram')
        cadence = float(overrides.get(name, defaults.get(name, intervals['pulse'])))
        if not math.isfinite(cadence) or cadence <= 0:
            raise ValueError(f'Invalid cadence for {name}')
        cadence = max(10, cadence)
        enabled = config.get('modules', {}).get(name, True)
        if name == 'microsoft_guard':
            enabled = enabled and config.get('modes', {}).get('enable_microsoft_guard', True)
        # resource_advisor stays eligible during host pressure. It is background,
        # not critical, and its cadence is floored in NervePlane so it cannot
        # take the worker reserved for security collectors or spin the runtime.
        pressure_response = name == 'resource_advisor'
        nerve.register(CollectorSpec(name, Cadence.PULSE, cadence, enabled=enabled, run=callback,
                        background=True, critical=critical,
                        defer_under_maximum_workload=not critical and not pressure_response,
                        pressure_response=pressure_response))
        twin.collector_status(name, status='pending' if enabled else 'disabled', interval_seconds=cadence)
    # Summary is held-state persistence, not a global collection pass.
    nerve.register(CollectorSpec('pulse', Cadence.PULSE, intervals['pulse'], run=pulse, background=True))
    nerve.register(CollectorSpec('capability', Cadence.IDLE_DEEP, intervals['idle_deep'], run=capability,
                                background=True, defer_under_maximum_workload=True))
    # Retention remains scheduled even under load: evidence growth must stay bounded.
    nerve.register(CollectorSpec('retention', Cadence.PULSE, intervals['idle_deep'], run=retention,
                                background=True, critical=True))
    store.log_event('runtime', 'INFO', 'Single monitoring owner acquired; autonomous collection only',
                    {'pid': proc.pid, 'collectors': list(callbacks)})
    return Runtime(store, twin, policy, nerve, config, whitelists, telemetry_path, caps, intervals,
                   lease, heartbeat, pulse, callbacks)

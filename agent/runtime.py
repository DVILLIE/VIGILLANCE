"""Shared runtime — one Nerve + Twin for both the headless agent and the GUI.

`python -m agent.main` (headless) and the Mission Console's AgentController both
call build_runtime(), so they run the SAME adaptive nerve loop
(heartbeat / pulse / idle_deep) with the Digital Twin populated. There is no
longer a divergent fixed-interval "scan everything" path in the GUI.

run_once (the PULSE body) lives here so main.py can stay a thin CLI and the
controller does not import it separately.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable

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
from agent.nerve import Cadence, CollectorSpec, NervePlane, default_intervals
from agent.policy import PolicyGate
from agent.store.db import AgentStore
from agent.twin import SelfBudget, TwinStore
from agent.utils import (
    DEFAULT_DATA_DIR,
    INSTALL_ROOT,
    load_yaml,
    resolve_config_paths,
    set_process_priority,
    setup_logging,
    show_toast,
)
from agent.version import get_version

logger = logging.getLogger("dvielle")


def _resolve_data_dir(config: dict) -> Path:
    custom = config.get("agent", {}).get("data_dir")
    if custom:
        return Path(custom)
    return DEFAULT_DATA_DIR


def _install_start_time(data_dir: Path) -> datetime:
    marker = data_dir / ".install_time"
    if marker.exists():
        try:
            return datetime.fromisoformat(marker.read_text(encoding="utf-8").strip())
        except ValueError:
            pass
    now = datetime.now(timezone.utc)
    data_dir.mkdir(parents=True, exist_ok=True)
    marker.write_text(now.isoformat(), encoding="utf-8")
    return now


def _in_baseline(config: dict, install_time: datetime) -> bool:
    days = int(config.get("agent", {}).get("baseline_days", 7))
    return datetime.now(timezone.utc) < install_time + timedelta(days=days)


def run_once(
    store: AgentStore,
    config: dict,
    whitelists: dict,
    telemetry_file: Path,
    scripts_dir: Path,
    modes: dict,
    modules: dict,
    twin: TwinStore | None = None,
    policy: PolicyGate | None = None,
) -> None:
    """PULSE collector: bounded module pass (not heartbeat).

    Each module runs inside its own try/except so one flaky collector degrades
    gracefully instead of blinding the rest of the observation pass.
    """
    monitor_only = modes.get("monitor_only", True) or _in_baseline(
        config, _install_start_time(_resolve_data_dir(config))
    )
    enable_auto_block = modes.get("enable_auto_block", False) and not monitor_only
    enable_toasts = modes.get("enable_toasts", True)
    enable_ms_guard = modes.get("enable_microsoft_guard", True)
    cortex = policy.cortex if policy is not None else None

    health: dict = {}

    def _guard(name: str, fn: Callable[[], None]) -> None:
        try:
            fn()
        except Exception:
            logger.exception("pulse module failed: %s", name)

    def _connections() -> None:
        conn_alerts = ConnectionMonitor(store, config, whitelists).run(monitor_only=monitor_only)
        for alert in conn_alerts:
            if enable_toasts:
                show_toast(
                    "DVielle",
                    f"Suspicious: {alert.process_name} -> {alert.remote_addr}",
                    severity="WARNING",
                )

    def _attacks() -> None:
        attack_alerts = AttackMonitor(store, config, scripts_dir, cortex=cortex).run(
            enable_auto_block=enable_auto_block
        )
        for alert in attack_alerts:
            if alert.collection_degraded and alert.event_id == 0:
                continue
            if alert.should_block and enable_toasts:
                show_toast("DVielle", f"Blocked attacker IP: {alert.source_ip}", severity="CRITICAL")
            elif alert.attempt_count >= 3 and enable_toasts and alert.source_ip:
                show_toast(
                    "DVielle",
                    f"Failed logons from {alert.source_ip} ({alert.attempt_count})",
                    severity="WARNING",
                )

    def _browser_guard() -> None:
        for threat in BrowserGuard(store, config).run():
            if enable_toasts and threat.severity in ("WARNING", "CRITICAL"):
                show_toast("DVielle — Browser watch", threat.message[:200], severity=threat.severity)

    def _ram() -> None:
        ram = RamMonitor(store, config, scripts_dir).run(
            enable_trim=modes.get("enable_ram_trim", False) and not monitor_only
        )
        health["ram_percent"] = ram.percent
        health["ram_available_mb"] = ram.available_mb

    def _resource_advisor() -> None:
        for advice in ResourceAdvisor(store, config).run():
            if enable_toasts:
                show_toast(
                    f"DVielle — {advice.resource}",
                    f"{advice.headline}\n{advice.suggestion}",
                    duration=12,
                    severity="WARNING",
                )

    def _disk() -> None:
        disks = DiskMonitor(store, config).run(
            enable_cleanup=modes.get("enable_disk_cleanup", False) and not monitor_only
        )
        if disks:
            primary = disks[0]
            health["disk_percent_used"] = primary.percent_used
            health["disk_free_gb"] = primary.free_gb
            if primary.low_space and enable_toasts:
                show_toast(
                    "DVielle",
                    f"Low disk: {primary.free_gb:.1f} GB free on {primary.mount}",
                    severity="WARNING",
                )

    def _security() -> None:
        sec = SecurityMonitor(store, config).run()
        health["defender_enabled"] = sec.defender_enabled
        health["firewall_enabled"] = sec.firewall_enabled
        health["details"] = {"issues": sec.issues}
        for issue in sec.issues:
            if enable_toasts:
                show_toast("DVielle", issue, severity="CRITICAL")
        if twin is not None:
            twin.patch(
                security={
                    "defender_enabled": sec.defender_enabled,
                    "firewall_enabled": sec.firewall_enabled,
                    "issues": list(sec.issues),
                }
            )

    def _privacy_guard() -> None:
        PrivacyGuard(store, config, telemetry_file).run()

    def _microsoft_guard() -> None:
        never_block = whitelists.get("never_block_domains", [])
        ms_alerts = MicrosoftGuard(
            store, config, telemetry_file, scripts_dir, never_block, cortex=cortex
        ).run(monitor_only=monitor_only)
        for alert in ms_alerts:
            if enable_toasts and alert.kind in ("connection", "process"):
                show_toast("DVielle — Privacy", alert.message[:200], severity="WARNING")

    def _network_info() -> None:
        NetworkMonitor(store).run()

    ordered = [
        ("connections", _connections),
        ("attacks", _attacks),
        ("browser_guard", _browser_guard),
        ("ram", _ram),
        ("resource_advisor", _resource_advisor),
        ("disk", _disk),
        ("security", _security),
        ("privacy_guard", _privacy_guard),
        ("network_info", _network_info),
    ]
    for name, fn in ordered:
        if modules.get(name, True):
            _guard(name, fn)
    if modules.get("microsoft_guard", True) and enable_ms_guard:
        _guard("microsoft_guard", _microsoft_guard)

    if health:
        store.log_health_snapshot(health)
        if twin is not None and ("disk_percent_used" in health or "ram_percent" in health):
            twin.patch(
                system={
                    "disk_percent": health.get("disk_percent_used"),
                    "disk_free_gb": health.get("disk_free_gb"),
                }
            )


@dataclass
class Runtime:
    """Constructed nerve loop + twin, driven by both entry points."""

    store: AgentStore
    twin: TwinStore
    policy: PolicyGate
    nerve: NervePlane
    config: dict
    whitelists: dict
    telemetry_path: Path
    caps: Any
    intervals: dict[str, float]
    _heartbeat: Callable[[], None]
    _pulse: Callable[[], None]

    def prime(self) -> None:
        """Run one heartbeat so the twin has memory/self-budget immediately."""
        self._heartbeat()

    def run_pulse_once(self) -> None:
        self._pulse()

    def tick(self) -> list[str]:
        return self.nerve.run_due()

    def sleep_hint(self) -> float:
        return self.nerve.sleep_seconds(default=min(2.0, self.intervals["heartbeat"]))


def build_runtime(
    config_dir: Path | None = None,
    *,
    on_pulse: Callable[[], None] | None = None,
) -> Runtime:
    """Load config, build store/twin/policy, probe capabilities, and register the
    heartbeat/pulse/idle_deep collectors on one NervePlane. Used by headless and GUI.
    """
    if config_dir is not None:
        config_path = config_dir / "config.yaml"
        whitelist_path = config_dir / "whitelists.yaml"
        telemetry_path = config_dir / "telemetry-domains.txt"
    else:
        config_path, whitelist_path, telemetry_path = resolve_config_paths(DEFAULT_DATA_DIR)

    config = load_yaml(config_path)
    whitelists = load_yaml(whitelist_path)
    data_dir = _resolve_data_dir(config)
    data_dir.mkdir(parents=True, exist_ok=True)

    log_cfg = config.get("logging", {})
    setup_logging(
        data_dir,
        level=log_cfg.get("level", "INFO"),
        max_mb=int(log_cfg.get("max_file_mb", 10)),
        backup_count=int(log_cfg.get("backup_count", 3)),
    )
    set_process_priority(config.get("agent", {}).get("process_priority", "below_normal"))

    store = AgentStore(data_dir / "agent.db")
    twin = TwinStore(data_dir / "twin.jsonl")
    policy = PolicyGate.create(store)  # autonomous gate stays fail-closed (empty registry)
    scripts_dir = INSTALL_ROOT / "scripts"
    modes = config.get("modes", {})
    modules = config.get("modules", {})

    caps = probe_capabilities(deep=False)
    twin.set_capability(caps)
    store.log_event(
        "capability",
        "INFO",
        f"CapabilityReport tier={caps.tier} admin={caps.is_admin} vision={caps.overall_vision}",
        caps.to_dict(),
    )
    store.log_event(
        "policy",
        "INFO",
        "PolicyGate ready — ActionExecutor registry empty (fail-closed); L2 recommend only",
        {"registered_handlers": []},
    )
    logger.info(
        "DVielle %s starting (Nerve) tier=%s admin=%s vision=%s gaps=%s",
        get_version(),
        caps.tier,
        caps.is_admin,
        caps.overall_vision,
        caps.gaps,
    )

    install_time = _install_start_time(data_dir)
    if _in_baseline(config, install_time):
        logger.info(
            "Baseline learning active — monitor-only until %s",
            install_time + timedelta(days=int(config.get("agent", {}).get("baseline_days", 7))),
        )

    intervals = default_intervals(config)
    if "T3" in caps.tier:  # low-RAM: stretch pulse / idle-deep / heartbeat
        intervals["pulse"] = max(intervals["pulse"], 90.0)
        intervals["idle_deep"] = max(intervals["idle_deep"], 1800.0)
        intervals["heartbeat"] = max(intervals["heartbeat"], 8.0)

    nerve = NervePlane()
    proc = psutil.Process()

    def _heartbeat() -> None:
        t0 = time.perf_counter()
        twin.update_memory()
        try:
            sys_cpu = psutil.cpu_percent(interval=None)  # non-blocking, system-wide
        except Exception:
            sys_cpu = None
        if sys_cpu is not None:
            twin.patch(system={"cpu_percent": round(sys_cpu, 1)})
        try:
            cpu = proc.cpu_percent(interval=None)
            rss = proc.memory_info().rss
        except Exception:
            cpu, rss = None, None
        twin.update_self_budget(
            SelfBudget(
                rss_bytes=rss,
                cpu_percent=cpu,
                last_cycle_ms=(time.perf_counter() - t0) * 1000,
                collectors_ran=["heartbeat"],
            )
        )

    def _pulse() -> None:
        t0 = time.perf_counter()
        run_once(
            store, config, whitelists, telemetry_path, scripts_dir, modes, modules,
            twin=twin, policy=policy,
        )
        try:
            cpu = proc.cpu_percent(interval=None)
            rss = proc.memory_info().rss
        except Exception:
            cpu, rss = None, None
        twin.update_self_budget(
            SelfBudget(
                rss_bytes=rss,
                cpu_percent=cpu,
                last_cycle_ms=(time.perf_counter() - t0) * 1000,
                collectors_ran=["pulse"],
            )
        )
        twin.snapshot()  # batched snapshot after pulse (not every heartbeat)
        if on_pulse is not None:
            try:
                on_pulse()
            except Exception:
                logger.exception("on_pulse callback failed")

    def _idle_deep() -> None:
        deep = probe_capabilities(deep=True)
        twin.set_capability(deep)
        store.log_event("capability", "INFO", f"Deep CapabilityReport tier={deep.tier}", deep.to_dict())

    nerve.register(CollectorSpec("heartbeat", Cadence.HEARTBEAT, intervals["heartbeat"], run=_heartbeat))
    nerve.register(
        CollectorSpec(
            "pulse", Cadence.PULSE, intervals["pulse"], run=_pulse, defer_under_maximum_workload=False
        )
    )
    nerve.register(
        CollectorSpec(
            "idle_deep", Cadence.IDLE_DEEP, intervals["idle_deep"], run=_idle_deep,
            defer_under_maximum_workload=True,
        )
    )

    return Runtime(
        store=store,
        twin=twin,
        policy=policy,
        nerve=nerve,
        config=config,
        whitelists=whitelists,
        telemetry_path=telemetry_path,
        caps=caps,
        intervals=intervals,
        _heartbeat=_heartbeat,
        _pulse=_pulse,
    )

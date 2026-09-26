"""DVielle Windows Monitoring & Hardening Agent — Adaptive Nerve loop."""

from __future__ import annotations

import argparse
import logging
import signal
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

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

_running = True
logger = logging.getLogger("dvielle")


def _handle_signal(signum, frame) -> None:
    global _running
    _running = False


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
) -> None:
    """PULSE collector: bounded module pass (not heartbeat)."""
    monitor_only = modes.get("monitor_only", True) or _in_baseline(
        config, _install_start_time(_resolve_data_dir(config))
    )
    enable_auto_block = modes.get("enable_auto_block", False) and not monitor_only
    enable_toasts = modes.get("enable_toasts", True)
    enable_ms_guard = modes.get("enable_microsoft_guard", True)

    health: dict = {}

    if modules.get("connections", True):
        conn_alerts = ConnectionMonitor(store, config, whitelists).run(monitor_only=monitor_only)
        for alert in conn_alerts:
            if enable_toasts:
                show_toast(
                    "DVielle",
                    f"Suspicious: {alert.process_name} -> {alert.remote_addr}",
                    severity="WARNING",
                )

    if modules.get("attacks", True):
        attack_alerts = AttackMonitor(store, config, scripts_dir).run(enable_auto_block=enable_auto_block)
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

    if modules.get("browser_guard", True):
        for threat in BrowserGuard(store, config).run():
            if enable_toasts and threat.severity in ("WARNING", "CRITICAL"):
                show_toast(
                    "DVielle — Browser watch",
                    threat.message[:200],
                    severity=threat.severity,
                )

    if modules.get("ram", True):
        ram = RamMonitor(store, config, scripts_dir).run(
            enable_trim=modes.get("enable_ram_trim", False) and not monitor_only
        )
        health["ram_percent"] = ram.percent
        health["ram_available_mb"] = ram.available_mb

    advice_list = []
    disks = []
    sec = None

    if modules.get("resource_advisor", True):
        advice_list = ResourceAdvisor(store, config).run()
        for advice in advice_list:
            if enable_toasts:
                show_toast(
                    f"DVielle — {advice.resource}",
                    f"{advice.headline}\n{advice.suggestion}",
                    duration=12,
                    severity="WARNING",
                )

    if modules.get("disk", True):
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

    if modules.get("security", True):
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

    if modules.get("privacy_guard", True):
        PrivacyGuard(store, config, telemetry_file).run()

    if modules.get("microsoft_guard", True) and enable_ms_guard:
        never_block = whitelists.get("never_block_domains", [])
        ms_alerts = MicrosoftGuard(
            store, config, telemetry_file, scripts_dir, never_block
        ).run(monitor_only=monitor_only)
        for alert in ms_alerts:
            if enable_toasts and alert.kind in ("connection", "process"):
                show_toast("DVielle — Privacy", alert.message[:200], severity="WARNING")

    if modules.get("network_info", True):
        NetworkMonitor(store).run()

    if health:
        store.log_health_snapshot(health)

    from agent.engine.service import collect_startup_items, ingest_monitors

    ingest_monitors(
        store,
        security=sec,
        advice=advice_list,
        disks=disks,
        startup_items=collect_startup_items(),
        collect_live=True,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="DVielle — Deep Vigilance Agent")
    parser.add_argument("--once", action="store_true", help="Run one pulse cycle and exit")
    parser.add_argument("--config-dir", type=Path, default=None, help="Override config directory")
    args = parser.parse_args(argv)

    data_dir = DEFAULT_DATA_DIR
    if args.config_dir:
        config_path = args.config_dir / "config.yaml"
        whitelist_path = args.config_dir / "whitelists.yaml"
        telemetry_path = args.config_dir / "telemetry-domains.txt"
    else:
        config_path, whitelist_path, telemetry_path = resolve_config_paths(data_dir)

    config = load_yaml(config_path)
    whitelists = load_yaml(whitelist_path)
    data_dir = _resolve_data_dir(config)
    data_dir.mkdir(parents=True, exist_ok=True)

    log_cfg = config.get("logging", {})
    logger = setup_logging(
        data_dir,
        level=log_cfg.get("level", "INFO"),
        max_mb=int(log_cfg.get("max_file_mb", 10)),
        backup_count=int(log_cfg.get("backup_count", 3)),
    )

    set_process_priority(config.get("agent", {}).get("process_priority", "below_normal"))

    store = AgentStore(data_dir / "agent.db")
    twin = TwinStore(data_dir / "twin.jsonl")
    scripts_dir = INSTALL_ROOT / "scripts"
    modes = config.get("modes", {})
    modules = config.get("modules", {})

    version = get_version()
    caps = probe_capabilities(deep=False)
    twin.set_capability(caps)
    store.log_event(
        "capability",
        "INFO",
        f"CapabilityReport tier={caps.tier} admin={caps.is_admin} vision={caps.overall_vision}",
        caps.to_dict(),
    )
    logger.info(
        "DVielle %s starting (Nerve) tier=%s admin=%s vision=%s gaps=%s",
        version,
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
    # T3 low-RAM: stretch pulse / idle-deep
    if "T3" in caps.tier:
        intervals["pulse"] = max(intervals["pulse"], 90.0)
        intervals["idle_deep"] = max(intervals["idle_deep"], 1800.0)
        intervals["heartbeat"] = max(intervals["heartbeat"], 8.0)

    nerve = NervePlane()
    proc = psutil.Process()

    def _heartbeat() -> None:
        t0 = time.perf_counter()
        twin.update_memory()
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
        run_once(store, config, whitelists, telemetry_path, scripts_dir, modes, modules, twin=twin)
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
        # Snapshot twin lightly after pulse (batched, not every heartbeat)
        twin.snapshot()

    def _idle_deep() -> None:
        # Capability deep probe only — heavy inventory comes later phases
        deep = probe_capabilities(deep=True)
        twin.set_capability(deep)
        store.log_event("capability", "INFO", f"Deep CapabilityReport tier={deep.tier}", deep.to_dict())

    nerve.register(
        CollectorSpec(
            name="heartbeat",
            cadence=Cadence.HEARTBEAT,
            interval_seconds=intervals["heartbeat"],
            run=_heartbeat,
        )
    )
    nerve.register(
        CollectorSpec(
            name="pulse",
            cadence=Cadence.PULSE,
            interval_seconds=intervals["pulse"],
            run=_pulse,
            defer_under_maximum_workload=False,  # still pulse; AI defer is for extras later
        )
    )
    nerve.register(
        CollectorSpec(
            name="idle_deep",
            cadence=Cadence.IDLE_DEEP,
            interval_seconds=intervals["idle_deep"],
            run=_idle_deep,
            defer_under_maximum_workload=True,
        )
    )

    signal.signal(signal.SIGINT, _handle_signal)
    signal.signal(signal.SIGTERM, _handle_signal)

    if args.once:
        _pulse()
        return 0

    # Prime heartbeat immediately
    _heartbeat()

    while _running:
        try:
            nerve.run_due()
        except Exception:
            logger.exception("Nerve tick failed")
        time.sleep(nerve.sleep_seconds(default=min(2.0, intervals["heartbeat"])))

    logger.info("DVielle stopped")
    return 0


if __name__ == "__main__":
    sys.exit(main())

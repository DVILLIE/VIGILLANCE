"""Fortoro Windows Monitoring & Hardening Agent — main scheduler loop."""

from __future__ import annotations

import argparse
import signal
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

from agent.modules.attacks import AttackMonitor
from agent.modules.connections import ConnectionMonitor
from agent.modules.disk import DiskMonitor
from agent.modules.microsoft_guard import MicrosoftGuard
from agent.modules.privacy_guard import PrivacyGuard
from agent.modules.ram import RamMonitor
from agent.modules.resource_advisor import ResourceAdvisor
from agent.modules.security import SecurityMonitor
from agent.store.db import AgentStore
from agent.utils import (
    DEFAULT_DATA_DIR,
    INSTALL_ROOT,
    PROJECT_ROOT,
    load_yaml,
    resolve_config_paths,
    set_process_priority,
    setup_logging,
    show_toast,
)

_running = True


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
) -> None:
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
                show_toast("DVielle", f"Suspicious: {alert.process_name} -> {alert.remote_addr}")

    if modules.get("attacks", True):
        attack_alerts = AttackMonitor(store, config, scripts_dir).run(enable_auto_block=enable_auto_block)
        for alert in attack_alerts:
            if alert.should_block and enable_toasts:
                show_toast("DVielle", f"Blocked attacker IP: {alert.source_ip}")
            elif alert.attempt_count >= 3 and enable_toasts:
                show_toast("DVielle", f"Failed logons from {alert.source_ip} ({alert.attempt_count})")

    if modules.get("ram", True):
        ram = RamMonitor(store, config, scripts_dir).run(
            enable_trim=modes.get("enable_ram_trim", False) and not monitor_only
        )
        health["ram_percent"] = ram.percent
        health["ram_available_mb"] = ram.available_mb

    if modules.get("resource_advisor", True):
        for advice in ResourceAdvisor(store, config).run():
            if enable_toasts:
                show_toast(
                    f"DVielle — {advice.resource}",
                    f"{advice.headline}\n{advice.suggestion}",
                    duration=12,
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
                show_toast("DVielle", f"Low disk: {primary.free_gb:.1f} GB free on {primary.mount}")

    if modules.get("security", True):
        sec = SecurityMonitor(store, config).run()
        health["defender_enabled"] = sec.defender_enabled
        health["firewall_enabled"] = sec.firewall_enabled
        health["details"] = {"issues": sec.issues}
        for issue in sec.issues:
            if enable_toasts:
                show_toast("DVielle", issue)

    if modules.get("privacy_guard", True):
        PrivacyGuard(store, config, telemetry_file).run()

    if modules.get("microsoft_guard", True) and enable_ms_guard:
        never_block = whitelists.get("never_block_domains", [])
        ms_alerts = MicrosoftGuard(
            store, config, telemetry_file, scripts_dir, never_block
        ).run(monitor_only=monitor_only)
        for alert in ms_alerts:
            if enable_toasts and alert.kind in ("connection", "process"):
                show_toast("DVielle — Privacy", alert.message[:200])

    if health:
        store.log_health_snapshot(health)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="DVielle — Deep Vigilance Agent")
    parser.add_argument("--once", action="store_true", help="Run one cycle and exit")
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

    interval = int(config.get("agent", {}).get("interval_seconds", 60))
    priority = config.get("agent", {}).get("process_priority", "below_normal")
    set_process_priority(priority)

    store = AgentStore(data_dir / "agent.db")
    scripts_dir = INSTALL_ROOT / "scripts"
    modes = config.get("modes", {})
    modules = config.get("modules", {})

    install_time = _install_start_time(data_dir)
    if _in_baseline(config, install_time):
        logger.info("Baseline learning active — monitor-only until %s", install_time + timedelta(days=int(config.get("agent", {}).get("baseline_days", 7))))

    logger.info("DVielle starting (interval=%ss, monitor_only=%s)", interval, modes.get("monitor_only", True))

    signal.signal(signal.SIGINT, _handle_signal)
    signal.signal(signal.SIGTERM, _handle_signal)

    while _running:
        try:
            run_once(store, config, whitelists, telemetry_path, scripts_dir, modes, modules)
        except Exception:
            logger.exception("Cycle failed")
        if args.once:
            break
        time.sleep(interval)

    logger.info("DVielle stopped")
    return 0


if __name__ == "__main__":
    sys.exit(main())

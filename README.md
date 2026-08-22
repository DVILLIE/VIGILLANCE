# Fortoro Windows Monitoring & Hardening Agent

A lightweight 24/7 background agent for Windows laptops. Monitors network connections, failed logons, RAM, disk, Defender/firewall status, and privacy setting drift — with optional auto-response after a baseline learning period.

**Design goals:** under 100 MB RAM, 0–1% CPU, poll-based (no packet sniffing), monitor-first rollout.

## Features (v1)

| Module | Behavior |
|--------|----------|
| **Connections** | Logs established connections; flags unknown IPs/processes; builds baseline allowlist |
| **Attacks** | Scans Security log for Event 4625/4776; optional auto-block after N failures |
| **RAM** | Alerts on high usage; optional trim when critically high (disabled by default) |
| **Disk** | Free space + SMART status; optional temp cleanup when low (disabled by default) |
| **Security** | Windows Defender + firewall profile health |
| **Privacy guard** | Re-checks telemetry/Cortana/ad ID registry values; alerts on drift |
| **Microsoft guard** | Blocks telemetry uploads, stops spy processes, hosts + firewall blocking |
| **Resource advisor** | CPU/RAM popups naming the culprit app and what to close |

## Smart popups (CPU / RAM)

When CPU or RAM is high, you get a brief toast like:

> **RAM 92%** — chrome.exe using 2.1 GB  
> Running in background — safe to close: Discord (800 MB), Steam (400 MB)

Popups are limited to once every 5 minutes per type so they won't spam you.

## Microsoft privacy (your internet, your rules)

With `microsoft_guard` enabled (after the 7-day baseline):

- Blocks telemetry domains in the **hosts file**
- **Firewall blocks** outbound from CompatTelRunner, DeviceCensus, etc.
- **Stops** DiagTrack and other telemetry services
- **Re-applies** registry privacy settings if Microsoft resets them
- **Terminates** active telemetry upload connections
- **Preserves** Windows Update — updates still work

Run once as Administrator: `scripts\harden-once.ps1`, then set `enable_microsoft_guard: true` in config.

## Requirements

- Windows 10/11 (Home or Pro)
- Python 3.12+
- Administrator rights for install, hardening, and firewall blocks

## Quick start

```powershell
# Clone repo, then from repo root:
pip install -r requirements.txt

# Run one cycle (dev / test):
python -m agent.main --once

# Install as scheduled task (Administrator):
powershell -ExecutionPolicy Bypass -File scripts\install.ps1

# One-time privacy hardening (Administrator, run once):
powershell -ExecutionPolicy Bypass -File scripts\harden-once.ps1

# Start the agent:
Start-ScheduledTask -TaskName FortoroAgent
```

## Configuration

Edit `%ProgramData%\FortoroAgent\config\config.yaml` after install (or `config/config.yaml` in dev).

Key settings:

```yaml
modes:
  monitor_only: true
  enable_microsoft_guard: true  # after baseline — blocks MS telemetry uploads

thresholds:
  cpu_alert_percent: 80         # popup threshold
  ram_alert_percent: 85
  failed_logon_block_after: 5
  ram_critical_percent: 90
  disk_low_percent: 15

resource_advisor:
  enabled: true
  toast_cooldown_seconds: 300   # 5 min between popups
```

Whitelists: `config/whitelists.yaml` — trusted processes, IPs, domains.

## Rollout phases

1. **Baseline (7 days)** — monitor-only, builds process allowlist
2. **Alerts** — toasts on critical events
3. **Auto-block** — enable `enable_auto_block` after testing
4. **Hardening** — run `harden-once.ps1` once; agent guards settings
5. **RAM/disk actions** — enable in v2 after validation

## Project structure

```
agent/           Python monitor loop and modules
config/          YAML config, whitelists, telemetry domain list
scripts/         PowerShell: install, harden-once, block-ip
docs/            Design decisions
data/            Local SQLite + logs (dev); %ProgramData%\FortoroAgent (prod)
```

## Logs and database

- Log file: `%ProgramData%\FortoroAgent\logs\agent.log`
- SQLite DB: `%ProgramData%\FortoroAgent\agent.db`

## Safety notes

- Auto-blocking is **off** by default to avoid breaking Windows Update, Store, or games
- `harden-once.ps1` creates a restore point before changes
- Defender exclusions added for install/data dirs during `install.ps1`
- "Complete" telemetry block is not guaranteed — Microsoft endpoints change

## License

MIT

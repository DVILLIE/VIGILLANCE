# DVielle — DEEP VIGILLANCE

A futuristic Windows security agent with a Jarvis-inspired command interface. Monitors connections, blocks Microsoft telemetry, detects attacks, and advises you when CPU/RAM is under pressure — all from a sleek holographic GUI that lives in your system tray.

**DVielle** = **DEEP VIGILLANCE**

## Features

| Module | Behavior |
|--------|----------|
| **Jarvis GUI** | Futuristic dark/cyan interface — vitals, intelligence feed, protection matrix |
| **System tray** | Minimize to taskbar tray; restore with one click |
| **Connections** | Logs and flags suspicious outbound traffic |
| **Attacks** | Failed logon / brute-force detection |
| **Microsoft guard** | Blocks telemetry uploads — your internet stays yours |
| **Resource advisor** | Popups naming culprit apps + what to close |
| **Security** | Defender + firewall health |

## Install (Windows — one click, UAC prompt)

1. Install **Python 3.12+** from [python.org](https://python.org)
2. Double-click:

```
installer\Install-DVielle.bat
```

Windows will ask for **Administrator approval** (UAC) — click Yes.

This installs to `C:\Program Files\DVielle`, creates Start Menu + Desktop shortcuts, and starts DVielle at login.

## Uninstall

Double-click:

```
installer\Uninstall-DVielle.bat
```

UAC prompt → removes program, shortcuts, startup task. Optionally keeps your logs/database.

Or use **Settings → Apps → DVielle → Uninstall**.

## Manual run (development)

```powershell
pip install -r requirements.txt
python -m dvielle                  # GUI (default)
python -m dvielle --headless       # background only, no GUI
python -m dvielle --config-dir config
```

## GUI overview

```
┌─────────────────────────────────────────────────────────┐
│  DVIELLE                          ● VIGILANCE ACTIVE    │
│  DEEP VIGILLANCE                                        │
├──────────┬──────────────────────────┬───────────────────┤
│ VITALS   │  INTELLIGENCE FEED       │ PROTECTION MATRIX │
│ CPU ███  │  [live event stream]     │ Network   ACTIVE  │
│ RAM ███  │                          │ Privacy   ACTIVE  │
│ DISK ██  │                          │ MS Block  ACTIVE  │
├──────────┴──────────────────────────┴───────────────────┤
│  v1.1.0  |  Your system. Your internet.    [Tray] [⏸] │
└─────────────────────────────────────────────────────────┘
```

- **X button** → minimizes to system tray (stays running)
- **Tray icon** → right-click: Open, Minimize, Toggle vigilance, Exit
- **Pause Vigilance** → stops monitoring without closing GUI

## Privacy hardening (optional, once)

After install, run as Administrator:

```powershell
cd "C:\Program Files\DVielle"
powershell -ExecutionPolicy Bypass -File scripts\harden-once.ps1
```

## Configuration

`%ProgramData%\DVielle\config\config.yaml`

## Data

- Logs: `%ProgramData%\DVielle\logs\agent.log`
- Database: `%ProgramData%\DVielle\agent.db`

## License

MIT

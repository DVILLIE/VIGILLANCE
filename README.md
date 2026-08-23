# DVielle — DEEP VIGILLANCE

**Laptop-only Windows guardian.** Everything runs under `C:\DVILLIE`.  
Monitor-first: connections, failed logons, RAM/CPU/disk, Defender/firewall health, Microsoft telemetry drift. Not a cloud bot; chat/VILL is deferred.

---

## Prerequisites

- Windows 10/11
- **Python 3.12** ([python.org](https://www.python.org/downloads/) — tick Add to PATH)
- Admin once for install / optional harden

## Install

1. Open this repo on the laptop (Cursor Desktop or clone).
2. File Explorer → `installer` → right-click **`Install-DVielle.bat`** → Run as administrator.

Creates:

```
C:\DVILLIE\
  agent\     config\     data\     scripts\     installer\
```

Registers scheduled tasks:

| Task | Role |
|------|------|
| **DVielle** | Headless `pythonw -m agent.main` at logon (core guardian) |
| **DVielleGUI** | Optional GUI (`python -m dvielle`) |

Also enables **logon-failure audit** so Event 4625 feeds the attacks module.

## Daily use

| Action | How |
|--------|-----|
| Headless agent | Auto at logon, or `py -3.12 -m agent.main` from `C:\DVILLIE` |
| One cycle | `py -3.12 -m agent.main --once` |
| Optional GUI | Desktop shortcut or `py -3.12 -m dvielle` |
| Harden once | Admin: `scripts\harden-once.ps1` (restore point first) |
| Uninstall | `installer\Uninstall-DVielle.bat` |

## Honest limits

- We **reduce and detect** Microsoft data use — we do **not** claim 100% anti-spy.
- On **Windows Home**, diagnostic data cannot truly reach “Security (0)”; lowest real floor is **Required**.
- Windows Update / delivery / certificates are **never** blocked by default.
- No auto-block / auto-trim on day one (7-day baseline + config flags).

See [docs/TELEMETRY_AND_HOME.md](docs/TELEMETRY_AND_HOME.md) and [docs/CHAT_DEFERRED.md](docs/CHAT_DEFERRED.md).

## Dev checks

```bat
py -3.12 -m pip install -r requirements.txt
py -3.12 scripts\smoke_test.py
py -3.12 -m pytest tests\test_db.py tests\test_utils.py tests\test_resource_advisor.py tests\test_network_info.py -q
```

## Docs

| Doc | Purpose |
|-----|---------|
| [docs/DECISIONS.md](docs/DECISIONS.md) | v1 product defaults |
| [docs/LAPTOP_ONLY.md](docs/LAPTOP_ONLY.md) | Install on the PC, not cloud |
| [docs/TELEMETRY_AND_HOME.md](docs/TELEMETRY_AND_HOME.md) | Home vs Pro telemetry honesty |
| [docs/CHAT_DEFERRED.md](docs/CHAT_DEFERRED.md) | Why chat/demo waits |

# DVielle — DEEP VIGILANCE

DVielle is a local Windows guardian. It observes workload, memory pressure, network connections, authentication failures, privacy policy and security posture, then explains the evidence. Version 1.6 adds one monitoring owner, independent collectors, workload deferral, bounded history and provider retry recovery.

The native console attaches to the background agent. Its values and activity come from measured state; unavailable or stale evidence is shown explicitly. Monitoring runs autonomously. Closing an application still requires a fresh process identity and explicit confirmation; automatic file cleanup, firewall changes and RAM trimming are disabled.

## Install

Windows 10/11 and Python 3.12 are required. Run `installer\Install-DVielle.bat` as administrator on the PC. The installer creates `C:\DVILLIE\.venv`, checks dependencies, registers the resident logon task and verifies startup. Existing configuration is preserved.

| Action | Command from C:\DVILLIE |
|---|---|
| Native console | `.venv\Scripts\pythonw.exe -m dvielle` or desktop shortcut |
| Headless monitoring | `.venv\Scripts\python.exe -m agent.main` |
| One observe-only diagnostic pass | `.venv\Scripts\python.exe -m agent.main --once` |
| Graceful owner shutdown | `.venv\Scripts\python.exe -m agent.main --stop` |
| Optional hardening | Review `scripts\harden-once.ps1` and its explicit apply/restore parameters |
| Browser snapshot viewer | See [demo/README.md](demo/README.md) |
| Uninstall | `installer\Uninstall-DVielle.bat` |

A second headless launch exits without duplicating collectors. A console can acquire ownership when no agent is running, attach when one is, and recover after an owner crash. An intentional shutdown is respected.

## Behavior and limits

- Scheduling responds to sustained CPU demand, measured memory pressure, configured foreground workloads and session inactivity. This is a conservative rule-based assessment; it does not infer arbitrary user intent.
- The CPU/RSS budget defers optional collectors after sustained excess. It is a scheduling control, not an operating-system quota or a verified performance guarantee.
- Authentication counts use source event time and record identity. Successful 4776 events are excluded; a 4776 workstation is a hostname, not a blockable source IP.
- Unknown peers, familiar process names, reverse DNS and cloud hosting do not establish trust or maliciousness.
- Windows Home and Pro have a Required diagnostic-data floor. Registry settings alone do not prove that traffic stopped.
- Public-IP lookup, cloud chat, cloud speech and web search require separate opt-ins. Core monitoring does not need a model.
- DVielle complements Windows security. It cannot prove a machine is free of threats.

See [implemented autonomy and verification](docs/AUTONOMY.md), [architecture](docs/VIGILLANCE_MASTER_ARCHITECTURE.md), [product decisions](docs/DECISIONS.md), and [Windows privacy details](docs/TELEMETRY_AND_HOME.md).

## Development checks

```bat
py -3.12 -m pip install -e ".[windows,chat,dev]"
py -3.12 scripts\smoke_test.py
py -3.12 -m pytest -q
py -3.12 -m ruff check agent dvielle scripts/smoke_test.py --select E9,F63,F7,F82
```

The installer smoke checks imports and package metadata without starting collectors. Unit tests use isolated fixtures; lifecycle tests start actual child processes with heavy collectors disabled and temporary state. A successful test run does not substitute for Windows installation and long-running field validation.

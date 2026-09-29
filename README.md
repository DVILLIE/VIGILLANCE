# DVielle — DEEP VIGILANCE

DVielle is a Windows-primary local guardian. Linux and macOS run in limited mode. It observes workload, memory pressure, network connections, authentication failures, privacy policy and security posture, then explains the evidence. Version 2.0.0 keeps the 1.7.0 dual gate and fails closed when a mutate decision is not saved, when a collection probe fails, or when an install would run elevated code from a writable directory. The resident scheduled task stays Limited. A Highest task is an explicit installer option only after the install directory is locked down, and elevated unattended use is not recommended until that lockdown is proven on the target Windows PC. 1.8.0 added a read-only Defender health report, a MAPS reachability check, and an edition matrix. 1.9.0 reads ASR rules and Controlled Folder Access, and can move a single eligible setting from Audit toward Block only after the user approves it and the live preference matches. It does not turn on App Control, and it does not offer Windows Sandbox on Home. Controlled Folder Access is described as a modification shield. Offline backups and a restore test stay required. 2.0.0 observes Windows Firewall app rules and can add an outbound block only after you confirm, through a privileged helper the Limited scheduled task does not become. The block is re-read with Get-NetFirewallRule. It is not a leakproof claim, and DVielle does not stop the firewall service. The published CPU contract is measured scheduling on the resident task, plus a Windows Job Object hard cap for the helper process when that assignment succeeds. User applications are not closed to satisfy it. 2.1.0 can open an unfamiliar folder in Windows Sandbox on Pro, Enterprise, or Education only, using a configuration that disables networking and maps that folder read-only. Windows Home is shown SAC, ASR, CFA, and Firewall instead, and a normal window is not called a sandbox. Package metadata can be checked with The Update Framework (root, timestamp, snapshot, and targets). A failed check leaves the last good file in place. Privileged auto-update stays off, and the running process is not claimed to be measured. 2.2.0 reads a local CISA KEV catalog and local OSV records when those files are present, and it says intel is unavailable when they are not. It does not invent vulnerability hits, and it does not ship abuse.ch dumps. It can set diagnostic data to Required after you confirm, and it re-reads the setting. Windows Home is not told that diagnostic data is off. It does not block Defender cloud, Windows Update, or certificate revocation endpoints. 2.3.0 adds activity experiences with different thresholds, not just names. Everyday watches ASR, Controlled Folder Access, and the firewall and stays quieter. It cannot turn on denylist actions or close an app by itself. Sensitive warns sooner and can suggest Controlled Folder Access Audit or a firewall restriction, and it still waits for you before it closes an app or opens an unfamiliar file. Opening an unfamiliar file uses Windows Sandbox on Pro, Enterprise, or Education. Windows Home sees the checklist instead. Passkey guidance explains relying-party sign-in, and it says stolen sessions and weak account recovery are separate problems. It does not change accounts for you, and it does not claim phishing is impossible. What is promised, what is assumed, and what is still unchecked is in [docs/CLAIMS.md](docs/CLAIMS.md).

The native console attaches to the background agent. Its values and activity come from measured state; unavailable or stale evidence is shown explicitly. Monitoring runs autonomously. Closing an application still requires a fresh process identity and explicit confirmation; automatic file cleanup, automatic firewall changes, and RAM trimming stay off.

## Install

Windows 10/11 and Python 3.12 are required. Run `installer\Install-DVielle.bat` as administrator on the PC. The installer creates `C:\DVILLIE\.venv`, syncs the dependencies declared in `pyproject.toml` (including `cryptography`) into that environment, registers the resident logon task and verifies startup. Existing configuration is preserved. Copying a new tree over an existing install does not refresh `.venv`; run the installer again, or the dependency sync in [docs/LAPTOP_ONLY.md](docs/LAPTOP_ONLY.md), before starting the resident.

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
- Windows Home has no Windows Sandbox and no App Control authoring. The console evidence strip shows edition support, not a guess that a feature is on. Pass/fail checks are in [docs/TRUST_GATES.md](docs/TRUST_GATES.md). Promises, assumptions, and unchecked items are in [docs/CLAIMS.md](docs/CLAIMS.md). The FREE roadmap is [docs/FUNCTION_SPEC.md](docs/FUNCTION_SPEC.md) §1.1.

See [implemented autonomy and verification](docs/AUTONOMY.md), [architecture](docs/VIGILLANCE_MASTER_ARCHITECTURE.md), [product decisions](docs/DECISIONS.md), and [Windows privacy details](docs/TELEMETRY_AND_HOME.md).

## Development checks

```bat
py -3.12 -m pip install -e ".[windows,chat,dev]"
py -3.12 scripts\smoke_test.py
py -3.12 -m pytest -q
py -3.12 -m ruff check agent dvielle scripts/smoke_test.py --select E9,F63,F7,F82
```

Options decisions (keep-on, then act only after a choice and a Cortex decision) are in [docs/FUNCTION_SPEC.md](docs/FUNCTION_SPEC.md). A local drill for speed, storage, privacy, AI, camera, and footprint does not close real apps, block real networks, use a camera, or search for a person:

```bat
py -3.12 -m agent.exercise
```

See [docs/DEV.md](docs/DEV.md). The installer smoke checks imports and package metadata without starting collectors. Unit tests use isolated fixtures; lifecycle tests start actual child processes with heavy collectors disabled and temporary state. A successful test run does not substitute for Windows installation and long-running field validation.

## Docs

| Doc | Purpose |
|-----|---------|
| [docs/VIGILLANCE_MASTER_ARCHITECTURE.md](docs/VIGILLANCE_MASTER_ARCHITECTURE.md) | **Master architecture + repo gap map** |
| [docs/FUNCTION_SPEC.md](docs/FUNCTION_SPEC.md) | Keep-on pillars, FREE prevention roadmap, honesty limits |
| [docs/TRUST_GATES.md](docs/TRUST_GATES.md) | Pass/fail checks; live process attestation still unchecked |
| [docs/CLAIMS.md](docs/CLAIMS.md) | Promises, assumptions, evidence, and what stays UNCHECKED |
| [docs/DECISIONS.md](docs/DECISIONS.md) | Product defaults |
| [docs/LAPTOP_ONLY.md](docs/LAPTOP_ONLY.md) | Install on the PC, not cloud |
| [docs/TELEMETRY_AND_HOME.md](docs/TELEMETRY_AND_HOME.md) | Home vs Pro telemetry honesty |
| [docs/CHAT_DEFERRED.md](docs/CHAT_DEFERRED.md) | Why chat/demo waits |
| [docs/AUTONOMY.md](docs/AUTONOMY.md) | What the resident agent does and does not do |
| [docs/DEV.md](docs/DEV.md) | Local checks |

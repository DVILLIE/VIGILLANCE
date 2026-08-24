# DVielle — DEEP VIGILLANCE

**Laptop-local Windows guardian** under `C:\DVILLIE`.  
Not cloud-first. Not antivirus-first. Not chat-first.

**Product thesis:** continuously observe resources, network, background behavior, privacy exposure, and security posture — then **explain** what is happening and apply **conservative** corrections only when evidence is strong. Especially: protect intentional workloads (including local AI) while reducing unjustified contention.

Full architecture (engines, pipeline, repo map, phases):  
→ [`docs/VIGILLANCE_MASTER_ARCHITECTURE.md`](docs/VIGILLANCE_MASTER_ARCHITECTURE.md)  
→ Futuristic Nerve System (roundtable): [`docs/VIGILLANCE_FUTURE_ARCHITECTURE.md`](docs/VIGILLANCE_FUTURE_ARCHITECTURE.md)  
→ Design system (**Phosphor Void**): [`docs/DESIGN.md`](docs/DESIGN.md)

---

## Prerequisites

- Windows 10/11
- **Python 3.12** ([python.org](https://www.python.org/downloads/) — tick Add to PATH)
- Admin once for install / optional harden

## Install

1. Open this repo on the laptop (Cursor Desktop or clone from https://github.com/DVILLIE/VIGILLANCE).
2. File Explorer → `installer` → right-click **`Install-DVielle.bat`** → Run as administrator.

Creates:

```
C:\DVILLIE\
  agent\     config\     data\     scripts\     installer\
```

Registers scheduled task **DVielle** (headless `pythonw -m agent.main` at logon) and enables logon-failure audit for failed-password detection.

## Daily use

| Action | How |
|--------|-----|
| Headless agent | Auto at logon, or `py -3.12 -m agent.main` from `C:\DVILLIE` |
| One cycle | `py -3.12 -m agent.main --once` |
| Optional GUI | Desktop shortcut or `py -3.12 -m dvielle` |
| Harden once | Admin: `scripts\harden-once.ps1` (restore point first) |
| Uninstall | `installer\Uninstall-DVielle.bat` |

## Honest limits

- We **reduce and detect** — we do **not** claim 100% anti-spy or replace Defender.
- On **Windows Home**, diagnostic data cannot truly reach “Security (0)”; lowest real floor is often **Required**.
- Windows Update / delivery / certificates are **never** blocked by default.
- No auto-block / auto-trim on day one (7-day baseline + config flags).
- High RAM alone is often healthy cache — the product targets **memory pressure**, not “used %.”

See [docs/TELEMETRY_AND_HOME.md](docs/TELEMETRY_AND_HOME.md) and [docs/CHAT_DEFERRED.md](docs/CHAT_DEFERRED.md).

## Dev checks

```bat
py -3.12 -m pip install -r requirements.txt
py -3.12 scripts\smoke_test.py
py -3.12 -m pytest tests\test_db.py tests\test_utils.py tests\test_resource_advisor.py tests\test_network_info.py tests\test_connections_classify.py -q
```

## Docs

| Doc | Purpose |
|-----|---------|
| [docs/VIGILLANCE_MASTER_ARCHITECTURE.md](docs/VIGILLANCE_MASTER_ARCHITECTURE.md) | **Master architecture + repo gap map** |
| [docs/DECISIONS.md](docs/DECISIONS.md) | Product defaults |
| [docs/LAPTOP_ONLY.md](docs/LAPTOP_ONLY.md) | Install on the PC, not cloud |
| [docs/TELEMETRY_AND_HOME.md](docs/TELEMETRY_AND_HOME.md) | Home vs Pro telemetry honesty |
| [docs/CHAT_DEFERRED.md](docs/CHAT_DEFERRED.md) | Why chat/demo waits |

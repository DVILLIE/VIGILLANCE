# Implemented autonomy — version 1.6

Status: implemented in the working tree, verified on 2026-09-14. This describes executable behavior, not every capability in the future architecture.

## Runtime ownership and recovery

`agent/ownership.py` uses an OS-held byte lock on Windows (flock on POSIX for development). The lock is acquired before logging, database initialization or collection. It is released after in-flight collectors drain, or by the operating system when the process exits. The token and process creation time in the shared snapshot identify the owner; a PID file alone is not ownership.

`agent/main.py` runs headless. `agent/controller.py` either acquires the same lease or reads the existing owner's `data/twin.json`. Attached consoles never start a parallel collection loop. They can take over after a crash, but respect a published intentional stop. The stop command targets the current ownership token, accepts only recent requests, and waits for release without killing by process name.

The installer configures the resident logon task with unlimited execution time, bounded failure restart and duplicate-instance suppression. It checks native exit codes and startup instead of treating registration or a warning as proof of a healthy agent.

Legacy releases used global Python without ownership locks. Install/upgrade/uninstall refuses to proceed when such an ambiguous instance is detected; the operator must exit it first. Current releases recheck an intentional stop while holding the lease before an attached console can take over. Snapshot replacement briefly retries Windows reader contention without exposing partial JSON.

## Scheduling

The heartbeat samples cheap memory, CPU, process footprint and session-input signals. Blocking PowerShell, DNS and process scans run outside the heartbeat. Each collector has its own cadence and at most one in-flight invocation. The default two-worker pool reserves capacity for core monitoring when optional I/O stalls. There is no unbounded task queue.

| Trigger | Response |
|---|---|
| Three high-CPU samples | Defer optional monitoring until three recovery samples |
| Measured memory pressure | Defer optional monitoring |
| Configured foreground process | Defer optional monitoring; its name grants no security trust |
| Unknown input/CPU state | Withhold idle-deep work |
| Low CPU and sufficient session inactivity | Permit idle-deep capability probing |
| Three samples exceeding CPU/RSS budget | Defer optional collection; core monitoring remains eligible |
| Collector exception | Record error and duration, retry with capped exponential backoff |
| Valid partial observation / authentication backlog | Publish partial coverage and continue at normal cadence |
| Shutdown | Stop scheduling and drain existing observations |

A worker slot does not interrupt an already running OS call. PowerShell calls have timeouts; OS DNS requests use a bounded background pool and may outlive the caller. No hard CPU/RSS quota is claimed. Workload profiles are explainable scheduling hypotheses, not trained intent detection.

`config/config.yaml` controls per-collector cadence, worker count, workload signals, budget and retention. Invalid nonfinite cadence/budget values fail startup. Old baseline and action flags cannot enable destructive collector behavior.

## Evidence and user controls

Each collector publishes its last attempt, last successful observation, error, duration and deferred/disabled state. Memory, disk, security and network values retain sample times. A heartbeat proves the scheduler is alive; it does not prove every provider succeeded.

Authentication batches retain UTC event time, Security log record ID and log generation. Insertion, deduplication and cursor advancement share a transaction. Queries drain oldest-first with a bounded batch; backlog, unreadable logs and resets remain visible. Event 4776 success status is excluded and its workstation is never treated as an IP.

Network classification uses domain-label boundaries and separates topology/name hints from trust. A cloud address or familiar executable name does not suppress evidence. Browser path checks normalize Windows paths and avoid treating common per-user installation folders as malware evidence.

Resource recommendations preserve PID creation times. Closing requires confirmation of the current identity, foreground and protected-family checks, and a recorded decision. Stale or missing identity is refused. File cleanup and automatic RAM trimming remain disabled. Privacy policy readings distinguish unavailable, configured and verified states; registry policy is not proof of effective traffic suppression.

The native console uses shared measured state and explicit collector freshness. Headless and tray modes retain critical notifications. Console voice for close and confirm stays local. The chat assistant is not part of the product. The browser entry point imports actual snapshots locally; it does not generate system metrics or run microphone, model, or network lookups.

SQLite observation tables and work logs have scheduled retention. Twin history rotates with one backup. Decision/action audit evidence remains durable, so its size still needs operational review.

## Validation and remaining scope

Verified on 2026-09-14 with Python 3.12 and Node 24:

- Full Python suite: **226 passed** (including real resident owner/attachment/stop and safe PowerShell contracts).
- Browser parser suite: **4 passed**; TypeScript/Vite production build passed.
- Selected Ruff checks across agent, console, tests and verification scripts passed; changed browser entry/parser lint passed.
- Import/configuration smoke passed. Browser file selection and rendering were checked against an actual isolated-runtime snapshot: stopped owner, measured memory, disabled collectors and unavailable security values were displayed accurately, with no browser console errors.

Unmounted demo chat sources were removed with the product assistant. Other unused demo files stay outside the snapshot viewer.

Regression coverage includes stalled providers, reserved core capacity, scheduling deferral/recovery, retry backoff, real cross-process ownership, graceful shutdown, missing measurements, source-time authentication, identity-bound process actions and installer helper contracts. The browser is checked with its TypeScript production build.

Tests using fixtures exercise failure cases; they are not measured activity from this PC. The real resident lifecycle tests use temporary configuration and disable heavy collectors. No installer, firewall rule, hardening policy or real application-close action is applied by these checks. Windows edition coverage, long-running footprint measurements and full scheduled-task installation still require field validation.

Publisher/signature-backed process trust, continuous ETW correlation, learned baselines, broad CVE inventory, verified VPN routing and generalized autonomous remediation remain future architecture. They are not represented as implemented intelligence.

## Primary references used in the review

- [Microsoft event 4776](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4776): success status and workstation semantics.
- [Microsoft TaskSettings.ExecutionTimeLimit](https://learn.microsoft.com/en-us/windows/win32/taskschd/tasksettings-executiontimelimit): scheduled-task duration.
- [Python 3.12 msvcrt locking](https://docs.python.org/3.12/library/msvcrt.html): nonblocking byte locks.
- [psutil process API](https://psutil.readthedocs.io/stable/): process identity and nonblocking CPU sampling.
- [Microsoft quality of service](https://learn.microsoft.com/en-us/windows/win32/procthread/quality-of-service): foreground/background resource policy.
- [MDN File API](https://developer.mozilla.org/en-US/docs/Web/API/File_API/Using_files_from_web_applications): user-selected local files in the browser.
